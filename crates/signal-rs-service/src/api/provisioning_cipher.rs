//! Provisioning cipher for device linking.
//!
//! ECDH + HKDF + AES-256-CBC cipher used to decrypt the `ProvisionMessage`
//! sent by the primary device during linking.

use aes::cipher::{BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use signal_rs_protos::{ProvisionEnvelope, ProvisionMessage};

use crate::error::{Result, ServiceError};

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// The info string used for HKDF key derivation.
const HKDF_INFO: &[u8] = b"TextSecure Provisioning Message";

/// Version byte expected at the start of the encrypted body.
const PROVISION_VERSION: u8 = 1;

/// ECDH + HKDF + AES-256-CBC cipher for decrypting ProvisionMessage.
pub struct ProvisioningCipher {
    our_private_key: StaticSecret,
    our_public_key: PublicKey,
}

impl Default for ProvisioningCipher {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvisioningCipher {
    /// Generate a new ephemeral Curve25519 keypair for provisioning.
    pub fn new() -> Self {
        use rand::rngs::OsRng;
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        Self {
            our_private_key: private_key,
            our_public_key: public_key,
        }
    }

    /// Return the public key in Signal's DJB format: `0x05 || 32-byte-pub-key`.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0x05u8];
        bytes.extend_from_slice(self.our_public_key.as_bytes());
        bytes
    }

    /// Decrypt a `ProvisionEnvelope` into a `ProvisionMessage`.
    pub fn decrypt(&self, envelope: &ProvisionEnvelope) -> Result<ProvisionMessage> {
        let their_public_key_bytes = envelope.public_key.as_ref()
            .ok_or_else(|| ServiceError::ProvisioningCipher("missing public key".into()))?;

        let body = envelope.body.as_ref()
            .ok_or_else(|| ServiceError::ProvisioningCipher("missing body".into()))?;

        // Strip 0x05 prefix from their public key
        let raw_key = if their_public_key_bytes.len() == 33 && their_public_key_bytes[0] == 0x05 {
            &their_public_key_bytes[1..]
        } else if their_public_key_bytes.len() == 32 {
            their_public_key_bytes.as_slice()
        } else {
            return Err(ServiceError::ProvisioningCipher(format!(
                "invalid public key length: {}",
                their_public_key_bytes.len()
            )));
        };

        let their_public: [u8; 32] = raw_key
            .try_into()
            .map_err(|_| ServiceError::ProvisioningCipher("invalid public key".into()))?;
        let their_public = PublicKey::from(their_public);

        // ECDH shared secret
        let shared_secret = self.our_private_key.diffie_hellman(&their_public);

        // HKDF-SHA256: derive 64 bytes (32 AES key + 32 MAC key)
        let hk = hkdf::Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut okm = [0u8; 64];
        hk.expand(HKDF_INFO, &mut okm)
            .map_err(|e| ServiceError::ProvisioningCipher(format!("HKDF expand failed: {e}")))?;

        let aes_key = &okm[..32];
        let mac_key = &okm[32..];

        // Parse body: version(1) || iv(16) || ciphertext(n) || mac(32)
        if body.len() < 1 + 16 + 32 {
            return Err(ServiceError::ProvisioningCipher("body too short".into()));
        }

        let version = body[0];
        if version != PROVISION_VERSION {
            return Err(ServiceError::ProvisioningCipher(format!(
                "unsupported version: {version}"
            )));
        }

        let iv = &body[1..17];
        let ciphertext = &body[17..body.len() - 32];
        let mac = &body[body.len() - 32..];

        // Verify HMAC-SHA256 of version || iv || ciphertext
        let mut hmac = HmacSha256::new_from_slice(mac_key)
            .map_err(|e| ServiceError::ProvisioningCipher(format!("HMAC init failed: {e}")))?;
        hmac.update(&body[..body.len() - 32]);
        hmac.verify_slice(mac)
            .map_err(|_| ServiceError::ProvisioningCipher("HMAC verification failed".into()))?;

        // AES-256-CBC decrypt with PKCS7 padding
        let iv_arr: [u8; 16] = iv
            .try_into()
            .map_err(|_| ServiceError::ProvisioningCipher("invalid IV length".into()))?;
        let aes_key_arr: [u8; 32] = aes_key
            .try_into()
            .map_err(|_| ServiceError::ProvisioningCipher("invalid AES key length".into()))?;

        let decryptor = Aes256CbcDec::new(&aes_key_arr.into(), &iv_arr.into());
        let mut buf = ciphertext.to_vec();
        let plaintext = decryptor
            .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf)
            .map_err(|e| ServiceError::ProvisioningCipher(format!("AES decrypt failed: {e}")))?;

        // Decode as ProvisionMessage protobuf
        use prost::Message;
        let provision_message = ProvisionMessage::decode(plaintext)
            .map_err(|e| ServiceError::ProvisioningCipher(format!("protobuf decode failed: {e}")))?;

        Ok(provision_message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_generates_valid_public_key() {
        let cipher = ProvisioningCipher::new();
        let pk = cipher.public_key_bytes();
        assert_eq!(pk.len(), 33);
        assert_eq!(pk[0], 0x05);
    }

    #[test]
    fn decrypt_rejects_bad_version() {
        let cipher = ProvisioningCipher::new();
        // Build a minimal envelope with wrong version
        let mut body = vec![0x02]; // wrong version
        body.extend_from_slice(&[0u8; 16]); // IV
        body.extend_from_slice(&[0u8; 32]); // MAC (will fail verification anyway)

        let envelope = ProvisionEnvelope {
            public_key: Some(cipher.public_key_bytes()),
            body: Some(body),
        };

        let result = cipher.decrypt(&envelope);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_rejects_short_body() {
        let cipher = ProvisioningCipher::new();
        let envelope = ProvisionEnvelope {
            public_key: Some(cipher.public_key_bytes()),
            body: Some(vec![0x01, 0x02, 0x03]),
        };

        let result = cipher.decrypt(&envelope);
        assert!(result.is_err());
    }
}
