//! Attachment processing.
//!
//! This module provides:
//! - Attachment encryption (AES-256-CBC with HMAC-SHA256)
//! - Attachment decryption and verification (digest check)
//! - Key generation for attachment encryption
//!
//! Attachment encryption scheme:
//! - Generate a random 64-byte key (32 bytes AES key + 32 bytes HMAC key)
//! - Encrypt with AES-256-CBC using a zero IV
//! - Append HMAC-SHA256 over (IV || ciphertext)
//! - The AttachmentPointer protobuf contains the key, digest, and CDN location

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::error::{Result, ServiceError};

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// The combined key length for attachment encryption: 32 AES + 32 HMAC.
const COMBINED_KEY_LEN: usize = 64;

/// The IV for attachment encryption (all zeros per Signal spec).
const ZERO_IV: [u8; 16] = [0u8; 16];

/// The HMAC length appended to the ciphertext.
const MAC_LEN: usize = 32;

/// An attachment key containing the AES and HMAC components.
#[derive(Debug, Clone)]
pub struct AttachmentKey {
    /// The combined 64-byte key (32 AES + 32 HMAC).
    pub combined: Vec<u8>,
}

impl AttachmentKey {
    /// Generate a new random attachment key.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut key = vec![0u8; COMBINED_KEY_LEN];
        rand::thread_rng().fill_bytes(&mut key);
        Self { combined: key }
    }

    /// Create from an existing combined key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != COMBINED_KEY_LEN {
            return Err(ServiceError::InvalidResponse(format!(
                "invalid attachment key length: expected {}, got {}",
                COMBINED_KEY_LEN,
                bytes.len()
            )));
        }
        Ok(Self {
            combined: bytes.to_vec(),
        })
    }

    /// Return the AES key (first 32 bytes).
    pub fn aes_key(&self) -> &[u8] {
        &self.combined[..32]
    }

    /// Return the HMAC key (last 32 bytes).
    pub fn hmac_key(&self) -> &[u8] {
        &self.combined[32..]
    }
}

/// Encrypt attachment data.
///
/// Returns `(ciphertext_with_mac, digest)` where:
/// - `ciphertext_with_mac` is the encrypted data with HMAC appended
/// - `digest` is the SHA-256 hash of the ciphertext_with_mac (for verification)
pub fn encrypt_attachment(key: &AttachmentKey, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let aes_key: [u8; 32] = key
        .aes_key()
        .try_into()
        .map_err(|_| ServiceError::InvalidResponse("invalid AES key".to_string()))?;

    // Encrypt with AES-256-CBC and PKCS7 padding
    let encryptor = Aes256CbcEnc::new(&aes_key.into(), &ZERO_IV.into());
    let ciphertext =
        encryptor.encrypt_padded_vec_mut::<aes::cipher::block_padding::Pkcs7>(plaintext);

    // Compute HMAC-SHA256 over (IV || ciphertext)
    let mut hmac = HmacSha256::new_from_slice(key.hmac_key())
        .map_err(|e| ServiceError::InvalidResponse(format!("HMAC init failed: {e}")))?;
    hmac.update(&ZERO_IV);
    hmac.update(&ciphertext);
    let mac = hmac.finalize().into_bytes();

    // Build the output: IV || ciphertext || MAC
    let mut output = Vec::with_capacity(ZERO_IV.len() + ciphertext.len() + MAC_LEN);
    output.extend_from_slice(&ZERO_IV);
    output.extend_from_slice(&ciphertext);
    output.extend_from_slice(&mac);

    // Compute the digest (SHA-256 of the output)
    let digest = Sha256::digest(&output).to_vec();

    Ok((output, digest))
}

/// Decrypt attachment data and verify the digest.
///
/// The `data` parameter is the raw downloaded bytes: IV(16) || ciphertext || MAC(32).
/// The `expected_digest` parameter is the SHA-256 hash from the AttachmentPointer.
pub fn decrypt_attachment(
    key: &AttachmentKey,
    data: &[u8],
    expected_digest: Option<&[u8]>,
) -> Result<Vec<u8>> {
    // Verify the digest if provided
    if let Some(expected) = expected_digest {
        let actual = Sha256::digest(data);
        if actual.as_slice() != expected {
            return Err(ServiceError::InvalidResponse(
                "attachment digest mismatch".to_string(),
            ));
        }
    }

    // Parse: IV(16) || ciphertext(n) || MAC(32)
    if data.len() < 16 + MAC_LEN {
        return Err(ServiceError::InvalidResponse(
            "attachment data too short".to_string(),
        ));
    }

    let iv = &data[..16];
    let ciphertext = &data[16..data.len() - MAC_LEN];
    let mac = &data[data.len() - MAC_LEN..];

    // Verify HMAC
    let mut hmac = HmacSha256::new_from_slice(key.hmac_key())
        .map_err(|e| ServiceError::InvalidResponse(format!("HMAC init failed: {e}")))?;
    hmac.update(iv);
    hmac.update(ciphertext);
    hmac.verify_slice(mac)
        .map_err(|_| ServiceError::InvalidResponse("attachment HMAC verification failed".to_string()))?;

    // Decrypt with AES-256-CBC
    let aes_key: [u8; 32] = key
        .aes_key()
        .try_into()
        .map_err(|_| ServiceError::InvalidResponse("invalid AES key".to_string()))?;
    let iv_arr: [u8; 16] = iv
        .try_into()
        .map_err(|_| ServiceError::InvalidResponse("invalid IV".to_string()))?;

    let decryptor = Aes256CbcDec::new(&aes_key.into(), &iv_arr.into());
    let mut buf = ciphertext.to_vec();
    let plaintext = decryptor
        .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf)
        .map_err(|e| ServiceError::InvalidResponse(format!("AES decrypt failed: {e}")))?;

    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = AttachmentKey::generate();
        let plaintext = b"Hello, Signal! This is test attachment data.";

        let (encrypted, digest) = encrypt_attachment(&key, plaintext).unwrap();
        let decrypted = decrypt_attachment(&key, &encrypted, Some(&digest)).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_rejects_bad_digest() {
        let key = AttachmentKey::generate();
        let plaintext = b"Test data";

        let (encrypted, _digest) = encrypt_attachment(&key, plaintext).unwrap();
        let bad_digest = vec![0u8; 32];

        let result = decrypt_attachment(&key, &encrypted, Some(&bad_digest));
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_rejects_tampered_data() {
        let key = AttachmentKey::generate();
        let plaintext = b"Test data for integrity check";

        let (mut encrypted, digest) = encrypt_attachment(&key, plaintext).unwrap();

        // Tamper with the ciphertext
        if encrypted.len() > 20 {
            encrypted[20] ^= 0xFF;
        }

        let result = decrypt_attachment(&key, &encrypted, Some(&digest));
        assert!(result.is_err());
    }

    #[test]
    fn key_from_bytes() {
        let key = AttachmentKey::generate();
        let restored = AttachmentKey::from_bytes(&key.combined).unwrap();
        assert_eq!(key.combined, restored.combined);
    }

    #[test]
    fn key_from_wrong_length_fails() {
        let result = AttachmentKey::from_bytes(&[0u8; 32]);
        assert!(result.is_err());
    }
}
