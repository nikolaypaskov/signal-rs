//! Profile operations.
//!
//! This module provides:
//! - Profile name encryption/decryption (AES-256-GCM)
//! - Profile key derivation helpers
//! - Unidentified access key derivation
//!
//! Signal profiles are encrypted with a 32-byte profile key. The profile key is used
//! to derive encryption keys for the profile name, about, and about_emoji fields.
//!
//! Encryption scheme:
//! - Derive a 32-byte encryption key from profile_key using HKDF
//! - Encrypt the profile name with AES-256-GCM (12-byte nonce, 16-byte tag)
//! - Output format: nonce(12) || ciphertext || tag(16)

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{Result, ServiceError};

type HmacSha256 = Hmac<Sha256>;

/// The length of a profile key.
pub const PROFILE_KEY_LEN: usize = 32;

/// HKDF info for deriving the profile name encryption key.
const NAME_KEY_INFO: &[u8] = b"Profile Name";

/// HKDF info for deriving the access key from the profile key.
const ACCESS_KEY_INFO: &[u8] = b"Unidentified Access Key";

/// The length of an unidentified access key.
const ACCESS_KEY_LEN: usize = 16;

/// A 32-byte profile key used for encrypting profile data.
#[derive(Debug, Clone)]
pub struct ProfileKey {
    /// The raw 32-byte key.
    pub bytes: [u8; PROFILE_KEY_LEN],
}

impl ProfileKey {
    /// Create a profile key from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PROFILE_KEY_LEN {
            return Err(ServiceError::InvalidResponse(format!(
                "invalid profile key length: expected {}, got {}",
                PROFILE_KEY_LEN,
                bytes.len()
            )));
        }
        let mut key = [0u8; PROFILE_KEY_LEN];
        key.copy_from_slice(bytes);
        Ok(Self { bytes: key })
    }

    /// Generate a new random profile key.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; PROFILE_KEY_LEN];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Derive the unidentified access key from this profile key.
    ///
    /// The access key is used for sealed sender (unidentified delivery).
    /// Recipients can verify the access key to accept unidentified messages.
    pub fn derive_access_key(&self) -> Vec<u8> {
        let hk = Hkdf::<Sha256>::new(None, &self.bytes);
        let mut okm = vec![0u8; ACCESS_KEY_LEN];
        hk.expand(ACCESS_KEY_INFO, &mut okm)
            .expect("HKDF expand should not fail for 16 bytes");
        okm
    }

    /// Derive the encryption key for profile name/about fields.
    fn derive_name_key(&self) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.bytes);
        let mut okm = [0u8; 32];
        hk.expand(NAME_KEY_INFO, &mut okm)
            .expect("HKDF expand should not fail for 32 bytes");
        okm
    }

    /// Encrypt a profile name string.
    ///
    /// The name is padded to a fixed length, then encrypted with
    /// AES-256-GCM using a random 12-byte nonce. The output is nonce(12) || ciphertext || tag(16).
    pub fn encrypt_name(&self, name: &str) -> Result<Vec<u8>> {
        let name_key = self.derive_name_key();

        // Pad the name to 81 bytes (Signal's fixed profile name length)
        let name_bytes = name.as_bytes();
        if name_bytes.len() > 81 {
            return Err(ServiceError::InvalidResponse(
                "profile name too long (max 81 bytes)".to_string(),
            ));
        }
        let mut padded = vec![0u8; 81];
        padded[..name_bytes.len()].copy_from_slice(name_bytes);

        // Generate random nonce
        use rand::RngCore;
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&name_key)
            .map_err(|e| ServiceError::InvalidResponse(format!("AES-GCM key init failed: {e}")))?;
        let ciphertext_with_tag = cipher.encrypt(nonce, padded.as_ref()).map_err(|e| {
            ServiceError::InvalidResponse(format!("AES-GCM encrypt failed: {e}"))
        })?;

        // Output: nonce(12) || ciphertext || tag(16)
        let mut output = Vec::with_capacity(12 + ciphertext_with_tag.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext_with_tag);

        Ok(output)
    }

    /// Decrypt a profile name.
    ///
    /// The input is nonce(12) || ciphertext || tag(16).
    /// Returns the decrypted name with trailing null bytes stripped.
    pub fn decrypt_name(&self, encrypted: &[u8]) -> Result<String> {
        if encrypted.len() < 12 + 16 {
            return Err(ServiceError::InvalidResponse(
                "encrypted profile name too short".to_string(),
            ));
        }

        let name_key = self.derive_name_key();
        let nonce = Nonce::from_slice(&encrypted[..12]);
        let ciphertext_with_tag = &encrypted[12..];

        let cipher = Aes256Gcm::new_from_slice(&name_key)
            .map_err(|e| ServiceError::InvalidResponse(format!("AES-GCM key init failed: {e}")))?;
        let plaintext = cipher.decrypt(nonce, ciphertext_with_tag).map_err(|e| {
            ServiceError::InvalidResponse(format!("profile name decrypt failed: {e}"))
        })?;

        // Strip trailing null bytes
        let end = plaintext
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(plaintext.len());

        String::from_utf8(plaintext[..end].to_vec()).map_err(|e| {
            ServiceError::InvalidResponse(format!("profile name not valid UTF-8: {e}"))
        })
    }

    /// Compute a profile key version string.
    ///
    /// The version is an HMAC of the profile key using the UUID as the message.
    /// This is used to detect when profiles need to be refreshed.
    /// Returns a base64url-no-pad encoded string.
    pub fn get_version_string(&self, uuid: &uuid::Uuid) -> String {
        use base64::Engine;
        let mut hmac = <HmacSha256 as Mac>::new_from_slice(&self.bytes)
            .expect("HMAC init should not fail");
        hmac.update(uuid.as_bytes());
        let result = hmac.finalize().into_bytes();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(result)
    }

    /// Compute a profile key commitment.
    ///
    /// The commitment binds the profile key to a UUID, used during
    /// profile uploads to prove ownership without revealing the key.
    pub fn get_commitment(&self, uuid: &uuid::Uuid) -> Vec<u8> {
        let hk = Hkdf::<Sha256>::new(Some(uuid.as_bytes()), &self.bytes);
        let mut okm = vec![0u8; 32];
        hk.expand(b"Profile Key Commitment", &mut okm)
            .expect("HKDF expand should not fail for 32 bytes");
        okm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_key_encrypt_decrypt_roundtrip() {
        let key = ProfileKey::generate();
        let name = "Alice Smith";

        let encrypted = key.encrypt_name(name).unwrap();
        let decrypted = key.decrypt_name(&encrypted).unwrap();

        assert_eq!(decrypted, name);
    }

    #[test]
    fn profile_key_rejects_long_name() {
        let key = ProfileKey::generate();
        let long_name = "a".repeat(100);

        let result = key.encrypt_name(&long_name);
        assert!(result.is_err());
    }

    #[test]
    fn profile_key_access_key_derivation() {
        let key = ProfileKey::generate();
        let access_key = key.derive_access_key();
        assert_eq!(access_key.len(), ACCESS_KEY_LEN);

        // Same key should produce same access key
        let access_key2 = key.derive_access_key();
        assert_eq!(access_key, access_key2);
    }

    #[test]
    fn profile_key_version_string() {
        let key = ProfileKey::generate();
        let uuid = uuid::Uuid::new_v4();

        let version = key.get_version_string(&uuid);
        assert!(!version.is_empty());
        assert_eq!(version.len(), 43); // base64url-no-pad encoded 32-byte HMAC
    }

    #[test]
    fn profile_key_commitment() {
        let key = ProfileKey::generate();
        let uuid = uuid::Uuid::new_v4();

        let commitment = key.get_commitment(&uuid);
        assert_eq!(commitment.len(), 32);
    }

    #[test]
    fn profile_key_from_bytes() {
        let key = ProfileKey::generate();
        let restored = ProfileKey::from_bytes(&key.bytes).unwrap();
        assert_eq!(key.bytes, restored.bytes);
    }

    #[test]
    fn profile_key_wrong_length_fails() {
        let result = ProfileKey::from_bytes(&[0u8; 16]);
        assert!(result.is_err());
    }
}
