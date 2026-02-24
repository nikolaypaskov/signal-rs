//! Groups v2 operations.
//!
//! This module provides higher-level group operations that combine API calls
//! with crypto. The actual API calls are in `crate::api::groups_v2`.
//!
//! Key concepts:
//! - **GroupMasterKey**: 32-byte master key for deriving all group secrets
//! - **GroupSecretParams**: derived from master key, used for zkgroup operations
//! - **Group ID**: derived from the master key, used to identify the group
//!
//! Group encryption uses the master key to derive encryption keys for:
//! - Group title
//! - Group description
//! - Group avatar
//! - Member profile keys
//!
//! Uses the official libsignal zkgroup crate for GroupSecretParams derivation,
//! group ID derivation, and blob encryption/decryption.

use crate::error::{Result, ServiceError};
use zkgroup::groups::GroupSecretParams;

/// The length of a group master key.
pub const GROUP_MASTER_KEY_LEN: usize = 32;

/// The length of a group identifier.
pub const GROUP_ID_LEN: usize = 32;

/// A 32-byte group master key from which all group secrets are derived.
#[derive(Debug, Clone)]
pub struct GroupMasterKey {
    /// The raw 32-byte key.
    pub bytes: [u8; GROUP_MASTER_KEY_LEN],
}

impl GroupMasterKey {
    /// Create a group master key from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != GROUP_MASTER_KEY_LEN {
            return Err(ServiceError::InvalidResponse(format!(
                "invalid group master key length: expected {}, got {}",
                GROUP_MASTER_KEY_LEN,
                bytes.len()
            )));
        }
        let mut key = [0u8; GROUP_MASTER_KEY_LEN];
        key.copy_from_slice(bytes);
        Ok(Self { bytes: key })
    }

    /// Generate a new random group master key.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; GROUP_MASTER_KEY_LEN];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Build the real zkgroup GroupSecretParams from this master key.
    fn zkgroup_secret_params(&self) -> GroupSecretParams {
        let zk_master_key = zkgroup::groups::GroupMasterKey::new(self.bytes);
        GroupSecretParams::derive_from_master_key(zk_master_key)
    }

    /// Derive the group identifier (group ID) from the master key.
    ///
    /// Uses the real zkgroup GroupSecretParams to derive the group identifier,
    /// matching the Signal protocol exactly.
    pub fn derive_group_id(&self) -> [u8; GROUP_ID_LEN] {
        let params = self.zkgroup_secret_params();
        params.get_group_identifier()
    }

    /// Derive the group secret params (used for zkgroup operations).
    ///
    /// Returns the serialized GroupSecretParams from zkgroup, suitable for
    /// storage or transmission.
    pub fn derive_secret_params(&self) -> GroupSecretParams {
        self.zkgroup_secret_params()
    }

    /// Encrypt a group title using zkgroup blob encryption.
    ///
    /// Uses GroupSecretParams::encrypt_blob_with_padding for protocol-correct
    /// encryption with random padding.
    pub fn encrypt_title(&self, title: &str) -> Result<Vec<u8>> {
        use rand::RngCore;

        let params = self.zkgroup_secret_params();
        let mut randomness = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut randomness);

        let encrypted = params.encrypt_blob_with_padding(
            randomness,
            title.as_bytes(),
            0,
        );
        Ok(encrypted)
    }

    /// Decrypt a group title using zkgroup blob decryption.
    pub fn decrypt_title(&self, encrypted: &[u8]) -> Result<String> {
        let params = self.zkgroup_secret_params();
        let plaintext = params
            .decrypt_blob_with_padding(encrypted)
            .map_err(|e| ServiceError::InvalidResponse(format!("group title decrypt failed: {e}")))?;

        String::from_utf8(plaintext).map_err(|e| {
            ServiceError::InvalidResponse(format!("group title not valid UTF-8: {e}"))
        })
    }
}

/// Parse a group ID from its base64-encoded representation.
pub fn parse_group_id(encoded: &str) -> Result<[u8; GROUP_ID_LEN]> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| ServiceError::InvalidResponse(format!("invalid group ID encoding: {e}")))?;
    if bytes.len() != GROUP_ID_LEN {
        return Err(ServiceError::InvalidResponse(format!(
            "invalid group ID length: expected {}, got {}",
            GROUP_ID_LEN,
            bytes.len()
        )));
    }
    let mut id = [0u8; GROUP_ID_LEN];
    id.copy_from_slice(&bytes);
    Ok(id)
}

/// Encode a group ID to its base64 representation.
pub fn encode_group_id(group_id: &[u8; GROUP_ID_LEN]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(group_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_master_key_roundtrip() {
        let key = GroupMasterKey::generate();
        let restored = GroupMasterKey::from_bytes(&key.bytes).unwrap();
        assert_eq!(key.bytes, restored.bytes);
    }

    #[test]
    fn group_id_deterministic() {
        let key = GroupMasterKey::generate();
        let id1 = key.derive_group_id();
        let id2 = key.derive_group_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn different_keys_produce_different_ids() {
        let key1 = GroupMasterKey::generate();
        let key2 = GroupMasterKey::generate();
        assert_ne!(key1.derive_group_id(), key2.derive_group_id());
    }

    #[test]
    fn group_title_encrypt_decrypt() {
        let key = GroupMasterKey::generate();
        let title = "Test Group Title";

        let encrypted = key.encrypt_title(title).unwrap();
        let decrypted = key.decrypt_title(&encrypted).unwrap();

        assert_eq!(decrypted, title);
    }

    #[test]
    fn group_id_encode_decode() {
        let key = GroupMasterKey::generate();
        let id = key.derive_group_id();
        let encoded = encode_group_id(&id);
        let decoded = parse_group_id(&encoded).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn group_master_key_wrong_length() {
        let result = GroupMasterKey::from_bytes(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn secret_params_deterministic() {
        let key = GroupMasterKey::generate();
        let params1 = key.derive_secret_params();
        let params2 = key.derive_secret_params();
        // GroupSecretParams derived from the same master key should be identical
        assert_eq!(
            params1.get_group_identifier(),
            params2.get_group_identifier()
        );
    }

    #[test]
    fn zkgroup_group_id_is_32_bytes() {
        let key = GroupMasterKey::generate();
        let id = key.derive_group_id();
        assert_eq!(id.len(), GROUP_ID_LEN);
    }

    #[test]
    fn zkgroup_secret_params_has_public_params() {
        let key = GroupMasterKey::generate();
        let params = key.derive_secret_params();
        // Should be able to get public params without panicking
        let _public = params.get_public_params();
    }
}
