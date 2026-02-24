//! Profile helper -- profile encryption, decryption, and management.
//!
//! Responsible for:
//! - Encrypting profile fields (name, about) with the profile key
//! - Decrypting received profiles
//! - Uploading/downloading profile avatars
//! - Username management (reservation, confirmation, deletion)

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{debug, info};

use signal_rs_service::api::account::{AccountApi, ConfirmUsernameRequest, UsernameHashRequest};
use signal_rs_service::api::profile::{ProfileApi, SetProfileRequest};
use signal_rs_store::Database;
use signal_rs_store::database::account_keys;

use crate::error::{ManagerError, Result};

type HmacSha256 = Hmac<Sha256>;

/// Helper for profile operations.
#[derive(Default)]
pub struct ProfileHelper;

impl ProfileHelper {
    /// Create a new profile helper.
    pub fn new() -> Self {
        Self
    }

    /// Update the user's own profile.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_profile(
        &self,
        db: &Database,
        profile_api: &ProfileApi<'_>,
        given_name: Option<&str>,
        family_name: Option<&str>,
        about: Option<&str>,
        about_emoji: Option<&str>,
        _avatar_path: Option<&str>,
        remove_avatar: bool,
    ) -> Result<()> {
        debug!(?given_name, ?family_name, ?about, "updating profile");

        let b64 = &base64::engine::general_purpose::STANDARD;

        // Retrieve the profile key from the store
        let profile_key = db.get_kv_blob(account_keys::PROFILE_KEY)?
            .ok_or_else(|| ManagerError::Other("no profile key found in store".into()))?;

        // Encrypt the profile name using AES-256-GCM with the profile key.
        let encrypted_name = given_name.map(|name| {
            let padded = pad_profile_name(name, family_name);
            encrypt_profile_field(&padded, &profile_key).map(|encrypted| b64.encode(&encrypted))
        }).transpose()?;

        let encrypted_about = about.map(|text| {
            encrypt_profile_field(text.as_bytes(), &profile_key).map(|encrypted| b64.encode(&encrypted))
        }).transpose()?;

        // Compute profile key commitment and version
        let commitment = compute_profile_key_commitment(&profile_key)?;
        let version = compute_profile_key_version(&profile_key)?;

        let request = SetProfileRequest {
            name: encrypted_name,
            about: encrypted_about,
            about_emoji: about_emoji.map(|s| s.to_string()),
            retain_avatar: !remove_avatar,
            commitment: b64.encode(&commitment),
            version: Some(hex::encode(&version)),
            payment_address: None,
            badge_ids: None,
        };

        profile_api.set_profile(&request).await?;

        info!("profile updated successfully");
        Ok(())
    }

    /// Decrypt a profile name using the profile key.
    pub fn decrypt_profile_name(
        &self,
        encrypted_name: &[u8],
        profile_key: &[u8],
    ) -> Result<String> {
        debug!("decrypting profile name");

        // Decrypt the profile name field
        let decrypted = decrypt_profile_field(encrypted_name, profile_key)?;

        // The profile name format is: given_name + '\0' + family_name
        // with PKCS7-style padding at the end
        let name = String::from_utf8_lossy(&decrypted);
        let name = name.trim_end_matches('\0').to_string();

        Ok(name)
    }

    /// Set the user's username.
    ///
    /// Uses libsignal's `usernames` crate for protocol-correct hashing and
    /// zero-knowledge proof generation.
    pub async fn set_username(
        &self,
        account_api: &AccountApi<'_>,
        username: &str,
    ) -> Result<()> {
        debug!(%username, "setting username");

        let b64 = &base64::engine::general_purpose::STANDARD;

        // Parse and hash the username using libsignal's username algorithm.
        // Username format is "nickname.discriminator" (e.g., "alice.42").
        let parsed = usernames::Username::new(username)
            .map_err(|e| ManagerError::Other(format!("invalid username format: {e}")))?;

        let username_hash = parsed.hash();

        // Generate a zero-knowledge proof that we know the username
        // corresponding to this hash.
        let mut randomness = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut randomness);
        let zk_proof = parsed.proof(&randomness)
            .map_err(|e| ManagerError::Other(format!("username proof generation failed: {e}")))?;

        // Encrypt the username for storage on the server.
        // create_for_username requires rand 0.9's CryptoRng.
        let mut rng = rand_09::rng();
        let (_entropy, encrypted_data) = usernames::create_for_username(
            &mut rng,
            username.to_string(),
            None,
        )
        .map_err(|e| ManagerError::Other(format!("username encryption failed: {e}")))?;

        // Reserve the username hash
        let request = UsernameHashRequest {
            username_hashes: vec![b64.encode(username_hash)],
        };
        let response = account_api.set_username_hash(&request).await?;

        // Confirm the reserved username with ZK proof
        let confirm_request = ConfirmUsernameRequest {
            username_hash: response.username_hash.clone(),
            zk_proof: b64.encode(&zk_proof),
            encrypted_username: Some(b64.encode(&encrypted_data)),
        };
        account_api.confirm_username(&confirm_request).await?;

        info!(%username, "username set successfully");
        Ok(())
    }

    /// Delete the user's username.
    pub async fn delete_username(&self, account_api: &AccountApi<'_>) -> Result<()> {
        debug!("deleting username");
        account_api.delete_username().await?;
        info!("username deleted");
        Ok(())
    }
}

/// Pad a profile name to the Signal format: given_name + '\0' + family_name,
/// padded to a fixed block size.
fn pad_profile_name(given_name: &str, family_name: Option<&str>) -> Vec<u8> {
    let mut name = given_name.as_bytes().to_vec();
    if let Some(family) = family_name {
        name.push(0);
        name.extend_from_slice(family.as_bytes());
    }
    // Pad to the next multiple of 128 bytes (Signal's profile name padding)
    let padded_len = ((name.len() / 128) + 1) * 128;
    name.resize(padded_len, 0);
    name
}

/// Encrypt a profile field using the profile key with AES-256-GCM.
///
/// Output format: nonce(12) || ciphertext || tag(16).
fn encrypt_profile_field(plaintext: &[u8], profile_key: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    use rand::RngCore;

    let cipher = Aes256Gcm::new_from_slice(profile_key)
        .map_err(|e| ManagerError::CryptoError(format!("invalid profile key: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext_with_tag = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| ManagerError::CryptoError(format!("AES-GCM encryption failed: {e}")))?;

    let mut output = Vec::with_capacity(12 + ciphertext_with_tag.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext_with_tag);
    Ok(output)
}

/// Decrypt a profile field using the profile key with AES-256-GCM.
///
/// Input format: nonce(12) || ciphertext || tag(16).
fn decrypt_profile_field(ciphertext: &[u8], profile_key: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

    if ciphertext.len() < 12 + 16 {
        return Err(ManagerError::CryptoError(
            "ciphertext too short for AES-GCM (need at least 28 bytes)".into(),
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(profile_key)
        .map_err(|e| ManagerError::CryptoError(format!("invalid profile key: {e}")))?;

    let nonce = Nonce::from_slice(&ciphertext[..12]);
    let ct_with_tag = &ciphertext[12..];

    cipher
        .decrypt(nonce, ct_with_tag)
        .map_err(|e| ManagerError::CryptoError(format!("AES-GCM decryption failed: {e}")))
}

/// Compute a profile key commitment using HMAC-SHA256.
fn compute_profile_key_commitment(profile_key: &[u8]) -> Result<Vec<u8>> {
    let mut hmac = HmacSha256::new_from_slice(profile_key)
        .map_err(|e| ManagerError::CryptoError(format!("HMAC key init failed: {e}")))?;
    hmac.update(b"profile_key_commitment");
    Ok(hmac.finalize().into_bytes().to_vec())
}

/// Compute a profile key version string using HMAC-SHA256.
///
/// Returns the raw HMAC bytes (caller hex-encodes them).
fn compute_profile_key_version(profile_key: &[u8]) -> Result<Vec<u8>> {
    let mut hmac = HmacSha256::new_from_slice(profile_key)
        .map_err(|e| ManagerError::CryptoError(format!("HMAC key init failed: {e}")))?;
    hmac.update(b"profile_key_version");
    Ok(hmac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- pad_profile_name ----

    #[test]
    fn pad_profile_name_given_only() {
        let padded = pad_profile_name("Alice", None);
        assert_eq!(padded.len(), 128);
        assert!(padded.starts_with(b"Alice"));
        assert!(padded[5..].iter().all(|&b| b == 0));
    }

    #[test]
    fn pad_profile_name_given_and_family() {
        let padded = pad_profile_name("Alice", Some("Smith"));
        assert_eq!(padded.len(), 128);
        assert_eq!(&padded[..5], b"Alice");
        assert_eq!(padded[5], 0); // separator
        assert_eq!(&padded[6..11], b"Smith");
        assert!(padded[11..].iter().all(|&b| b == 0));
    }

    #[test]
    fn pad_profile_name_exact_boundary() {
        let name = "a".repeat(128);
        let padded = pad_profile_name(&name, None);
        assert_eq!(padded.len(), 256);
    }

    #[test]
    fn pad_profile_name_empty() {
        let padded = pad_profile_name("", None);
        assert_eq!(padded.len(), 128);
        assert!(padded.iter().all(|&b| b == 0));
    }

    // ---- encrypt/decrypt profile field roundtrip ----

    #[test]
    fn encrypt_decrypt_profile_field_roundtrip() {
        let profile_key = [0xABu8; 32];
        let plaintext = b"Hello, Signal!";

        let encrypted = encrypt_profile_field(plaintext, &profile_key).unwrap();
        assert_eq!(encrypted.len(), 12 + plaintext.len() + 16);

        let decrypted = decrypt_profile_field(&encrypted, &profile_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_empty_plaintext() {
        let profile_key = [0x42u8; 32];
        let plaintext = b"";

        let encrypted = encrypt_profile_field(plaintext, &profile_key).unwrap();
        let decrypted = decrypt_profile_field(&encrypted, &profile_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_produces_different_nonces() {
        let profile_key = [0x11u8; 32];
        let plaintext = b"test data";

        let e1 = encrypt_profile_field(plaintext, &profile_key).unwrap();
        let e2 = encrypt_profile_field(plaintext, &profile_key).unwrap();

        assert_ne!(&e1[..12], &e2[..12]);
        assert_eq!(
            decrypt_profile_field(&e1, &profile_key).unwrap(),
            decrypt_profile_field(&e2, &profile_key).unwrap()
        );
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key1 = [0xAAu8; 32];
        let key2 = [0xBBu8; 32];
        let plaintext = b"secret";

        let encrypted = encrypt_profile_field(plaintext, &key1).unwrap();
        assert!(decrypt_profile_field(&encrypted, &key2).is_err());
    }

    #[test]
    fn decrypt_too_short_fails() {
        let profile_key = [0x42u8; 32];
        let short = vec![0u8; 20];
        assert!(decrypt_profile_field(&short, &profile_key).is_err());
    }

    // ---- compute_profile_key_commitment ----

    #[test]
    fn profile_key_commitment_deterministic() {
        let key = [0x99u8; 32];
        let c1 = compute_profile_key_commitment(&key).unwrap();
        let c2 = compute_profile_key_commitment(&key).unwrap();
        assert_eq!(c1, c2);
        assert_eq!(c1.len(), 32);
    }

    #[test]
    fn profile_key_commitment_differs_for_different_keys() {
        let c1 = compute_profile_key_commitment(&[0x11u8; 32]).unwrap();
        let c2 = compute_profile_key_commitment(&[0x22u8; 32]).unwrap();
        assert_ne!(c1, c2);
    }

    // ---- compute_profile_key_version ----

    #[test]
    fn profile_key_version_deterministic() {
        let key = [0xCCu8; 32];
        let v1 = compute_profile_key_version(&key).unwrap();
        let v2 = compute_profile_key_version(&key).unwrap();
        assert_eq!(v1, v2);
        assert_eq!(v1.len(), 32);
    }

    #[test]
    fn profile_key_version_differs_from_commitment() {
        let key = [0xDDu8; 32];
        assert_ne!(
            compute_profile_key_commitment(&key).unwrap(),
            compute_profile_key_version(&key).unwrap()
        );
    }

    // ---- username hash (real libsignal algorithm) ----

    fn username_hash(username: &str) -> [u8; 32] {
        usernames::Username::new(username).unwrap().hash()
    }

    #[test]
    fn username_hash_deterministic() {
        let h1 = username_hash("alice.42");
        let h2 = username_hash("alice.42");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn username_hash_differs_for_different_usernames() {
        assert_ne!(
            username_hash("alice.42"),
            username_hash("bob.99")
        );
    }

    #[test]
    fn username_hash_invalid_format() {
        // A username without discriminator should fail
        assert!(usernames::Username::new("alice").is_err());
    }

    #[test]
    fn username_proof_roundtrip() {
        let parsed = usernames::Username::new("alice.42").unwrap();
        let hash = parsed.hash();

        let mut randomness = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut randomness);
        let proof = parsed.proof(&randomness).unwrap();

        // Verify the proof against the hash
        usernames::Username::verify_proof(&proof, hash).unwrap();
    }

    // ---- ProfileHelper decrypt_profile_name ----

    #[test]
    fn decrypt_profile_name_roundtrip_with_family() {
        let helper = ProfileHelper::new();
        let profile_key = [0xEEu8; 32];

        let padded = pad_profile_name("Alice", Some("Smith"));
        let encrypted = encrypt_profile_field(&padded, &profile_key).unwrap();

        let name = helper.decrypt_profile_name(&encrypted, &profile_key).unwrap();
        assert!(name.contains("Alice"));
        assert!(name.contains("Smith"));
    }

    #[test]
    fn decrypt_profile_name_given_only() {
        let helper = ProfileHelper::new();
        let profile_key = [0xFFu8; 32];

        let padded = pad_profile_name("Bob", None);
        let encrypted = encrypt_profile_field(&padded, &profile_key).unwrap();

        let name = helper.decrypt_profile_name(&encrypted, &profile_key).unwrap();
        assert_eq!(name, "Bob");
    }
}
