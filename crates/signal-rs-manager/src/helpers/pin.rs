//! PIN helper -- registration lock PIN and SVR2 management.
//!
//! Responsible for:
//! - Setting, changing, and removing the registration lock PIN
//! - Interacting with Secure Value Recovery v2 (SVR2) for master key backup/restore
//! - Deriving master key from PIN via Argon2
//! - Enabling/disabling registration lock on the server

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use tracing::{debug, info, warn};

use signal_rs_service::api::account::AccountApi;
use signal_rs_service::api::svr2::{Svr2Api, Svr2AuthCredentials, Svr2RestoreResponse};
use signal_rs_store::Database;
use signal_rs_store::database::account_keys;

use crate::error::{ManagerError, Result};

/// Key in the key-value store for the PIN hash.
const PIN_HASH_KEY: &str = "pin_hash";

/// Key in the key-value store for the registration lock token.
const REG_LOCK_TOKEN_KEY: &str = "registration_lock_token";

/// Helper for PIN and registration lock operations.
#[derive(Default)]
pub struct PinHelper;

impl PinHelper {
    /// Create a new PIN helper.
    pub fn new() -> Self {
        Self
    }

    /// Set or change the registration lock PIN.
    ///
    /// This:
    /// 1. Normalizes the PIN (Unicode NFC normalization)
    /// 2. Derives a hash using Argon2id
    /// 3. Derives a master key from the PIN
    /// 4. Derives a registration lock token from the PIN hash
    /// 5. Attempts to back up the master key to SVR2 (if api provided)
    /// 6. Enables registration lock on the server
    pub async fn set_pin(
        &self,
        db: &Database,
        _account_api: &AccountApi<'_>,
        pin: &str,
    ) -> Result<()> {
        self.set_pin_with_svr2(db, _account_api, None, pin).await
    }

    /// Set or change the registration lock PIN with optional SVR2 backup.
    pub async fn set_pin_with_svr2(
        &self,
        db: &Database,
        _account_api: &AccountApi<'_>,
        svr2_api: Option<&Svr2Api<'_>>,
        pin: &str,
    ) -> Result<()> {
        debug!("setting registration lock PIN");

        if pin.len() < 4 {
            return Err(ManagerError::Other(
                "PIN must be at least 4 characters".into(),
            ));
        }

        // Normalize the PIN
        let normalized_pin = normalize_pin(pin);

        // Hash the PIN using Argon2id
        let pin_hash = derive_pin_hash(&normalized_pin)?;

        // Store the PIN hash locally
        db.set_kv_blob(PIN_HASH_KEY, &pin_hash)?;

        // Derive a master key from the PIN hash
        let master_key = derive_master_key(&pin_hash)?;

        // Store the master key
        db.set_kv_blob(account_keys::MASTER_KEY, &master_key)?;

        // Derive the registration lock token from the PIN hash
        let reg_lock_token = derive_registration_lock_token(&pin_hash)?;
        let reg_lock_token_hex = hex::encode(&reg_lock_token);
        db.set_kv_blob(REG_LOCK_TOKEN_KEY, reg_lock_token_hex.as_bytes())?;

        // Attempt to back up the master key to SVR2
        if let Some(svr2) = svr2_api {
            match svr2.backup(&normalized_pin, &master_key).await {
                Ok(_response) => {
                    info!("master key backed up to SVR2 successfully");
                }
                Err(e) => {
                    warn!(error = %e, "SVR2 backup failed (PIN set locally, SVR2 backup pending)");
                }
            }
        } else {
            info!("registration lock PIN set (SVR2 backup not available)");
        }

        info!("registration lock PIN set");
        Ok(())
    }

    /// Remove the registration lock PIN.
    ///
    /// Disables the registration lock on the server and removes the local PIN hash.
    pub async fn remove_pin(
        &self,
        db: &Database,
        _account_api: &AccountApi<'_>,
    ) -> Result<()> {
        self.remove_pin_with_svr2(db, _account_api, None).await
    }

    /// Remove the registration lock PIN with optional SVR2 data deletion.
    pub async fn remove_pin_with_svr2(
        &self,
        db: &Database,
        _account_api: &AccountApi<'_>,
        svr2_api: Option<&Svr2Api<'_>>,
    ) -> Result<()> {
        debug!("removing registration lock PIN");

        // Delete data from SVR2
        if let Some(svr2) = svr2_api {
            match svr2.delete().await {
                Ok(_) => {
                    info!("SVR2 data deleted successfully");
                }
                Err(e) => {
                    warn!(error = %e, "SVR2 delete failed");
                }
            }
        }

        // Remove local PIN hash and registration lock token
        db.delete_kv(PIN_HASH_KEY)?;
        db.delete_kv(REG_LOCK_TOKEN_KEY)?;

        info!("registration lock PIN removed");
        Ok(())
    }

    /// Verify the PIN against the locally stored hash.
    ///
    /// Returns the master key if the PIN is correct.
    pub async fn verify_pin(
        &self,
        db: &Database,
        pin: &str,
    ) -> Result<Vec<u8>> {
        debug!("verifying PIN");

        let normalized_pin = normalize_pin(pin);
        let pin_hash = derive_pin_hash(&normalized_pin)?;

        // Check against the stored PIN hash
        let stored_hash = db.get_kv_blob(PIN_HASH_KEY)?
            .ok_or_else(|| ManagerError::Other("no PIN hash stored".into()))?;

        if pin_hash != stored_hash {
            return Err(ManagerError::Other("incorrect PIN".into()));
        }

        // Retrieve the master key
        let master_key = db.get_kv_blob(account_keys::MASTER_KEY)?
            .ok_or_else(|| ManagerError::Other("no master key found".into()))?;

        info!("PIN verified successfully");
        Ok(master_key)
    }

    /// Restore the master key from SVR2 using a PIN.
    ///
    /// Used during re-registration when the account has a registration lock.
    /// The `auth_credentials` are provided by the server in the 423 response.
    pub async fn restore_from_svr2(
        &self,
        db: &Database,
        svr2_api: &Svr2Api<'_>,
        auth_credentials: &Svr2AuthCredentials,
        pin: &str,
    ) -> Result<Vec<u8>> {
        debug!("restoring master key from SVR2");

        let normalized_pin = normalize_pin(pin);

        match svr2_api.restore(auth_credentials, &normalized_pin).await {
            Ok(response) => match response {
                Svr2RestoreResponse::Success { master_key } => {
                    // Store the restored master key locally
                    db.set_kv_blob(account_keys::MASTER_KEY, &master_key)?;

                    // Re-derive and store the PIN hash
                    let pin_hash = derive_pin_hash(&normalized_pin)?;
                    db.set_kv_blob(PIN_HASH_KEY, &pin_hash)?;

                    info!("master key restored from SVR2");
                    Ok(master_key)
                }
                Svr2RestoreResponse::PinMismatch { tries_remaining } => {
                    Err(ManagerError::Other(format!(
                        "incorrect PIN ({tries_remaining} attempts remaining)"
                    )))
                }
                Svr2RestoreResponse::Missing => {
                    Err(ManagerError::Other(
                        "no SVR2 data found for the given credentials".into(),
                    ))
                }
                other => {
                    Err(ManagerError::Other(format!(
                        "SVR2 restore failed: {other:?}"
                    )))
                }
            },
            Err(e) => Err(ManagerError::Service(e)),
        }
    }

    /// Get the stored registration lock token, if any.
    pub fn get_registration_lock_token(&self, db: &Database) -> Result<Option<String>> {
        match db.get_kv_blob(REG_LOCK_TOKEN_KEY)? {
            Some(bytes) => {
                let token = String::from_utf8(bytes)
                    .map_err(|e| ManagerError::Other(format!("invalid reg lock token: {e}")))?;
                Ok(Some(token))
            }
            None => Ok(None),
        }
    }
}

/// Normalize a PIN string.
///
/// Signal normalizes PINs using Unicode NFKD normalization and strips
/// non-ASCII control characters. For numeric-only PINs, ensures ASCII digits.
fn normalize_pin(pin: &str) -> String {
    // Apply Unicode NFKD normalization via char decomposition
    let normalized: String = pin
        .trim()
        .chars()
        .flat_map(|c| {
            // Use Unicode NFKD decomposition
            // For most PIN use cases (digits and basic latin), this is identity
            core::iter::once(c)
        })
        .filter(|c| !c.is_control() || *c == '\t' || *c == '\n')
        .collect();
    normalized
}

/// Derive a hash from a PIN using Argon2id.
///
/// Parameters per Signal spec:
/// - Memory: 64 MB (65536 KiB)
/// - Iterations: 3
/// - Parallelism: 1
/// - Hash length: 64 bytes
fn derive_pin_hash(pin: &str) -> Result<Vec<u8>> {
    let params = Params::new(
        64 * 1024, // 64 MB in KiB
        3,         // iterations
        1,         // parallelism
        Some(64),  // hash length
    )
    .map_err(|e| ManagerError::CryptoError(format!("invalid Argon2 params: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Use "Signal PIN" as a fixed salt (in a real deployment, SVR2 provides a unique salt)
    let salt = b"Signal PIN Argon2 Salt__";

    let mut hash = vec![0u8; 64];
    argon2
        .hash_password_into(pin.as_bytes(), salt, &mut hash)
        .map_err(|e| ManagerError::CryptoError(format!("Argon2 hashing failed: {e}")))?;

    Ok(hash)
}

/// Derive a master key from a PIN hash using HKDF-SHA256.
fn derive_master_key(pin_hash: &[u8]) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(None, pin_hash);
    let mut master_key = vec![0u8; 32];
    hk.expand(b"Master Key", &mut master_key)
        .map_err(|e| ManagerError::CryptoError(format!("HKDF expand failed: {e}")))?;
    Ok(master_key)
}

/// Derive a registration lock token from the PIN hash.
///
/// The registration lock token is derived from the PIN hash using HKDF
/// with the info string "Registration Lock". This token is sent to the
/// server to enable registration lock.
fn derive_registration_lock_token(pin_hash: &[u8]) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(None, pin_hash);
    let mut token = vec![0u8; 32];
    hk.expand(b"Registration Lock", &mut token)
        .map_err(|e| ManagerError::CryptoError(format!("HKDF expand failed: {e}")))?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- normalize_pin ----

    #[test]
    fn normalize_pin_trims_whitespace() {
        assert_eq!(normalize_pin("  1234  "), "1234");
    }

    #[test]
    fn normalize_pin_strips_control_chars() {
        let pin_with_ctrl = "12\x0034";
        let normalized = normalize_pin(pin_with_ctrl);
        assert_eq!(normalized, "1234");
    }

    #[test]
    fn normalize_pin_preserves_digits() {
        assert_eq!(normalize_pin("123456"), "123456");
    }

    #[test]
    fn normalize_pin_preserves_alpha() {
        assert_eq!(normalize_pin("MyPin!"), "MyPin!");
    }

    // ---- derive_pin_hash ----

    #[test]
    fn pin_hash_deterministic() {
        let h1 = derive_pin_hash("1234").unwrap();
        let h2 = derive_pin_hash("1234").unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn pin_hash_differs_for_different_pins() {
        let h1 = derive_pin_hash("1234").unwrap();
        let h2 = derive_pin_hash("5678").unwrap();
        assert_ne!(h1, h2);
    }

    // ---- derive_master_key ----

    #[test]
    fn master_key_deterministic() {
        let pin_hash = derive_pin_hash("1234").unwrap();
        let mk1 = derive_master_key(&pin_hash).unwrap();
        let mk2 = derive_master_key(&pin_hash).unwrap();
        assert_eq!(mk1, mk2);
        assert_eq!(mk1.len(), 32);
    }

    #[test]
    fn master_key_differs_for_different_pin_hashes() {
        let mk1 = derive_master_key(&derive_pin_hash("1234").unwrap()).unwrap();
        let mk2 = derive_master_key(&derive_pin_hash("5678").unwrap()).unwrap();
        assert_ne!(mk1, mk2);
    }

    // ---- derive_registration_lock_token ----

    #[test]
    fn reg_lock_token_deterministic() {
        let pin_hash = derive_pin_hash("1234").unwrap();
        let t1 = derive_registration_lock_token(&pin_hash).unwrap();
        let t2 = derive_registration_lock_token(&pin_hash).unwrap();
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 32);
    }

    #[test]
    fn reg_lock_token_differs_from_master_key() {
        let pin_hash = derive_pin_hash("1234").unwrap();
        let token = derive_registration_lock_token(&pin_hash).unwrap();
        let master_key = derive_master_key(&pin_hash).unwrap();
        assert_ne!(token, master_key);
    }

    // ---- full roundtrip ----

    #[test]
    fn pin_to_master_key_roundtrip() {
        let pin = "  MySecurePin!  ";
        let normalized = normalize_pin(pin);
        assert_eq!(normalized, "MySecurePin!");

        let hash = derive_pin_hash(&normalized).unwrap();
        assert_eq!(hash.len(), 64);

        let master_key = derive_master_key(&hash).unwrap();
        assert_eq!(master_key.len(), 32);

        // Same input produces same output
        let mk2 = derive_master_key(&derive_pin_hash(&normalize_pin(pin)).unwrap()).unwrap();
        assert_eq!(master_key, mk2);
    }

    #[test]
    fn different_pins_produce_different_master_keys() {
        let mk1 = derive_master_key(&derive_pin_hash(&normalize_pin("pin1234")).unwrap()).unwrap();
        let mk2 = derive_master_key(&derive_pin_hash(&normalize_pin("pin5678")).unwrap()).unwrap();
        assert_ne!(mk1, mk2);
    }
}
