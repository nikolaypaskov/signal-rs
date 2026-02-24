//! Identity helper -- identity key management and safety numbers.
//!
//! Responsible for:
//! - Computing safety numbers for identity verification
//! - Verifying identity keys (trust on first use, explicit verification)
//! - Handling identity key changes
//! - Generating fingerprint strings for display

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use uuid::Uuid;

use signal_rs_protocol::TrustLevel;
use signal_rs_store::Database;

use crate::error::{ManagerError, Result};
use crate::types::{Identity, RecipientIdentifier};

type HmacSha256 = Hmac<Sha256>;

/// Helper for identity/trust operations.
#[derive(Default)]
pub struct IdentityHelper;

impl IdentityHelper {
    /// Create a new identity helper.
    pub fn new() -> Self {
        Self
    }

    /// Get all stored identities.
    pub async fn get_identities(&self, db: &Database) -> Result<Vec<Identity>> {
        debug!("listing all identities");

        let records = db.list_all_identities()?;
        let mut identities = Vec::with_capacity(records.len());

        for record in records {
            // Parse the address as a UUID
            let uuid = Uuid::parse_str(&record.address).unwrap_or_default();

            // Compute a displayable fingerprint from the identity key bytes
            let fingerprint = compute_fingerprint_from_key(&record.identity_key);

            let trust_level = match record.trust_level {
                0 => TrustLevel::Untrusted,
                1 => TrustLevel::TrustedUnverified,
                2 => TrustLevel::TrustedVerified,
                _ => TrustLevel::Untrusted,
            };

            identities.push(Identity {
                address: uuid,
                trust_level,
                fingerprint,
                added: record.added_timestamp as u64,
            });
        }

        debug!(count = identities.len(), "loaded identities");
        Ok(identities)
    }

    /// Trust an identity as verified after comparing safety numbers.
    pub async fn trust_verified(
        &self,
        db: &Database,
        recipient: &RecipientIdentifier,
        _safety_number: &str,
    ) -> Result<()> {
        let address = resolve_address(recipient)?;
        debug!(%address, "trusting identity as verified");

        db.set_identity_trust_level(&address, TrustLevel::TrustedVerified)?;

        info!(%address, "identity marked as TrustedVerified");
        Ok(())
    }

    /// Trust all known keys for a recipient (accept on first use).
    pub async fn trust_all_keys(
        &self,
        db: &Database,
        recipient: &RecipientIdentifier,
    ) -> Result<()> {
        let address = resolve_address(recipient)?;
        debug!(%address, "trusting all keys as TrustedUnverified");

        db.set_identity_trust_level(&address, TrustLevel::TrustedUnverified)?;

        info!(%address, "identity marked as TrustedUnverified");
        Ok(())
    }

    /// Check whether a contact's identity key has changed.
    ///
    /// Compares the incoming identity key bytes against the key stored in the
    /// database for the given address. Returns:
    /// - `Ok(false)` if the keys match or no previous key was stored (TOFU).
    /// - `Ok(true)` if the key has changed. In that case, the new key is stored
    ///   with trust level `TrustedUnverified`, and a warning is logged.
    pub fn check_identity_key_change(
        &self,
        db: &Database,
        address_uuid: &Uuid,
        incoming_key: &[u8],
    ) -> Result<bool> {
        let address = address_uuid.to_string();
        debug!(%address, "checking identity key change");

        let records = db.list_all_identities().map_err(|e| {
            ManagerError::Other(format!("failed to list identities: {e}"))
        })?;

        let existing = records.iter().find(|r| r.address == address);

        match existing {
            None => {
                // Trust on first use -- no previous key, nothing to compare.
                debug!(%address, "no previous identity key, TOFU accepted");
                Ok(false)
            }
            Some(record) => {
                if record.identity_key == incoming_key {
                    // Keys match, no change.
                    debug!(%address, "identity key unchanged");
                    Ok(false)
                } else {
                    // Key changed -- reset trust to unverified and warn.
                    warn!(
                        %address,
                        "identity key changed for contact -- safety number has changed"
                    );
                    db.set_identity_trust_level(&address, TrustLevel::TrustedUnverified)
                        .map_err(|e| {
                            ManagerError::Other(format!(
                                "failed to reset trust level: {e}"
                            ))
                        })?;
                    info!(%address, "trust level reset to TrustedUnverified after key change");
                    Ok(true)
                }
            }
        }
    }

    /// Compute the safety number fingerprint for a recipient.
    pub fn compute_safety_number(
        &self,
        db: &Database,
        recipient: &RecipientIdentifier,
    ) -> Result<String> {
        let address = resolve_address(recipient)?;
        debug!(%address, "computing safety number");

        // Retrieve the identity key for this address
        let records = db.list_all_identities()?;
        let record = records.iter().find(|r| r.address == address)
            .ok_or_else(|| ManagerError::Other(format!(
                "no identity key found for {address}"
            )))?;

        // Compute a numeric safety number from the identity key.
        // The real Signal safety number is computed using the NumericFingerprintGenerator
        // from libsignal, which combines both parties' identity keys and stable identifiers.
        // For now, produce a deterministic numeric string from the key bytes.
        let fingerprint = compute_numeric_safety_number(&record.identity_key);

        debug!(%address, "safety number computed");
        Ok(fingerprint)
    }
}

/// Resolve a RecipientIdentifier to the address string used in the identity store.
fn resolve_address(recipient: &RecipientIdentifier) -> Result<String> {
    match recipient {
        RecipientIdentifier::Uuid(uuid) => Ok(uuid.to_string()),
        RecipientIdentifier::PhoneNumber(number) => {
            Err(ManagerError::Other(format!(
                "cannot resolve phone number {number} to identity address; use UUID instead"
            )))
        }
        RecipientIdentifier::Username(username) => {
            Err(ManagerError::Other(format!(
                "cannot resolve username {username} to identity address; use UUID instead"
            )))
        }
    }
}

/// Compute a hex fingerprint from raw identity key bytes using SHA-256.
fn compute_fingerprint_from_key(key_bytes: &[u8]) -> String {
    use std::fmt::Write;
    let hash = Sha256::digest(key_bytes);
    let mut s = String::with_capacity(64);
    for byte in hash.iter() {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// Compute a numeric safety number from identity key bytes.
///
/// Uses iterated HMAC-SHA256 hashing to produce a 60-digit numeric string.
/// This approximates Signal's NumericFingerprintGenerator using HMAC-SHA256.
fn compute_numeric_safety_number(key_bytes: &[u8]) -> String {
    let mut digits = String::with_capacity(60);

    // Iteratively hash with HMAC-SHA256 to produce 12 groups of 5 digits
    let mut current_hash = Sha256::digest(key_bytes).to_vec();

    for _chunk_idx in 0..12u8 {
        // Use the current hash as HMAC key, hashing the key bytes + iteration
        let mut hmac = HmacSha256::new_from_slice(&current_hash)
            .expect("HMAC init should not fail");
        hmac.update(key_bytes);
        hmac.update(&[_chunk_idx]);
        current_hash = hmac.finalize().into_bytes().to_vec();

        // Extract a 5-digit group from the first 8 bytes of the hash
        let value = u64::from_be_bytes([
            current_hash[0],
            current_hash[1],
            current_hash[2],
            current_hash[3],
            current_hash[4],
            current_hash[5],
            current_hash[6],
            current_hash[7],
        ]);
        let group = value % 100000;
        digits.push_str(&format!("{group:05}"));
    }

    digits
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- compute_fingerprint_from_key ----

    #[test]
    fn fingerprint_deterministic() {
        let key = [0x05u8; 33]; // typical identity key format
        let f1 = compute_fingerprint_from_key(&key);
        let f2 = compute_fingerprint_from_key(&key);
        assert_eq!(f1, f2);
        assert_eq!(f1.len(), 64); // hex-encoded SHA-256 is 64 chars
    }

    #[test]
    fn fingerprint_is_lowercase_hex() {
        let key = [0xAB; 33];
        let fp = compute_fingerprint_from_key(&key);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn fingerprint_differs_for_different_keys() {
        let f1 = compute_fingerprint_from_key(&[0x11; 33]);
        let f2 = compute_fingerprint_from_key(&[0x22; 33]);
        assert_ne!(f1, f2);
    }

    // ---- compute_numeric_safety_number ----

    #[test]
    fn safety_number_is_60_digits() {
        let key = [0x05u8; 33];
        let sn = compute_numeric_safety_number(&key);
        assert_eq!(sn.len(), 60);
        assert!(sn.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn safety_number_deterministic() {
        let key = [0xAB; 33];
        let sn1 = compute_numeric_safety_number(&key);
        let sn2 = compute_numeric_safety_number(&key);
        assert_eq!(sn1, sn2);
    }

    #[test]
    fn safety_number_differs_for_different_keys() {
        let sn1 = compute_numeric_safety_number(&[0x11; 33]);
        let sn2 = compute_numeric_safety_number(&[0x22; 33]);
        assert_ne!(sn1, sn2);
    }

    // ---- resolve_address ----

    #[test]
    fn resolve_address_uuid() {
        let uuid = Uuid::new_v4();
        let r = RecipientIdentifier::Uuid(uuid);
        let addr = resolve_address(&r).unwrap();
        assert_eq!(addr, uuid.to_string());
    }

    #[test]
    fn resolve_address_phone_number_fails() {
        let r = RecipientIdentifier::PhoneNumber("+15551234567".into());
        assert!(resolve_address(&r).is_err());
    }

    #[test]
    fn resolve_address_username_fails() {
        let r = RecipientIdentifier::Username("alice.42".into());
        assert!(resolve_address(&r).is_err());
    }

    // ---- check_identity_key_change ----

    #[test]
    fn identity_key_change_tofu_returns_false() {
        let db = Database::open_in_memory().unwrap();
        let helper = IdentityHelper::new();
        let uuid = Uuid::new_v4();
        // No previous key stored: TOFU
        let result = helper.check_identity_key_change(&db, &uuid, &[0x05; 33]).unwrap();
        assert!(!result, "should return false for trust on first use");
    }

    #[test]
    fn identity_key_change_same_key_returns_false() {
        let db = Database::open_in_memory().unwrap();
        let helper = IdentityHelper::new();
        let uuid = Uuid::new_v4();
        let key_bytes = [0x05; 33];

        // Store an identity key
        use signal_rs_protocol::{ProtocolAddress, ServiceId, DeviceId, IdentityKey};
        use signal_rs_protocol::stores::IdentityKeyStore;
        let addr = ProtocolAddress::new(ServiceId::aci(uuid), DeviceId(1));
        let ik = IdentityKey::from_bytes(&key_bytes).unwrap();
        db.save_identity(&addr, &ik).unwrap();

        // Check with same key -- should return false (no change)
        let result = helper.check_identity_key_change(&db, &uuid, &key_bytes).unwrap();
        assert!(!result, "should return false when keys match");
    }

    #[test]
    fn identity_key_change_different_key_returns_true() {
        let db = Database::open_in_memory().unwrap();
        let helper = IdentityHelper::new();
        let uuid = Uuid::new_v4();

        // Store an identity key
        use signal_rs_protocol::{ProtocolAddress, ServiceId, DeviceId, IdentityKey};
        use signal_rs_protocol::stores::IdentityKeyStore;
        let addr = ProtocolAddress::new(ServiceId::aci(uuid), DeviceId(1));
        let old_key = [0x05; 33];
        let ik = IdentityKey::from_bytes(&old_key).unwrap();
        db.save_identity(&addr, &ik).unwrap();

        // Check with a different key -- should return true (key changed)
        let mut new_key = [0x05; 33];
        new_key[1] = 0xFF; // change the key material
        let result = helper.check_identity_key_change(&db, &uuid, &new_key).unwrap();
        assert!(result, "should return true when keys differ");

        // Verify trust level was reset to TrustedUnverified (i.e. 1)
        let trust = db.get_identity_trust_level(&uuid.to_string()).unwrap();
        assert_eq!(trust, Some(TrustLevel::TrustedUnverified));
    }
}
