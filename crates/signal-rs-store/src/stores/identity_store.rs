//! Identity key store implementation.
//!
//! Implements [`signal_rs_protocol::IdentityKeyStore`] for [`Database`].
//! Uses the `identity` table and the `key_value` table for the local identity
//! key pair and registration ID.

use signal_rs_protocol::{
    IdentityKey, IdentityKeyPair, ProtocolAddress, ProtocolError, TrustLevel,
};
use tracing::debug;

use crate::database::Database;

/// Account ID type constants matching signal-cli convention.
const _ACCOUNT_ID_TYPE_ACI: i64 = 0;
const _ACCOUNT_ID_TYPE_PNI: i64 = 1;

/// Key-value store keys for local identity data.
const KEY_IDENTITY_KEY_PAIR: &str = "identity_key_pair";
const KEY_REGISTRATION_ID: &str = "registration_id";

/// Map a `TrustLevel` to its integer representation in the database.
fn trust_level_to_i64(level: TrustLevel) -> i64 {
    match level {
        TrustLevel::Untrusted => 0,
        TrustLevel::TrustedUnverified => 1,
        TrustLevel::TrustedVerified => 2,
    }
}

/// Map an integer from the database to a `TrustLevel`.
fn trust_level_from_i64(value: i64) -> TrustLevel {
    match value {
        0 => TrustLevel::Untrusted,
        1 => TrustLevel::TrustedUnverified,
        2 => TrustLevel::TrustedVerified,
        _ => TrustLevel::Untrusted,
    }
}

impl signal_rs_protocol::stores::IdentityKeyStore for Database {
    fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, ProtocolError> {
        debug!("loading local identity key pair");
        let bytes: Vec<u8> = self
            .conn()
            .query_row(
                "SELECT value FROM key_value WHERE key = ?1",
                [KEY_IDENTITY_KEY_PAIR],
                |row| row.get(0),
            )
            .map_err(|e| ProtocolError::StorageError(format!("failed to load identity key pair: {e}")))?;

        IdentityKeyPair::from_bytes(&bytes)
    }

    fn get_local_registration_id(&self) -> Result<u32, ProtocolError> {
        debug!("loading local registration id");
        let id: i64 = self
            .conn()
            .query_row(
                "SELECT value FROM key_value WHERE key = ?1",
                [KEY_REGISTRATION_ID],
                |row| row.get(0),
            )
            .map_err(|e| ProtocolError::StorageError(format!("failed to load registration id: {e}")))?;

        Ok(id as u32)
    }

    fn save_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool, ProtocolError> {
        let address_str = address.service_id.to_string();
        debug!(address = %address_str, "saving identity key");

        // Check if an existing identity key differs.
        let existing: Option<Vec<u8>> = self
            .conn()
            .query_row(
                "SELECT identity_key FROM identity WHERE address = ?1",
                [&address_str],
                |row| row.get(0),
            )
            .ok();

        let replaced = match &existing {
            Some(existing_key) => existing_key.as_slice() != identity.serialize(),
            None => false,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        self.conn()
            .execute(
                "INSERT INTO identity (address, identity_key, added_timestamp, trust_level)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(address) DO UPDATE SET
                     identity_key = excluded.identity_key,
                     added_timestamp = excluded.added_timestamp",
                rusqlite::params![
                    address_str,
                    identity.serialize(),
                    now,
                    trust_level_to_i64(TrustLevel::TrustedUnverified),
                ],
            )
            .map_err(|e| ProtocolError::StorageError(format!("failed to save identity: {e}")))?;

        Ok(replaced)
    }

    fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _trust_level: TrustLevel,
    ) -> Result<bool, ProtocolError> {
        let address_str = address.service_id.to_string();
        debug!(address = %address_str, "checking identity trust");

        let result: Option<Vec<u8>> = self
            .conn()
            .query_row(
                "SELECT identity_key FROM identity WHERE address = ?1",
                [&address_str],
                |row| row.get(0),
            )
            .ok();

        match result {
            // No stored identity means we trust on first use (TOFU).
            None => Ok(true),
            // If the stored key matches, it is trusted.
            Some(stored_key) => Ok(stored_key.as_slice() == identity.serialize()),
        }
    }

    fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, ProtocolError> {
        let address_str = address.service_id.to_string();
        debug!(address = %address_str, "loading identity key");

        let result: Option<Vec<u8>> = self
            .conn()
            .query_row(
                "SELECT identity_key FROM identity WHERE address = ?1",
                [&address_str],
                |row| row.get(0),
            )
            .ok();

        match result {
            None => Ok(None),
            Some(bytes) => {
                let key = IdentityKey::from_bytes(&bytes)?;
                Ok(Some(key))
            }
        }
    }
}

/// A record of a stored identity key.
#[derive(Debug, Clone)]
pub struct IdentityRecord {
    pub address: String,
    pub identity_key: Vec<u8>,
    pub trust_level: i32,
    pub added_timestamp: i64,
}

impl Database {
    /// List all stored identity records.
    pub fn list_all_identities(&self) -> crate::error::Result<Vec<IdentityRecord>> {
        debug!("listing all identities");
        let mut stmt = self.conn().prepare(
            "SELECT address, identity_key, trust_level, added_timestamp FROM identity ORDER BY _id",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(IdentityRecord {
                    address: row.get("address")?,
                    identity_key: row.get("identity_key")?,
                    trust_level: row.get("trust_level")?,
                    added_timestamp: row.get("added_timestamp")?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Store the local identity key pair in the key-value table.
    pub fn set_identity_key_pair(&self, pair: &IdentityKeyPair) -> crate::error::Result<()> {
        debug!("saving local identity key pair");
        self.conn().execute(
            "INSERT INTO key_value (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![KEY_IDENTITY_KEY_PAIR, pair.serialize()],
        )?;
        Ok(())
    }

    /// Store the local registration ID in the key-value table.
    pub fn set_registration_id(&self, id: u32) -> crate::error::Result<()> {
        debug!(registration_id = id, "saving local registration id");
        self.conn().execute(
            "INSERT INTO key_value (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![KEY_REGISTRATION_ID, id as i64],
        )?;
        Ok(())
    }

    /// Get the trust level for a stored identity.
    pub fn get_identity_trust_level(&self, address: &str) -> crate::error::Result<Option<TrustLevel>> {
        let result: Option<i64> = self
            .conn()
            .query_row(
                "SELECT trust_level FROM identity WHERE address = ?1",
                [address],
                |row| row.get(0),
            )
            .ok();
        Ok(result.map(trust_level_from_i64))
    }

    /// Set the trust level for a stored identity.
    pub fn set_identity_trust_level(
        &self,
        address: &str,
        level: TrustLevel,
    ) -> crate::error::Result<()> {
        debug!(address, ?level, "setting identity trust level");
        self.conn().execute(
            "UPDATE identity SET trust_level = ?1 WHERE address = ?2",
            rusqlite::params![trust_level_to_i64(level), address],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signal_rs_protocol::stores::IdentityKeyStore;
    use signal_rs_protocol::{DeviceId, ServiceId};
    use uuid::Uuid;

    #[test]
    fn list_all_identities() {
        let db = Database::open_in_memory().unwrap();

        // Initially no identities.
        let identities = db.list_all_identities().unwrap();
        assert!(identities.is_empty());

        // Save a couple of remote identities.
        let uuid1 = Uuid::new_v4();
        let addr1 = ProtocolAddress::new(ServiceId::aci(uuid1), DeviceId(1));
        let pair1 = IdentityKeyPair::generate();
        db.save_identity(&addr1, pair1.public_key()).unwrap();

        let uuid2 = Uuid::new_v4();
        let addr2 = ProtocolAddress::new(ServiceId::aci(uuid2), DeviceId(1));
        let pair2 = IdentityKeyPair::generate();
        db.save_identity(&addr2, pair2.public_key()).unwrap();

        let identities = db.list_all_identities().unwrap();
        assert_eq!(identities.len(), 2);
        assert_eq!(identities[0].trust_level, 1); // TrustedUnverified
    }

    #[test]
    fn save_and_load_identity() {
        let db = Database::open_in_memory().unwrap();
        let pair = IdentityKeyPair::generate();
        db.set_identity_key_pair(&pair).unwrap();
        db.set_registration_id(42).unwrap();

        let loaded_pair = db.get_identity_key_pair().unwrap();
        assert_eq!(pair.public_key(), loaded_pair.public_key());
        assert_eq!(db.get_local_registration_id().unwrap(), 42);

        // Save a remote identity.
        let uuid = Uuid::new_v4();
        let addr = ProtocolAddress::new(ServiceId::aci(uuid), DeviceId(1));
        let remote_pair = IdentityKeyPair::generate();
        let remote_key = remote_pair.public_key().clone();

        let replaced = db.save_identity(&addr, &remote_key).unwrap();
        assert!(!replaced);

        let loaded = db.get_identity(&addr).unwrap();
        assert_eq!(loaded.as_ref(), Some(&remote_key));

        assert!(db.is_trusted_identity(&addr, &remote_key, TrustLevel::TrustedUnverified).unwrap());
    }
}
