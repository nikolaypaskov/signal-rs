//! Pre-key store implementation.
//!
//! Implements [`signal_rs_protocol::PreKeyStore`] for [`Database`].

use signal_rs_protocol::{PreKeyId, PreKeyRecord, ProtocolError};
use tracing::debug;

use crate::database::Database;

/// Default account ID type (ACI = 0).
const ACCOUNT_ID_TYPE_ACI: i64 = 0;

impl signal_rs_protocol::stores::PreKeyStore for Database {
    fn get_pre_key(&self, id: PreKeyId) -> Result<PreKeyRecord, ProtocolError> {
        debug!(key_id = id.0, "loading pre-key");
        let (public_key, private_key): (Vec<u8>, Vec<u8>) = self
            .conn()
            .query_row(
                "SELECT public_key, private_key FROM pre_key
                 WHERE account_id_type = ?1 AND key_id = ?2",
                rusqlite::params![ACCOUNT_ID_TYPE_ACI, id.0 as i64],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|e| {
                ProtocolError::StorageError(format!("failed to load pre-key {id}: {e}"))
            })?;

        Ok(PreKeyRecord {
            id,
            public_key,
            private_key,
        })
    }

    fn save_pre_key(&self, id: PreKeyId, record: &PreKeyRecord) -> Result<(), ProtocolError> {
        debug!(key_id = id.0, "saving pre-key");
        self.conn()
            .execute(
                "INSERT INTO pre_key (account_id_type, key_id, public_key, private_key)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(account_id_type, key_id) DO UPDATE SET
                     public_key = excluded.public_key,
                     private_key = excluded.private_key",
                rusqlite::params![
                    ACCOUNT_ID_TYPE_ACI,
                    id.0 as i64,
                    record.public_key,
                    record.private_key,
                ],
            )
            .map_err(|e| {
                ProtocolError::StorageError(format!("failed to save pre-key {id}: {e}"))
            })?;
        Ok(())
    }

    fn remove_pre_key(&self, id: PreKeyId) -> Result<(), ProtocolError> {
        debug!(key_id = id.0, "removing pre-key");
        self.conn()
            .execute(
                "DELETE FROM pre_key WHERE account_id_type = ?1 AND key_id = ?2",
                rusqlite::params![ACCOUNT_ID_TYPE_ACI, id.0 as i64],
            )
            .map_err(|e| {
                ProtocolError::StorageError(format!("failed to remove pre-key {id}: {e}"))
            })?;
        Ok(())
    }
}

impl Database {
    /// Save a pre-key with a specific account ID type (0 = ACI, 1 = PNI).
    pub fn save_pre_key_for_account(
        &self,
        account_id_type: i64,
        id: PreKeyId,
        record: &PreKeyRecord,
    ) -> crate::error::Result<()> {
        debug!(account_id_type, key_id = id.0, "saving pre-key for account type");
        self.conn().execute(
            "INSERT INTO pre_key (account_id_type, key_id, public_key, private_key)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(account_id_type, key_id) DO UPDATE SET
                 public_key = excluded.public_key,
                 private_key = excluded.private_key",
            rusqlite::params![account_id_type, id.0 as i64, record.public_key, record.private_key],
        )?;
        Ok(())
    }

    /// Mark a pre-key as stale.
    pub fn mark_pre_key_stale(&self, account_id_type: i64, id: PreKeyId) -> crate::error::Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        self.conn().execute(
            "UPDATE pre_key SET stale_timestamp = ?1
             WHERE account_id_type = ?2 AND key_id = ?3",
            rusqlite::params![now, account_id_type, id.0 as i64],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signal_rs_protocol::stores::PreKeyStore;

    #[test]
    fn save_load_remove_pre_key() {
        let db = Database::open_in_memory().unwrap();
        let id = PreKeyId(1);
        let record = PreKeyRecord {
            id,
            public_key: vec![0x05; 33],
            private_key: vec![0xAA; 32],
        };

        db.save_pre_key(id, &record).unwrap();
        let loaded = db.get_pre_key(id).unwrap();
        assert_eq!(loaded.public_key, record.public_key);
        assert_eq!(loaded.private_key, record.private_key);

        db.remove_pre_key(id).unwrap();
        assert!(db.get_pre_key(id).is_err());
    }
}
