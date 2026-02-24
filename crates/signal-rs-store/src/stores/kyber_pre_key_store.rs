//! Kyber pre-key store implementation.
//!
//! Implements [`signal_rs_protocol::KyberPreKeyStore`] for [`Database`].

use signal_rs_protocol::{KyberPreKeyId, KyberPreKeyRecord, ProtocolError};
use tracing::debug;

use crate::database::Database;

/// Default account ID type (ACI = 0).
const ACCOUNT_ID_TYPE_ACI: i64 = 0;

impl signal_rs_protocol::stores::KyberPreKeyStore for Database {
    fn get_kyber_pre_key(
        &self,
        id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, ProtocolError> {
        debug!(key_id = id.0, "loading kyber pre-key");
        let (serialized, is_last_resort, timestamp): (Vec<u8>, i64, i64) = self
            .conn()
            .query_row(
                "SELECT serialized, is_last_resort, timestamp FROM kyber_pre_key
                 WHERE account_id_type = ?1 AND key_id = ?2",
                rusqlite::params![ACCOUNT_ID_TYPE_ACI, id.0 as i64],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|e| {
                ProtocolError::StorageError(format!(
                    "failed to load kyber pre-key {id}: {e}"
                ))
            })?;

        Ok(KyberPreKeyRecord {
            id,
            key_pair_serialized: serialized,
            // The signature is embedded in the serialized data for Kyber keys.
            signature: Vec::new(),
            timestamp: timestamp as u64,
            is_last_resort: is_last_resort != 0,
        })
    }

    fn save_kyber_pre_key(
        &self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), ProtocolError> {
        debug!(key_id = id.0, is_last_resort = record.is_last_resort, "saving kyber pre-key");
        self.conn()
            .execute(
                "INSERT INTO kyber_pre_key (account_id_type, key_id, serialized, is_last_resort, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(account_id_type, key_id) DO UPDATE SET
                     serialized = excluded.serialized,
                     is_last_resort = excluded.is_last_resort,
                     timestamp = excluded.timestamp",
                rusqlite::params![
                    ACCOUNT_ID_TYPE_ACI,
                    id.0 as i64,
                    record.key_pair_serialized,
                    record.is_last_resort as i64,
                    record.timestamp as i64,
                ],
            )
            .map_err(|e| {
                ProtocolError::StorageError(format!(
                    "failed to save kyber pre-key {id}: {e}"
                ))
            })?;
        Ok(())
    }

    fn mark_kyber_pre_key_used(&self, id: KyberPreKeyId) -> Result<(), ProtocolError> {
        debug!(key_id = id.0, "marking kyber pre-key as used");

        // Check if this is a last-resort key. If not, delete it.
        let is_last_resort: Option<i64> = self
            .conn()
            .query_row(
                "SELECT is_last_resort FROM kyber_pre_key
                 WHERE account_id_type = ?1 AND key_id = ?2",
                rusqlite::params![ACCOUNT_ID_TYPE_ACI, id.0 as i64],
                |row| row.get(0),
            )
            .ok();

        match is_last_resort {
            Some(1) => {
                // Last-resort keys are kept; just mark a stale timestamp.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;
                self.conn()
                    .execute(
                        "UPDATE kyber_pre_key SET stale_timestamp = ?1
                         WHERE account_id_type = ?2 AND key_id = ?3",
                        rusqlite::params![now, ACCOUNT_ID_TYPE_ACI, id.0 as i64],
                    )
                    .map_err(|e| {
                        ProtocolError::StorageError(format!(
                            "failed to mark kyber pre-key {id} as stale: {e}"
                        ))
                    })?;
            }
            _ => {
                // Non-last-resort keys are deleted after use.
                self.conn()
                    .execute(
                        "DELETE FROM kyber_pre_key
                         WHERE account_id_type = ?1 AND key_id = ?2",
                        rusqlite::params![ACCOUNT_ID_TYPE_ACI, id.0 as i64],
                    )
                    .map_err(|e| {
                        ProtocolError::StorageError(format!(
                            "failed to delete kyber pre-key {id}: {e}"
                        ))
                    })?;
            }
        }

        Ok(())
    }
}

impl Database {
    /// Save a Kyber pre-key with a specific account ID type.
    pub fn save_kyber_pre_key_for_account(
        &self,
        account_id_type: i64,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> crate::error::Result<()> {
        debug!(account_id_type, key_id = id.0, "saving kyber pre-key for account type");
        self.conn().execute(
            "INSERT INTO kyber_pre_key (account_id_type, key_id, serialized, is_last_resort, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(account_id_type, key_id) DO UPDATE SET
                 serialized = excluded.serialized,
                 is_last_resort = excluded.is_last_resort,
                 timestamp = excluded.timestamp",
            rusqlite::params![
                account_id_type,
                id.0 as i64,
                record.key_pair_serialized,
                record.is_last_resort as i64,
                record.timestamp as i64,
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signal_rs_protocol::stores::KyberPreKeyStore;

    #[test]
    fn save_load_and_use_kyber_pre_key() {
        let db = Database::open_in_memory().unwrap();
        let id = KyberPreKeyId(100);
        let record = KyberPreKeyRecord {
            id,
            key_pair_serialized: vec![0xDD; 128],
            signature: Vec::new(),
            timestamp: 9999,
            is_last_resort: false,
        };

        db.save_kyber_pre_key(id, &record).unwrap();
        let loaded = db.get_kyber_pre_key(id).unwrap();
        assert_eq!(loaded.key_pair_serialized, record.key_pair_serialized);

        // Mark as used: non-last-resort should delete it.
        db.mark_kyber_pre_key_used(id).unwrap();
        assert!(db.get_kyber_pre_key(id).is_err());
    }

    #[test]
    fn last_resort_key_survives_use() {
        let db = Database::open_in_memory().unwrap();
        let id = KyberPreKeyId(200);
        let record = KyberPreKeyRecord {
            id,
            key_pair_serialized: vec![0xEE; 128],
            signature: Vec::new(),
            timestamp: 1111,
            is_last_resort: true,
        };

        db.save_kyber_pre_key(id, &record).unwrap();
        db.mark_kyber_pre_key_used(id).unwrap();
        // Last-resort key should still be loadable.
        let loaded = db.get_kyber_pre_key(id).unwrap();
        assert!(loaded.is_last_resort);
    }
}
