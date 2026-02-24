//! Signed pre-key store implementation.
//!
//! Implements [`signal_rs_protocol::SignedPreKeyStore`] for [`Database`].

use signal_rs_protocol::{ProtocolError, SignedPreKeyId, SignedPreKeyRecord};
use tracing::debug;

use crate::database::Database;

/// Default account ID type (ACI = 0).
const ACCOUNT_ID_TYPE_ACI: i64 = 0;

impl signal_rs_protocol::stores::SignedPreKeyStore for Database {
    fn get_signed_pre_key(
        &self,
        id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, ProtocolError> {
        debug!(key_id = id.0, "loading signed pre-key");
        let (public_key, private_key, signature, timestamp): (Vec<u8>, Vec<u8>, Vec<u8>, i64) =
            self.conn()
                .query_row(
                    "SELECT public_key, private_key, signature, timestamp FROM signed_pre_key
                     WHERE account_id_type = ?1 AND key_id = ?2",
                    rusqlite::params![ACCOUNT_ID_TYPE_ACI, id.0 as i64],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .map_err(|e| {
                    ProtocolError::StorageError(format!(
                        "failed to load signed pre-key {id}: {e}"
                    ))
                })?;

        Ok(SignedPreKeyRecord {
            id,
            public_key,
            private_key,
            signature,
            timestamp: timestamp as u64,
        })
    }

    fn save_signed_pre_key(
        &self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), ProtocolError> {
        debug!(key_id = id.0, "saving signed pre-key");
        self.conn()
            .execute(
                "INSERT INTO signed_pre_key (account_id_type, key_id, public_key, private_key, signature, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(account_id_type, key_id) DO UPDATE SET
                     public_key = excluded.public_key,
                     private_key = excluded.private_key,
                     signature = excluded.signature,
                     timestamp = excluded.timestamp",
                rusqlite::params![
                    ACCOUNT_ID_TYPE_ACI,
                    id.0 as i64,
                    record.public_key,
                    record.private_key,
                    record.signature,
                    record.timestamp as i64,
                ],
            )
            .map_err(|e| {
                ProtocolError::StorageError(format!(
                    "failed to save signed pre-key {id}: {e}"
                ))
            })?;
        Ok(())
    }
}

impl Database {
    /// Save a signed pre-key with a specific account ID type.
    pub fn save_signed_pre_key_for_account(
        &self,
        account_id_type: i64,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> crate::error::Result<()> {
        debug!(account_id_type, key_id = id.0, "saving signed pre-key for account type");
        self.conn().execute(
            "INSERT INTO signed_pre_key (account_id_type, key_id, public_key, private_key, signature, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(account_id_type, key_id) DO UPDATE SET
                 public_key = excluded.public_key,
                 private_key = excluded.private_key,
                 signature = excluded.signature,
                 timestamp = excluded.timestamp",
            rusqlite::params![
                account_id_type,
                id.0 as i64,
                record.public_key,
                record.private_key,
                record.signature,
                record.timestamp as i64,
            ],
        )?;
        Ok(())
    }

    /// Mark a signed pre-key as stale.
    pub fn mark_signed_pre_key_stale(
        &self,
        account_id_type: i64,
        id: SignedPreKeyId,
    ) -> crate::error::Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        self.conn().execute(
            "UPDATE signed_pre_key SET stale_timestamp = ?1
             WHERE account_id_type = ?2 AND key_id = ?3",
            rusqlite::params![now, account_id_type, id.0 as i64],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signal_rs_protocol::stores::SignedPreKeyStore;

    #[test]
    fn save_and_load_signed_pre_key() {
        let db = Database::open_in_memory().unwrap();
        let id = SignedPreKeyId(10);
        let record = SignedPreKeyRecord {
            id,
            public_key: vec![0x05; 33],
            private_key: vec![0xBB; 32],
            signature: vec![0xCC; 64],
            timestamp: 1234567890,
        };

        db.save_signed_pre_key(id, &record).unwrap();
        let loaded = db.get_signed_pre_key(id).unwrap();
        assert_eq!(loaded.public_key, record.public_key);
        assert_eq!(loaded.private_key, record.private_key);
        assert_eq!(loaded.signature, record.signature);
        assert_eq!(loaded.timestamp, record.timestamp);
    }
}
