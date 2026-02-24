//! Sender key store implementation.
//!
//! Implements [`signal_rs_protocol::SenderKeyStore`] for [`Database`].

use signal_rs_protocol::{ProtocolAddress, ProtocolError, SenderKeyRecord};
use tracing::debug;
use uuid::Uuid;

use crate::database::Database;

impl signal_rs_protocol::stores::SenderKeyStore for Database {
    fn store_sender_key(
        &self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), ProtocolError> {
        let address_str = sender.service_id.to_string();
        let device_id = sender.device_id.0 as i64;
        let dist_id_bytes = distribution_id.as_bytes().to_vec();
        debug!(
            address = %address_str,
            device_id,
            distribution_id = %distribution_id,
            "storing sender key"
        );

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        self.conn()
            .execute(
                "INSERT INTO sender_key (address, device_id, distribution_id, record, created_timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(address, device_id, distribution_id) DO UPDATE SET
                     record = excluded.record,
                     created_timestamp = excluded.created_timestamp",
                rusqlite::params![address_str, device_id, dist_id_bytes, record.serialize(), now],
            )
            .map_err(|e| {
                ProtocolError::StorageError(format!("failed to store sender key: {e}"))
            })?;
        Ok(())
    }

    fn load_sender_key(
        &self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, ProtocolError> {
        let address_str = sender.service_id.to_string();
        let device_id = sender.device_id.0 as i64;
        let dist_id_bytes = distribution_id.as_bytes().to_vec();
        debug!(
            address = %address_str,
            device_id,
            distribution_id = %distribution_id,
            "loading sender key"
        );

        let result: Option<Vec<u8>> = self
            .conn()
            .query_row(
                "SELECT record FROM sender_key
                 WHERE address = ?1 AND device_id = ?2 AND distribution_id = ?3",
                rusqlite::params![address_str, device_id, dist_id_bytes],
                |row| row.get(0),
            )
            .ok();

        Ok(result.map(SenderKeyRecord::from_bytes))
    }
}

impl Database {
    /// Record that a sender key has been shared with a recipient.
    pub fn mark_sender_key_shared(
        &self,
        address: &str,
        device_id: u32,
        distribution_id: &Uuid,
    ) -> crate::error::Result<()> {
        let dist_id_bytes = distribution_id.as_bytes().to_vec();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        debug!(address, device_id, %distribution_id, "marking sender key as shared");

        self.conn().execute(
            "INSERT INTO sender_key_shared (address, device_id, distribution_id, timestamp)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(address, device_id, distribution_id) DO UPDATE SET
                 timestamp = excluded.timestamp",
            rusqlite::params![address, device_id as i64, dist_id_bytes, now],
        )?;
        Ok(())
    }

    /// Check whether a sender key has been shared with a recipient.
    pub fn is_sender_key_shared(
        &self,
        address: &str,
        device_id: u32,
        distribution_id: &Uuid,
    ) -> crate::error::Result<bool> {
        let dist_id_bytes = distribution_id.as_bytes().to_vec();
        let count: i64 = self
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sender_key_shared
                 WHERE address = ?1 AND device_id = ?2 AND distribution_id = ?3",
                rusqlite::params![address, device_id as i64, dist_id_bytes],
                |row| row.get(0),
            )?;
        Ok(count > 0)
    }

    /// Clear all shared sender key records for a distribution ID.
    pub fn clear_sender_key_shared(&self, distribution_id: &Uuid) -> crate::error::Result<()> {
        let dist_id_bytes = distribution_id.as_bytes().to_vec();
        debug!(%distribution_id, "clearing shared sender keys");
        self.conn().execute(
            "DELETE FROM sender_key_shared WHERE distribution_id = ?1",
            [dist_id_bytes],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signal_rs_protocol::stores::SenderKeyStore;
    use signal_rs_protocol::{DeviceId, ServiceId};

    #[test]
    fn store_and_load_sender_key() {
        let db = Database::open_in_memory().unwrap();
        let uuid = Uuid::new_v4();
        let sender = ProtocolAddress::new(ServiceId::aci(uuid), DeviceId(1));
        let dist_id = Uuid::new_v4();
        let record = SenderKeyRecord::from_bytes(vec![0xAB; 64]);

        // No sender key initially.
        assert!(db.load_sender_key(&sender, dist_id).unwrap().is_none());

        // Store and load.
        db.store_sender_key(&sender, dist_id, &record).unwrap();
        let loaded = db
            .load_sender_key(&sender, dist_id)
            .unwrap()
            .expect("should exist");
        assert_eq!(loaded.serialize(), record.serialize());
    }

    #[test]
    fn sender_key_shared_tracking() {
        let db = Database::open_in_memory().unwrap();
        let dist_id = Uuid::new_v4();
        let address = "test-address";

        assert!(!db.is_sender_key_shared(address, 1, &dist_id).unwrap());

        db.mark_sender_key_shared(address, 1, &dist_id).unwrap();
        assert!(db.is_sender_key_shared(address, 1, &dist_id).unwrap());

        db.clear_sender_key_shared(&dist_id).unwrap();
        assert!(!db.is_sender_key_shared(address, 1, &dist_id).unwrap());
    }
}
