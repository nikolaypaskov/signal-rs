//! Session store implementation.
//!
//! Implements [`signal_rs_protocol::SessionStore`] for [`Database`].

use signal_rs_protocol::{DeviceId, ProtocolAddress, ProtocolError, ServiceId, SessionRecord};
use tracing::debug;

use crate::database::Database;

/// Default account ID type (ACI = 0).
const ACCOUNT_ID_TYPE_ACI: i64 = 0;

impl signal_rs_protocol::stores::SessionStore for Database {
    fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, ProtocolError> {
        let address_str = address.service_id.to_string();
        let device_id = address.device_id.0 as i64;
        debug!(address = %address_str, device_id, "loading session");

        let result: Option<Vec<u8>> = self
            .conn()
            .query_row(
                "SELECT record FROM session
                 WHERE account_id_type = ?1 AND address = ?2 AND device_id = ?3",
                rusqlite::params![ACCOUNT_ID_TYPE_ACI, address_str, device_id],
                |row| row.get(0),
            )
            .ok();

        Ok(result.map(SessionRecord::from_bytes))
    }

    fn store_session(
        &self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), ProtocolError> {
        let address_str = address.service_id.to_string();
        let device_id = address.device_id.0 as i64;
        debug!(address = %address_str, device_id, "storing session");

        self.conn()
            .execute(
                "INSERT INTO session (account_id_type, address, device_id, record)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(account_id_type, address, device_id) DO UPDATE SET
                     record = excluded.record",
                rusqlite::params![ACCOUNT_ID_TYPE_ACI, address_str, device_id, record.serialize_to_vec()],
            )
            .map_err(|e| {
                ProtocolError::StorageError(format!("failed to store session: {e}"))
            })?;
        Ok(())
    }

    fn delete_session(&self, address: &ProtocolAddress) -> Result<(), ProtocolError> {
        let address_str = address.service_id.to_string();
        let device_id = address.device_id.0 as i64;
        debug!(address = %address_str, device_id, "deleting session");

        self.conn()
            .execute(
                "DELETE FROM session
                 WHERE account_id_type = ?1 AND address = ?2 AND device_id = ?3",
                rusqlite::params![ACCOUNT_ID_TYPE_ACI, address_str, device_id],
            )
            .map_err(|e| {
                ProtocolError::StorageError(format!("failed to delete session: {e}"))
            })?;
        Ok(())
    }

    fn get_sub_device_sessions(
        &self,
        service_id: &ServiceId,
    ) -> Result<Vec<DeviceId>, ProtocolError> {
        let address_str = service_id.to_string();
        debug!(address = %address_str, "listing sub-device sessions");

        let mut stmt = self
            .conn()
            .prepare(
                "SELECT device_id FROM session
                 WHERE account_id_type = ?1 AND address = ?2 AND device_id != 1",
            )
            .map_err(|e| {
                ProtocolError::StorageError(format!("failed to prepare sub-device query: {e}"))
            })?;

        let device_ids = stmt
            .query_map(rusqlite::params![ACCOUNT_ID_TYPE_ACI, address_str], |row| {
                let id: i64 = row.get(0)?;
                Ok(DeviceId(id as u32))
            })
            .map_err(|e| {
                ProtocolError::StorageError(format!("failed to query sub-device sessions: {e}"))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| {
                ProtocolError::StorageError(format!("failed to collect sub-device sessions: {e}"))
            })?;

        Ok(device_ids)
    }
}

impl Database {
    /// Delete all sessions for a given address (all device IDs).
    pub fn delete_all_sessions(&self, service_id: &ServiceId) -> crate::error::Result<()> {
        let address_str = service_id.to_string();
        debug!(address = %address_str, "deleting all sessions");
        self.conn().execute(
            "DELETE FROM session WHERE account_id_type = ?1 AND address = ?2",
            rusqlite::params![ACCOUNT_ID_TYPE_ACI, address_str],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signal_rs_protocol::stores::SessionStore;
    use uuid::Uuid;

    #[test]
    fn store_load_delete_session() {
        let db = Database::open_in_memory().unwrap();
        let uuid = Uuid::new_v4();
        let addr = ProtocolAddress::new(ServiceId::aci(uuid), DeviceId(1));
        let record = SessionRecord::from_bytes(vec![0x01, 0x02, 0x03]);

        // No session initially.
        assert!(db.load_session(&addr).unwrap().is_none());

        // Store and load.
        db.store_session(&addr, &record).unwrap();
        let loaded = db.load_session(&addr).unwrap().expect("session should exist");
        assert_eq!(loaded.serialize_to_vec(), record.serialize_to_vec());

        // Delete.
        db.delete_session(&addr).unwrap();
        assert!(db.load_session(&addr).unwrap().is_none());
    }

    #[test]
    fn sub_device_sessions() {
        let db = Database::open_in_memory().unwrap();
        let uuid = Uuid::new_v4();
        let sid = ServiceId::aci(uuid);

        // Store sessions for devices 1, 2, 3.
        for device in [1, 2, 3] {
            let addr = ProtocolAddress::new(sid, DeviceId(device));
            let record = SessionRecord::from_bytes(vec![device as u8]);
            db.store_session(&addr, &record).unwrap();
        }

        // Sub-device sessions should exclude device 1.
        let subs = db.get_sub_device_sessions(&sid).unwrap();
        assert_eq!(subs.len(), 2);
        assert!(subs.contains(&DeviceId(2)));
        assert!(subs.contains(&DeviceId(3)));
    }
}
