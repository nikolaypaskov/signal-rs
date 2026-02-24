//! Sync helper -- multi-device synchronization.
//!
//! Responsible for:
//! - Requesting sync data from the primary device
//! - Handling incoming sync messages (contacts, groups, blocked list, etc.)
//! - Sending sync receipts to other devices

use prost::Message as ProstMessage;
use tracing::{debug, info, warn};

use signal_rs_protocol::stores::{IdentityKeyStore, KyberPreKeyStore, PreKeyStore, SenderKeyStore, SessionStore, SignedPreKeyStore};
use signal_rs_protocol::{DeviceId, ProtocolAddress, ServiceId};
use signal_rs_service::content::{
    SignalContent, SyncContent, SyncKind,
};
use signal_rs_service::pipe::sender::MessageSender;
use signal_rs_store::Database;
use signal_rs_store::database::account_keys;

use crate::error::{ManagerError, Result};

/// Helper for multi-device sync operations.
#[derive(Default)]
pub struct SyncHelper;

impl SyncHelper {
    /// Create a new sync helper.
    pub fn new() -> Self {
        Self
    }

    /// Request all sync data from the primary device.
    ///
    /// Sends request messages for contacts, groups, configuration, blocked list, etc.
    /// This is typically called by a newly linked device to populate its local state.
    pub async fn request_all_data<S: SessionStore + IdentityKeyStore + SenderKeyStore + SignedPreKeyStore + PreKeyStore + KyberPreKeyStore + Send + Sync>(
        &self,
        db: &Database,
        sender: &MessageSender<S>,
    ) -> Result<()> {
        debug!("requesting all sync data from primary device");

        let self_address = get_self_address(db)?;

        // Send sync requests for each data type.
        // Each request is a SyncMessage.Request with a specific type.
        let request_types = [
            "CONTACTS",
            "GROUPS",
            "CONFIGURATION",
            "BLOCKED",
            "KEYS",
        ];

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        for request_type in &request_types {
            let content = SignalContent::Sync(SyncContent {
                kind: SyncKind::Request {
                    request_type: request_type.to_string(),
                },
            });

            match sender.send_message(&self_address, &content, timestamp, None).await {
                Ok(result) => {
                    debug!(request_type, success = result.success, "sync request sent");
                }
                Err(e) => {
                    debug!(request_type, error = %e, "failed to send sync request");
                }
            }
        }

        info!("sync requests sent for all data types");
        Ok(())
    }

    /// Send a read receipt sync message.
    ///
    /// Notifies other linked devices that messages have been read on this device.
    /// Each entry is a `(sender_service_id, message_timestamp)` pair identifying
    /// the message that was read.
    pub async fn send_read_sync<S: SessionStore + IdentityKeyStore + SenderKeyStore + SignedPreKeyStore + PreKeyStore + KyberPreKeyStore + Send + Sync>(
        &self,
        db: &Database,
        sender: &MessageSender<S>,
        entries: &[(ServiceId, u64)],
    ) -> Result<()> {
        debug!(count = entries.len(), "sending read sync");

        if entries.is_empty() {
            return Ok(());
        }

        let self_address = get_self_address(db)?;

        let content = SignalContent::Sync(SyncContent {
            kind: SyncKind::ReadReceipts { entries: entries.to_vec() },
        });

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        match sender.send_message(&self_address, &content, timestamp, None).await {
            Ok(result) => {
                debug!(success = result.success, "read sync sent");
            }
            Err(e) => {
                debug!(error = %e, "failed to send read sync");
            }
        }

        info!(count = entries.len(), "read sync sent");
        Ok(())
    }

    /// Send a viewed receipt sync message.
    ///
    /// Notifies other linked devices that view-once messages have been viewed.
    /// Each entry is a `(sender_service_id, message_timestamp)` pair identifying
    /// the message that was viewed.
    pub async fn send_viewed_sync<S: SessionStore + IdentityKeyStore + SenderKeyStore + SignedPreKeyStore + PreKeyStore + KyberPreKeyStore + Send + Sync>(
        &self,
        db: &Database,
        sender: &MessageSender<S>,
        entries: &[(ServiceId, u64)],
    ) -> Result<()> {
        debug!(count = entries.len(), "sending viewed sync");

        if entries.is_empty() {
            return Ok(());
        }

        let self_address = get_self_address(db)?;

        let content = SignalContent::Sync(SyncContent {
            kind: SyncKind::ViewedReceipts { entries: entries.to_vec() },
        });

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        match sender.send_message(&self_address, &content, timestamp, None).await {
            Ok(result) => {
                debug!(success = result.success, "viewed sync sent");
            }
            Err(e) => {
                debug!(error = %e, "failed to send viewed sync");
            }
        }

        info!(count = entries.len(), "viewed sync sent");
        Ok(())
    }

    /// Send a sent-message transcript to other linked devices.
    ///
    /// When this device sends a message, it should also send a sync transcript
    /// so other linked devices know about it.
    pub async fn send_sent_transcript<S: SessionStore + IdentityKeyStore + SenderKeyStore + SignedPreKeyStore + PreKeyStore + KyberPreKeyStore + Send + Sync>(
        &self,
        db: &Database,
        sender: &MessageSender<S>,
        destination: Option<ServiceId>,
        timestamp: u64,
        content: Option<Box<signal_rs_service::content::DataContent>>,
    ) -> Result<()> {
        debug!(
            ?destination,
            timestamp,
            "sending sent transcript sync"
        );

        let self_address = get_self_address(db)?;

        let sync_content = SignalContent::Sync(SyncContent {
            kind: SyncKind::SentTranscript {
                destination,
                timestamp,
                content,
            },
        });

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        match sender.send_message(&self_address, &sync_content, now, None).await {
            Ok(result) => {
                debug!(success = result.success, "sent transcript sync sent");
            }
            Err(e) => {
                debug!(error = %e, "failed to send sent transcript sync");
            }
        }

        info!(timestamp, "sent transcript sync sent");
        Ok(())
    }

    /// Send a keys sync message (triggers pre-key upload on the primary device).
    pub async fn send_keys_sync<S: SessionStore + IdentityKeyStore + SenderKeyStore + SignedPreKeyStore + PreKeyStore + KyberPreKeyStore + Send + Sync>(
        &self,
        db: &Database,
        sender: &MessageSender<S>,
    ) -> Result<()> {
        debug!("sending keys sync request");

        let self_address = get_self_address(db)?;

        let content = SignalContent::Sync(SyncContent {
            kind: SyncKind::Keys,
        });

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        match sender.send_message(&self_address, &content, timestamp, None).await {
            Ok(result) => {
                debug!(success = result.success, "keys sync sent");
            }
            Err(e) => {
                debug!(error = %e, "failed to send keys sync");
            }
        }

        info!("keys sync request sent");
        Ok(())
    }

    /// Send a blocked list sync message after blocking or unblocking a contact/group.
    ///
    /// Notifies other linked devices about the updated blocked list so they
    /// can stay in sync.
    pub async fn send_blocked_list_sync<S: SessionStore + IdentityKeyStore + SenderKeyStore + SignedPreKeyStore + PreKeyStore + KyberPreKeyStore + Send + Sync>(
        &self,
        db: &Database,
        sender: &MessageSender<S>,
    ) -> Result<()> {
        debug!("sending blocked list sync");

        let self_address = get_self_address(db)?;

        let content = SignalContent::Sync(SyncContent {
            kind: SyncKind::Blocked,
        });

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        match sender.send_message(&self_address, &content, timestamp, None).await {
            Ok(result) => {
                debug!(success = result.success, "blocked list sync sent");
            }
            Err(e) => {
                // Sync failures are non-fatal
                debug!(error = %e, "failed to send blocked list sync");
            }
        }

        info!("blocked list sync sent");
        Ok(())
    }

    /// Send a contacts sync message after a trust/identity change.
    ///
    /// When the user trusts or untrusts an identity, other linked devices
    /// need to be notified so they reflect the updated trust state.
    pub async fn send_contacts_sync<S: SessionStore + IdentityKeyStore + SenderKeyStore + SignedPreKeyStore + PreKeyStore + KyberPreKeyStore + Send + Sync>(
        &self,
        db: &Database,
        sender: &MessageSender<S>,
    ) -> Result<()> {
        debug!("sending contacts sync after trust change");

        let self_address = get_self_address(db)?;

        let content = SignalContent::Sync(SyncContent {
            kind: SyncKind::Contacts,
        });

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        match sender.send_message(&self_address, &content, timestamp, None).await {
            Ok(result) => {
                debug!(success = result.success, "contacts sync sent");
            }
            Err(e) => {
                debug!(error = %e, "failed to send contacts sync");
            }
        }

        info!("contacts sync sent after trust change");
        Ok(())
    }

    /// Process incoming contacts sync data.
    ///
    /// Parses a stream of length-delimited `ContactDetails` protobuf records
    /// from the given raw bytes and upserts each contact into the recipient
    /// store. The blob is typically downloaded from the CDN after receiving a
    /// `SyncMessage.Contacts` attachment pointer.
    pub fn process_contacts_sync(
        &self,
        db: &Database,
        data: &[u8],
    ) -> Result<()> {
        debug!(data_len = data.len(), "processing contacts sync blob");

        let mut cursor = std::io::Cursor::new(data);
        let mut count: usize = 0;

        while (cursor.position() as usize) < data.len() {
            // Each record is length-delimited (varint length prefix + protobuf bytes).
            let contact = match prost::decode_length_delimiter(&mut cursor) {
                Ok(len) => {
                    let pos = cursor.position() as usize;
                    if pos + len > data.len() {
                        warn!("contacts sync: truncated record at offset {pos}");
                        break;
                    }
                    let record_bytes = &data[pos..pos + len];
                    cursor.set_position((pos + len) as u64);
                    match signal_rs_protos::ContactDetails::decode(record_bytes) {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(error = %e, "contacts sync: failed to decode ContactDetails");
                            continue;
                        }
                    }
                }
                Err(_) => break, // no more records
            };

            // Extract ACI -- skip contacts without one
            let aci = match contact.aci.as_deref() {
                Some(a) if !a.is_empty() => a,
                _ => {
                    debug!(number = ?contact.number, "skipping contact without ACI");
                    continue;
                }
            };

            let number = contact.number.as_deref();
            let given_name = contact.name.as_deref();
            let profile_key = contact.profile_key.as_deref();
            let archived = contact.archived.unwrap_or(false);

            if let Err(e) = db.upsert_recipient_from_sync(
                aci,
                None,  // storage_id
                None,  // storage_record
                number,
                None,  // pni
                None,  // username
                profile_key,
                given_name,
                None,  // family_name (ContactDetails only has a single `name`)
                false, // blocked (reserved in ContactDetails proto)
                archived,
                false, // profile_sharing
                false, // hide_story
                false, // hidden
                0,     // mute_until
                None,  // unregistered_timestamp
                None,  // nick_name_given_name
                None,  // nick_name_family_name
                None,  // note
            ) {
                warn!(aci, error = %e, "failed to upsert contact from sync");
            } else {
                count += 1;
            }
        }

        info!(count, "contacts sync processed");
        Ok(())
    }

    /// Send a fetch-latest sync message.
    ///
    /// Requests other devices to send updated data.
    pub async fn send_fetch_latest<S: SessionStore + IdentityKeyStore + SenderKeyStore + SignedPreKeyStore + PreKeyStore + KyberPreKeyStore + Send + Sync>(
        &self,
        db: &Database,
        sender: &MessageSender<S>,
    ) -> Result<()> {
        debug!("sending fetch latest sync request");

        let self_address = get_self_address(db)?;

        let content = SignalContent::Sync(SyncContent {
            kind: SyncKind::FetchLatest,
        });

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        match sender.send_message(&self_address, &content, timestamp, None).await {
            Ok(result) => {
                debug!(success = result.success, "fetch latest sync sent");
            }
            Err(e) => {
                debug!(error = %e, "failed to send fetch latest sync");
            }
        }

        info!("fetch latest sync request sent");
        Ok(())
    }
}

/// Get the self address (our own ACI + device ID) from the store.
fn get_self_address(db: &Database) -> Result<ProtocolAddress> {
    let aci_str = db.get_kv_string(account_keys::ACI_UUID)?
        .ok_or_else(|| ManagerError::NotRegistered)?;

    let uuid = uuid::Uuid::parse_str(&aci_str)
        .map_err(|e| ManagerError::Other(format!("invalid ACI UUID: {e}")))?;

    let device_id = db.get_kv_string(account_keys::DEVICE_ID)?
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(1);

    Ok(ProtocolAddress::new(
        ServiceId::aci(uuid),
        DeviceId(device_id),
    ))
}
