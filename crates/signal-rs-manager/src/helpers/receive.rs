//! Receive helper -- handles incoming message processing.
//!
//! Responsible for:
//! - Processing decrypted envelopes into application-level messages
//! - Dispatching sync messages
//! - Handling receipt messages
//! - Triggering jobs (pre-key refresh, profile download, etc.)

use prost::Message as ProstMessage;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use uuid::Uuid;

use signal_rs_protocol::sealed_sender;
use signal_rs_protocol::stores::IdentityKeyStore;
use signal_rs_store::Database;
use signal_rs_store::models::message::MessageType;

use crate::error::Result;
use crate::types::{Message, QuoteRef};

/// A delivery receipt that should be sent back to the message sender.
///
/// After processing an incoming data message, the receiver should send
/// a delivery receipt to acknowledge that the message was received.
/// The manager is responsible for actually sending this via the MessageSender.
#[derive(Debug, Clone)]
pub struct PendingDeliveryReceipt {
    /// The sender's UUID (who we need to send the receipt to).
    pub sender_uuid: Uuid,
    /// The timestamp of the received message.
    pub message_timestamp: u64,
}

/// Serializable attachment metadata stored as JSON on message records.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttachmentMeta {
    content_type: Option<String>,
    file_name: Option<String>,
    size: Option<u32>,
    cdn_id: Option<String>,
    cdn_key: Option<String>,
    width: Option<u32>,
    height: Option<u32>,
}

/// Helper for receiving and processing messages.
#[derive(Default)]
pub struct ReceiveHelper;

impl ReceiveHelper {
    /// Create a new receive helper.
    pub fn new() -> Self {
        Self
    }

    /// Process a batch of incoming messages from the WebSocket pipe.
    ///
    /// Takes raw envelope bytes, decrypts them, and converts them into
    /// application-level Message structs. Also stores received messages
    /// in the local database.
    ///
    /// For sealed-sender envelopes (type 6), the local identity key pair
    /// is loaded from the database to perform the unseal operation.
    pub async fn process_incoming(
        &self,
        db: &Database,
        envelopes: &[Vec<u8>],
    ) -> Result<Vec<Message>> {
        let (messages, _receipts) = self.process_incoming_with_receipts(db, envelopes).await?;
        Ok(messages)
    }

    /// Process a batch of incoming messages and collect delivery receipts.
    ///
    /// Like [`process_incoming`], but also returns a list of
    /// `PendingDeliveryReceipt` entries. The caller should send each
    /// delivery receipt back to the message sender.
    pub async fn process_incoming_with_receipts(
        &self,
        db: &Database,
        envelopes: &[Vec<u8>],
    ) -> Result<(Vec<Message>, Vec<PendingDeliveryReceipt>)> {
        debug!(count = envelopes.len(), "processing incoming envelopes");

        let mut messages = Vec::new();
        let mut receipts = Vec::new();

        for envelope_bytes in envelopes {
            match self.process_single_envelope(db, envelope_bytes).await {
                Ok(Some((msg, receipt))) => {
                    messages.push(msg);
                    if let Some(r) = receipt {
                        receipts.push(r);
                    }
                }
                Ok(None) => {
                    // Non-message envelope (receipt, typing, etc.)
                    debug!("envelope processed (no message produced)");
                }
                Err(e) => {
                    warn!(error = %e, "failed to process envelope");
                }
            }
        }

        info!(
            processed = envelopes.len(),
            messages = messages.len(),
            delivery_receipts = receipts.len(),
            "incoming batch processed"
        );
        Ok((messages, receipts))
    }

    /// Process a single envelope and optionally return a Message and a delivery receipt.
    ///
    /// Deserializes the protobuf Envelope, decrypts the content, parses
    /// the Content protobuf, and routes to the appropriate handler.
    async fn process_single_envelope(
        &self,
        db: &Database,
        envelope_bytes: &[u8],
    ) -> Result<Option<(Message, Option<PendingDeliveryReceipt>)>> {
        // Step 1: Deserialize the Envelope protobuf
        let envelope = signal_rs_protos::Envelope::decode(envelope_bytes)
            .map_err(|e| {
                crate::error::ManagerError::Other(format!(
                    "failed to decode Envelope protobuf: {e}"
                ))
            })?;

        let envelope_type = envelope.r#type.unwrap_or(0);
        let timestamp = envelope.timestamp.unwrap_or(0);

        // Receipt envelopes (type 5) don't carry content
        if envelope_type == 5 {
            debug!("receipt envelope, no content to process");
            return Ok(None);
        }

        // Step 2: Handle sealed sender envelopes (type 6 = UNIDENTIFIED_SENDER).
        // For sealed sender, the content field contains the sealed ciphertext
        // which wraps sender info + the real Content protobuf.
        let (source_uuid_str, content_bytes) = if envelope_type == 6 {
            let sealed_data = match envelope.content {
                Some(ref c) => c.clone(),
                None => {
                    warn!("sealed sender envelope has no content");
                    return Ok(None);
                }
            };

            let identity = match db.get_identity_key_pair() {
                Ok(id) => id,
                Err(e) => {
                    warn!(error = %e, "sealed sender envelope received but failed to load identity key");
                    return Ok(None);
                }
            };

            match sealed_sender::unseal(&sealed_data, &identity, timestamp) {
                Ok(unsealed) => {
                    let sender_uuid = unsealed.sender_uuid.to_string();
                    info!(
                        sender = %sender_uuid,
                        device = unsealed.sender_device_id.value(),
                        msg_type = unsealed.msg_type,
                        timestamp,
                        "unsealed sealed sender envelope"
                    );
                    // Note: unsealed.content is still encrypted (inner Signal message).
                    // In the normal flow, the manager's decrypt_envelope() handles type 6
                    // before passing to the receive helper, so this path is only reached
                    // if process_single_envelope is called directly with raw envelopes.
                    (sender_uuid, unsealed.content)
                }
                Err(e) => {
                    warn!(error = %e, "failed to unseal sealed sender envelope");
                    return Err(crate::error::ManagerError::Protocol(e));
                }
            }
        } else {
            // Normal envelope: source_service_id is in the envelope header
            let source = envelope.source_service_id.as_deref().unwrap_or_default().to_string();
            let content = match envelope.content {
                Some(ref c) => c.clone(),
                None => return Ok(None),
            };
            (source, content)
        };

        debug!(
            source = %source_uuid_str,
            envelope_type,
            timestamp,
            "processing envelope in receive helper"
        );

        // Step 2.5: Check if the sender is blocked
        if !source_uuid_str.is_empty()
            && let Ok(Some(sender_recipient)) = db.get_recipient_by_aci(&source_uuid_str)
                && sender_recipient.blocked {
                    debug!(
                        source = %source_uuid_str,
                        "dropping message from blocked sender"
                    );
                    return Ok(None);
                }

        // Step 3: Strip content padding and parse the Content protobuf
        let unpadded = signal_rs_service::content::strip_content_padding(content_bytes.as_slice());
        let content = signal_rs_protos::Content::decode(unpadded)
            .map_err(|e| {
                crate::error::ManagerError::Other(format!(
                    "failed to decode Content protobuf: {e}"
                ))
            })?;

        // Step 4: Route to the appropriate handler based on Content fields

        // Handle EditMessage (content.edit_message) before data_message
        if let Some(ref edit_message) = content.edit_message {
            let target_ts = edit_message.target_sent_timestamp.unwrap_or(0);
            if target_ts > 0
                && let Some(ref new_dm) = edit_message.data_message
                && let Some(ref new_body) = new_dm.body
            {
                let sender_uuid = Uuid::parse_str(&source_uuid_str).unwrap_or(Uuid::nil());
                debug!(%sender_uuid, target_ts, "handling edit message");

                // Look up the sender recipient to find the original message
                if let Ok(sender) = db.get_or_create_recipient(&sender_uuid.to_string()) {
                    if let Ok(Some(original)) = db.get_message_by_timestamp_and_sender(target_ts as i64, sender.id) {
                        if let Err(e) = db.update_message_body(original.id, new_body) {
                            warn!(error = %e, "failed to update message body for edit");
                        } else {
                            info!(msg_id = original.id, target_ts, "message edited");
                        }
                    } else {
                        debug!(target_ts, "edit target message not found");
                    }
                }
            }
            return Ok(None);
        }

        if let Some(ref data_message) = content.data_message {
            // Check if the group is blocked (for group messages)
            if let Some(ref gv2) = data_message.group_v2
                && let Some(ref master_key_bytes) = gv2.master_key
                    && let Ok(mk) = signal_rs_service::groups::GroupMasterKey::from_bytes(master_key_bytes) {
                        let group_id = mk.derive_group_id();
                        if let Ok(Some(group)) = db.get_group_by_group_id(&group_id)
                            && group.blocked {
                                debug!(
                                    "dropping message from blocked group"
                                );
                                return Ok(None);
                            }
                    }

            let sender_uuid = Uuid::parse_str(&source_uuid_str).unwrap_or(Uuid::nil());

            // Compute expires_at if the message has a disappearing timer
            let expire_timer = data_message.expire_timer.unwrap_or(0);
            let expires_at = if expire_timer > 0 {
                let now_millis = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;
                Some(now_millis + (expire_timer as i64) * 1000)
            } else {
                None
            };

            let msg = self
                .handle_data_message(db, &sender_uuid, timestamp, data_message, expires_at)
                .await?;
            if let Some(msg) = msg {
                // Build a delivery receipt to send back to the sender
                let receipt = if !sender_uuid.is_nil() {
                    Some(PendingDeliveryReceipt {
                        sender_uuid,
                        message_timestamp: timestamp,
                    })
                } else {
                    None
                };
                return Ok(Some((msg, receipt)));
            }
            return Ok(None);
        }

        if let Some(ref sync_message) = content.sync_message {
            // Handle contacts sync: parse ContactDetails records from the blob
            if let Some(ref contacts) = sync_message.contacts {
                debug!(
                    complete = contacts.complete.unwrap_or(false),
                    "contacts sync message received"
                );
                // The blob field is an AttachmentPointer; in practice the
                // attachment data has already been downloaded and appended
                // to the envelope by the pipe layer.  When no inline data
                // is available we still log that we saw the message.
                if let Some(ref blob) = contacts.blob {
                    // Extract CDN key for logging/future download
                    let cdn_ref: Option<String> = match &blob.attachment_identifier {
                        Some(
                            signal_rs_protos::attachment_pointer::AttachmentIdentifier::CdnKey(k),
                        ) => Some(k.clone()),
                        Some(
                            signal_rs_protos::attachment_pointer::AttachmentIdentifier::CdnId(id),
                        ) => Some(id.to_string()),
                        None => None,
                    };
                    debug!(?cdn_ref, "contacts blob attachment pointer received");
                }
                return Ok(None);
            }

            if let Some(ref sent) = sync_message.sent {
                // Sync transcript: a message we sent from another device
                if let Some(ref dest_uuid_str) = sent.destination_service_id
                    && let Ok(dest_uuid) = Uuid::parse_str(dest_uuid_str) {
                        let ts = sent.timestamp.unwrap_or(timestamp);
                        let body = sent
                            .message
                            .as_ref()
                            .and_then(|dm| dm.body.as_deref());

                        // Compute expires_at for sync transcript
                        let expire_timer = sent
                            .message
                            .as_ref()
                            .and_then(|dm| dm.expire_timer)
                            .unwrap_or(0);
                        let expires_at = if expire_timer > 0 {
                            let now_millis = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as i64;
                            Some(now_millis + (expire_timer as i64) * 1000)
                        } else {
                            None
                        };

                        let msg = self
                            .handle_sync_transcript(db, &dest_uuid, ts, body, expires_at)
                            .await?;
                        // No delivery receipt for sync transcripts (they're our own messages)
                        return Ok(msg.map(|m| (m, None)));
                    }
            }
            debug!("sync message processed (no message produced)");
            return Ok(None);
        }

        // Typing, receipt, call, story messages don't produce stored Messages
        if content.typing_message.is_some() {
            debug!("typing message received");
            return Ok(None);
        }
        if content.receipt_message.is_some() {
            debug!("receipt message received");
            return Ok(None);
        }
        if let Some(ref call_message) = content.call_message {
            debug!("call message received");

            // Persist the call to the call log.
            let peer_aci = source_uuid_str.clone();

            if let Some(ref offer) = call_message.offer {
                let call_id = offer.id.unwrap_or(0).to_string();
                let call_type = match offer.r#type {
                    Some(1) => "VIDEO",
                    _ => "AUDIO",
                };
                if let Err(e) = db.insert_call(
                    &call_id,
                    &peer_aci,
                    call_type,
                    "INCOMING",
                    timestamp as i64,
                    None,
                    "MISSED",
                ) {
                    warn!(error = %e, "failed to insert call offer into call log");
                }
            } else if let Some(ref hangup) = call_message.hangup {
                let call_id = hangup.id.unwrap_or(0).to_string();
                let status = match hangup.r#type {
                    Some(2) => "DECLINED",
                    Some(3) => "BUSY",
                    _ => "ANSWERED",
                };
                // Update existing call entry or insert a new one for the hangup.
                if let Err(e) = db.insert_call(
                    &call_id,
                    &peer_aci,
                    "AUDIO",
                    "INCOMING",
                    timestamp as i64,
                    None,
                    status,
                ) {
                    warn!(error = %e, "failed to insert call hangup into call log");
                }
            } else if let Some(ref busy) = call_message.busy {
                let call_id = busy.id.unwrap_or(0).to_string();
                if let Err(e) = db.insert_call(
                    &call_id,
                    &peer_aci,
                    "AUDIO",
                    "INCOMING",
                    timestamp as i64,
                    None,
                    "BUSY",
                ) {
                    warn!(error = %e, "failed to insert call busy into call log");
                }
            }

            return Ok(None);
        }
        if content.story_message.is_some() {
            debug!("story message received");
            return Ok(None);
        }

        debug!("Content protobuf had no recognized fields");
        Ok(None)
    }

    /// Handle a decrypted data message.
    ///
    /// Processes the full DataMessage, handling sub-types:
    /// - Group messages (group_v2 context)
    /// - Reactions
    /// - Remote deletes
    /// - Attachments (metadata only)
    /// - Quotes (replies)
    /// - Stickers
    /// - Normal text messages
    ///
    /// If `expires_at` is `Some`, the message will be scheduled for deletion.
    pub async fn handle_data_message(
        &self,
        db: &Database,
        sender_uuid: &Uuid,
        timestamp: u64,
        data_message: &signal_rs_protos::DataMessage,
        expires_at: Option<i64>,
    ) -> Result<Option<Message>> {
        debug!(%sender_uuid, timestamp, ?expires_at, "handling data message");

        // --- Skip protocol-level flag messages that aren't real chat content ---
        if data_message.is_end_session() {
            debug!(%sender_uuid, "end-session (session refresh) message, skipping");
            return Ok(None);
        }
        if data_message.is_profile_key_update() {
            debug!(%sender_uuid, "profile key update message, skipping");
            return Ok(None);
        }
        if data_message.is_expiration_update() {
            debug!(%sender_uuid, "expiration timer update message, skipping");
            return Ok(None);
        }

        let body = data_message.body.as_deref();

        // Find or create the sender recipient
        let sender = db.get_or_create_recipient(&sender_uuid.to_string())?;

        // --- Handle reactions ---
        if let Some(ref reaction) = data_message.reaction {
            let emoji = reaction.emoji.as_deref().unwrap_or("");
            let target_author_aci = reaction.target_author_aci.as_deref().unwrap_or("");
            let target_ts = reaction.target_sent_timestamp.unwrap_or(0);
            let remove = reaction.remove.unwrap_or(false);

            debug!(
                emoji,
                target_author_aci,
                target_ts,
                remove,
                "handling reaction"
            );

            // Find the target message by timestamp. We need the target author's recipient
            // to look up the message precisely.
            let target_msg = if !target_author_aci.is_empty() {
                if let Ok(target_sender) = db.get_or_create_recipient(target_author_aci) {
                    db.get_message_by_timestamp_and_sender(target_ts as i64, target_sender.id)
                        .ok()
                        .flatten()
                } else {
                    // Might be our own message (sender_id = None)
                    db.get_message_by_timestamp(target_ts as i64).ok().flatten()
                }
            } else {
                db.get_message_by_timestamp(target_ts as i64).ok().flatten()
            };

            if let Some(target) = target_msg {
                if remove {
                    if let Err(e) = db.remove_reaction(target.id, &sender_uuid.to_string()) {
                        debug!(error = %e, "failed to remove reaction (may not exist)");
                    } else {
                        info!(msg_id = target.id, %sender_uuid, "reaction removed");
                    }
                } else if let Err(e) = db.add_reaction(
                    target.id,
                    &sender_uuid.to_string(),
                    emoji,
                    timestamp as i64,
                ) {
                    warn!(error = %e, "failed to add reaction");
                } else {
                    info!(msg_id = target.id, emoji, %sender_uuid, "reaction added");
                }
            } else {
                debug!(target_ts, "reaction target message not found");
            }

            // Reactions don't produce a stored message themselves
            return Ok(None);
        }

        // --- Handle remote deletes ---
        if let Some(ref delete) = data_message.delete {
            let target_ts = delete.target_sent_timestamp.unwrap_or(0);
            debug!(target_ts, "handling remote delete");

            if target_ts > 0 {
                // Find by timestamp and sender
                if let Ok(Some(target)) =
                    db.get_message_by_timestamp_and_sender(target_ts as i64, sender.id)
                {
                    if let Err(e) = db.mark_message_deleted(target.id) {
                        warn!(error = %e, "failed to mark message as deleted");
                    } else {
                        info!(msg_id = target.id, "message marked as remotely deleted");
                    }
                } else {
                    debug!(target_ts, "delete target message not found");
                }
            }

            return Ok(None);
        }

        // --- Handle stickers ---
        if let Some(ref sticker) = data_message.sticker {
            let pack_id = sticker.pack_id.as_deref().map(hex::encode).unwrap_or_default();
            let sticker_id = sticker.sticker_id.unwrap_or(0);
            let sticker_emoji = sticker.emoji.as_deref().unwrap_or("");
            debug!(pack_id, sticker_id, sticker_emoji, "handling sticker message");

            // Determine the thread (group or 1:1)
            let (thread, group_id_str) = self.resolve_thread(db, sender.id, data_message)?;

            // Compute expires_in
            let expires_in = expires_at.map(|eat| {
                let now_millis = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;
                ((eat - now_millis) / 1000).max(0)
            });

            // Store as a normal message with sticker emoji as the body
            let sticker_body = if sticker_emoji.is_empty() {
                format!("[Sticker pack={} id={}]", pack_id, sticker_id)
            } else {
                sticker_emoji.to_string()
            };

            let msg_id = db.insert_message_with_expiry(
                thread.id,
                Some(sender.id),
                timestamp as i64,
                None,
                Some(&sticker_body),
                MessageType::Normal,
                None,
                expires_in,
                None,
                expires_at,
            )?;

            db.update_thread_on_message(thread.id, timestamp as i64, true)?;

            info!(msg_id, %sender_uuid, "sticker message stored");

            let message = Message {
                text: Some(sticker_body),
                attachments: Vec::new(),
                quote: None,
                reaction: None,
                timestamp,
                sender: Some(sender_uuid.to_string()),
                destination: None,
                group_id: group_id_str,
                is_view_once: false,
            };
            return Ok(Some(message));
        }

        // --- Dedup check for normal/text messages ---
        if let Ok(Some(_existing)) =
            db.get_message_by_timestamp_and_sender(timestamp as i64, sender.id)
        {
            debug!(
                %sender_uuid,
                timestamp,
                "duplicate message detected, skipping storage"
            );
            return Ok(None);
        }

        // --- Resolve thread (group or 1:1) ---
        let (thread, group_id_str) = self.resolve_thread(db, sender.id, data_message)?;

        // --- Extract quote info ---
        let (quote_id, quote_ref) = if let Some(ref quote) = data_message.quote {
            let quote_timestamp = quote.id.unwrap_or(0);
            let quote_author = quote.author_aci.as_deref().unwrap_or("").to_string();
            let quote_text = quote.text.clone();

            // Try to find the quoted message in our DB to get its internal ID
            let db_quote_id = if quote_timestamp > 0 && !quote_author.is_empty() {
                if let Ok(author_recipient) = db.get_or_create_recipient(&quote_author) {
                    db.get_message_by_timestamp_and_sender(
                        quote_timestamp as i64,
                        author_recipient.id,
                    )
                    .ok()
                    .flatten()
                    .map(|m| m.id)
                } else {
                    None
                }
            } else {
                None
            };

            let qref = QuoteRef {
                id: quote_timestamp,
                author: quote_author,
                text: quote_text,
            };

            (db_quote_id, Some(qref))
        } else {
            (None, None)
        };

        // --- Extract attachment metadata ---
        let attachments_json = if !data_message.attachments.is_empty() {
            let metas: Vec<AttachmentMeta> = data_message
                .attachments
                .iter()
                .map(|att| {
                    let (cdn_id, cdn_key) = match &att.attachment_identifier {
                        Some(
                            signal_rs_protos::attachment_pointer::AttachmentIdentifier::CdnId(id),
                        ) => (Some(id.to_string()), None),
                        Some(
                            signal_rs_protos::attachment_pointer::AttachmentIdentifier::CdnKey(k),
                        ) => (None, Some(k.clone())),
                        None => (None, None),
                    };
                    AttachmentMeta {
                        content_type: att.content_type.clone(),
                        file_name: att.file_name.clone(),
                        size: att.size,
                        cdn_id,
                        cdn_key,
                        width: att.width,
                        height: att.height,
                    }
                })
                .collect();
            serde_json::to_string(&metas).ok()
        } else {
            None
        };

        let attachment_names: Vec<String> = data_message
            .attachments
            .iter()
            .map(|att| {
                att.file_name
                    .clone()
                    .unwrap_or_else(|| att.content_type.clone().unwrap_or_else(|| "attachment".into()))
            })
            .collect();

        // Compute expires_in (seconds) from expires_at for storage
        let expires_in = expires_at.map(|eat| {
            let now_millis = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            ((eat - now_millis) / 1000).max(0)
        });

        // Insert the message into the store
        let msg_id = db.insert_message_with_expiry(
            thread.id,
            Some(sender.id),
            timestamp as i64,
            None,
            body,
            MessageType::Normal,
            quote_id,
            expires_in,
            attachments_json.as_deref(),
            expires_at,
        )?;

        // Update thread with latest message
        db.update_thread_on_message(thread.id, timestamp as i64, true)?;

        // Build the application-level Message
        let is_view_once = data_message.is_view_once.unwrap_or(false);

        let message = Message {
            text: body.map(|s| s.to_string()),
            attachments: attachment_names,
            quote: quote_ref,
            reaction: None,
            timestamp,
            sender: Some(sender_uuid.to_string()),
            destination: None,
            group_id: group_id_str,
            is_view_once,
        };

        info!(msg_id, %sender_uuid, "data message stored");
        Ok(Some(message))
    }

    /// Resolve the thread for a data message, handling both group and 1:1 threads.
    ///
    /// Returns the thread and an optional group_id string for group messages.
    fn resolve_thread(
        &self,
        db: &Database,
        sender_recipient_id: i64,
        data_message: &signal_rs_protos::DataMessage,
    ) -> Result<(signal_rs_store::models::thread::Thread, Option<String>)> {
        if let Some(ref gv2) = data_message.group_v2
            && let Some(ref master_key_bytes) = gv2.master_key
            && let Ok(mk) = signal_rs_service::groups::GroupMasterKey::from_bytes(master_key_bytes)
        {
            let group_id_bytes = mk.derive_group_id();
            let group_id_b64 = signal_rs_service::groups::encode_group_id(&group_id_bytes);

            // Find or create the group in the DB
            let group = match db.get_group_by_group_id(&group_id_bytes) {
                Ok(Some(g)) => g,
                Ok(None) => {
                    // Auto-create the group so we can store messages for it
                    let dist_id = uuid::Uuid::new_v4();
                    let db_id = db.insert_group(
                        &group_id_bytes,
                        master_key_bytes,
                        dist_id.as_bytes(),
                    )?;
                    db.get_group_by_id(db_id)?
                        .ok_or_else(|| crate::error::ManagerError::Other(
                            "failed to load newly created group".into(),
                        ))?
                }
                Err(e) => {
                    warn!(error = %e, "failed to look up group, falling back to 1:1 thread");
                    let thread = db.get_or_create_thread_for_recipient(sender_recipient_id)?;
                    return Ok((thread, None));
                }
            };

            let thread = db.get_or_create_thread_for_group(group.id)?;
            return Ok((thread, Some(group_id_b64)));
        }

        // 1:1 thread
        let thread = db.get_or_create_thread_for_recipient(sender_recipient_id)?;
        Ok((thread, None))
    }

    /// Build a ReceiptMessage protobuf (DELIVERY type) for the given timestamp.
    ///
    /// This returns the serialized `Content` protobuf bytes that should be
    /// sent to the original message sender as a delivery receipt.
    pub fn build_delivery_receipt(timestamp: u64) -> Vec<u8> {
        use prost::Message as ProstMsg;

        let receipt = signal_rs_protos::ReceiptMessage {
            r#type: Some(signal_rs_protos::receipt_message::Type::Delivery as i32),
            timestamp: vec![timestamp],
        };
        let content = signal_rs_protos::Content {
            receipt_message: Some(receipt),
            ..Default::default()
        };
        content.encode_to_vec()
    }

    /// Build a ReceiptMessage protobuf (READ type) for the given timestamps.
    ///
    /// This returns the serialized `Content` protobuf bytes that should be
    /// sent to the original message sender(s) as read receipts.
    pub fn build_read_receipt(timestamps: &[u64]) -> Vec<u8> {
        use prost::Message as ProstMsg;

        let receipt = signal_rs_protos::ReceiptMessage {
            r#type: Some(signal_rs_protos::receipt_message::Type::Read as i32),
            timestamp: timestamps.to_vec(),
        };
        let content = signal_rs_protos::Content {
            receipt_message: Some(receipt),
            ..Default::default()
        };
        content.encode_to_vec()
    }

    /// Handle a sync transcript (message sent from another device).
    ///
    /// When we send a message from another linked device, we receive a
    /// sync transcript so all devices have the sent message in their history.
    pub async fn handle_sync_transcript(
        &self,
        db: &Database,
        destination_uuid: &Uuid,
        timestamp: u64,
        body: Option<&str>,
        expires_at: Option<i64>,
    ) -> Result<Option<Message>> {
        debug!(%destination_uuid, timestamp, ?expires_at, "handling sync transcript");

        // Find or create the destination recipient
        let dest = db.get_or_create_recipient(&destination_uuid.to_string())?;

        // Find or create the thread
        let thread = db.get_or_create_thread_for_recipient(dest.id)?;

        // Compute expires_in (seconds) from expires_at for storage
        let expires_in = expires_at.map(|eat| {
            let now_millis = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            ((eat - now_millis) / 1000).max(0)
        });

        // Insert as an outgoing message (sender_id = None for our own messages)
        let _msg_id = db.insert_message_with_expiry(
            thread.id,
            None, // outgoing
            timestamp as i64,
            None,
            body,
            MessageType::Normal,
            None,
            expires_in,
            None,
            expires_at,
        )?;

        db.update_thread_on_message(thread.id, timestamp as i64, false)?;

        // Build the message for display
        let message = Message {
            text: body.map(|s| s.to_string()),
            attachments: Vec::new(),
            quote: None,
            reaction: None,
            timestamp,
            sender: None, // outgoing from self
            destination: Some(destination_uuid.to_string()),
            group_id: None,
            is_view_once: false,
        };

        info!(timestamp, "sync transcript stored");
        Ok(Some(message))
    }
}
