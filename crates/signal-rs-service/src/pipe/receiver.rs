//! Message receiver -- processes incoming envelopes from the WebSocket pipe.
//!
//! The receiver maintains a WebSocket connection to the Signal service and
//! decrypts incoming `Envelope` protobufs into higher-level `Content` types.
//!
//! Connection lifecycle:
//! 1. Connect to `wss://chat.signal.org/v1/websocket/` with credentials
//! 2. Receive server-push `PUT /api/v1/message` requests containing `Envelope` protobufs
//! 3. Acknowledge each message with a 200 response
//! 4. Decrypt the envelope and convert to `SignalContent`
//! 5. On disconnect, reconnect with exponential backoff

use std::time::Duration;

use futures::stream::BoxStream;
use prost::Message;
use tracing::{debug, warn};

use signal_rs_protos::Envelope;
use signal_rs_protocol::stores::{IdentityKeyStore, KyberPreKeyStore, PreKeyStore, SenderKeyStore, SessionStore, SignedPreKeyStore};
use signal_rs_protocol::{DeviceId, ProtocolAddress, ServiceId};

use crate::content::{
    CallContent, CallType, DataContent, ReceiptContent, ReceiptType, SignalContent, StoryContent,
    SyncContent, SyncKind, TypingAction, TypingContent,
};
use crate::error::{Result, ServiceError};
use crate::net::connection::ConnectionManager;
use crate::pipe::cipher::{CiphertextType, SignalCipher};

/// Initial reconnect delay.
const INITIAL_RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Maximum reconnect delay (exponential backoff cap).
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(60);

/// Receives and decrypts messages from the Signal service.
pub struct MessageReceiver<S: SessionStore + IdentityKeyStore + SenderKeyStore + SignedPreKeyStore + PreKeyStore + KyberPreKeyStore + Send + Sync> {
    /// The connection manager for obtaining WebSocket connections.
    connection: ConnectionManager,
    /// The cipher for decrypting messages.
    cipher: SignalCipher<S>,
}

impl<S: SessionStore + IdentityKeyStore + SenderKeyStore + SignedPreKeyStore + PreKeyStore + KyberPreKeyStore + Send + Sync> MessageReceiver<S> {
    /// Create a new message receiver.
    pub fn new(connection: ConnectionManager, store: S) -> Self {
        Self {
            connection,
            cipher: SignalCipher::new(store),
        }
    }

    /// Start receiving messages.
    ///
    /// Returns a stream of decrypted `SignalContent` items. The stream will
    /// reconnect automatically on transient failures with exponential backoff.
    ///
    /// Each item in the stream is the result of:
    /// 1. Receiving a `WebSocketRequestMessage` from the server
    /// 2. Parsing the body as an `Envelope` protobuf
    /// 3. Decrypting the envelope using the Signal Protocol
    /// 4. Parsing the plaintext as a `Content` protobuf
    /// 5. Converting to our high-level `SignalContent` type
    pub fn receive(&self) -> BoxStream<'_, Result<SignalContent>> {
        let stream = futures::stream::unfold(
            (false, INITIAL_RECONNECT_DELAY),
            move |(mut connected, mut reconnect_delay)| async move {
                loop {
                    // Connect the WebSocket if not already connected.
                    if !connected {
                        debug!("connecting authenticated WebSocket for receiving");
                        match self.connection.get_authenticated_ws().await {
                            Ok(ws) => {
                                connected = true;
                                reconnect_delay = INITIAL_RECONNECT_DELAY; // Reset backoff
                                debug!("WebSocket connected, waiting for messages");

                                // Receive loop for this connection
                                loop {
                                    match ws.receive_request().await {
                                        Ok(request) => {
                                            // Acknowledge the message
                                            if let Err(e) =
                                                ws.send_response(request.id, 200).await
                                            {
                                                warn!("failed to ack message: {e}");
                                            }

                                            // Only process PUT /api/v1/message requests
                                            if request.verb != "PUT"
                                                || !request.path.contains("/api/v1/message")
                                            {
                                                debug!(
                                                    verb = %request.verb,
                                                    path = %request.path,
                                                    "ignoring non-message request"
                                                );
                                                continue;
                                            }

                                            // Parse the envelope
                                            let body = match request.body {
                                                Some(b) => b,
                                                None => continue,
                                            };

                                            match self.process_envelope(&body).await {
                                                Ok(Some(content)) => {
                                                    return Some((
                                                        Ok(content),
                                                        (connected, reconnect_delay),
                                                    ));
                                                }
                                                Ok(None) => {
                                                    // Envelope processed but no content to yield
                                                    // (e.g., receipt, unknown type)
                                                    continue;
                                                }
                                                Err(e) => {
                                                    return Some((
                                                        Err(e),
                                                        (connected, reconnect_delay),
                                                    ));
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("WebSocket receive error: {e}");
                                            connected = false;
                                            break;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(
                                    delay_secs = reconnect_delay.as_secs(),
                                    error = %e,
                                    "failed to connect WebSocket, retrying"
                                );
                                tokio::time::sleep(reconnect_delay).await;
                                // Exponential backoff
                                reconnect_delay = std::cmp::min(
                                    reconnect_delay * 2,
                                    MAX_RECONNECT_DELAY,
                                );
                                continue;
                            }
                        }
                    }
                }
            },
        );

        Box::pin(stream)
    }

    /// Process a raw envelope into a high-level content type.
    async fn process_envelope(&self, data: &[u8]) -> Result<Option<SignalContent>> {
        let envelope = Envelope::decode(data)?;

        let source_uuid = envelope.source_service_id.as_deref().unwrap_or_default();
        let source_device = envelope.source_device.unwrap_or(1);
        let envelope_type = envelope.r#type.unwrap_or(0);
        let timestamp = envelope.timestamp.unwrap_or(0);

        debug!(
            source = source_uuid,
            device = source_device,
            envelope_type = envelope_type,
            timestamp = timestamp,
            "processing envelope"
        );

        // Skip envelopes without content
        let content_bytes = match envelope.content {
            Some(ref c) => c.clone(),
            None => return Ok(None),
        };

        // Determine the cipher type from the envelope type.
        // See Envelope.Type in SignalService.proto:
        // 0 = UNKNOWN
        // 1 = CIPHERTEXT (Whisper)
        // 3 = PREKEY_BUNDLE
        // 5 = RECEIPT (no decryption needed)
        // 6 = UNIDENTIFIED_SENDER (sealed sender)
        // 8 = PLAINTEXT_CONTENT
        let cipher_type = match envelope_type {
            1 => CiphertextType::Whisper,
            3 => CiphertextType::PreKey,
            5 => {
                // Receipt envelope - no decryption needed
                debug!("received receipt envelope");
                return Ok(None);
            }
            6 => {
                // Sealed sender (UNIDENTIFIED_SENDER): the content field
                // contains the sealed ciphertext which wraps the real sender
                // identity and the encrypted Content protobuf.
                debug!("received sealed sender envelope, unsealing");
                let plaintext = self
                    .cipher
                    .decrypt_sealed_sender(&content_bytes)
                    .await?;

                // Parse the decrypted bytes as a Content protobuf
                let proto_content =
                    signal_rs_protos::Content::decode(plaintext.data.as_slice()).map_err(
                        |e| {
                            ServiceError::InvalidResponse(format!(
                                "failed to decode Content protobuf from sealed sender: {e}"
                            ))
                        },
                    )?;

                // Route to the appropriate SignalContent variant
                let content = self.content_from_proto(&proto_content, timestamp)?;
                return Ok(content);
            }
            7 => CiphertextType::SenderKey,
            8 => CiphertextType::Plaintext,
            _ => {
                debug!(envelope_type = envelope_type, "unhandled envelope type");
                return Ok(None);
            }
        };

        // Build the sender address
        let sender_uuid = uuid::Uuid::parse_str(source_uuid).map_err(|e| {
            ServiceError::InvalidResponse(format!("invalid source UUID: {e}"))
        })?;
        let sender_address = ProtocolAddress::new(
            ServiceId::aci(sender_uuid),
            DeviceId(source_device),
        );

        // Decrypt the content
        let plaintext = self
            .cipher
            .decrypt(&sender_address, &content_bytes, cipher_type)
            .await?;

        // Parse the decrypted bytes as a Content protobuf
        let proto_content = signal_rs_protos::Content::decode(plaintext.data.as_slice())
            .map_err(|e| ServiceError::InvalidResponse(format!("failed to decode Content protobuf: {e}")))?;

        // Route to the appropriate SignalContent variant based on which
        // field is populated in the Content protobuf.
        let content = self.content_from_proto(&proto_content, timestamp)?;

        Ok(content)
    }

    /// Convert a protobuf `Content` into a high-level `SignalContent`.
    fn content_from_proto(
        &self,
        proto: &signal_rs_protos::Content,
        envelope_timestamp: u64,
    ) -> Result<Option<SignalContent>> {
        // Check each field in priority order

        if let Some(ref dm) = proto.data_message {
            return Ok(Some(SignalContent::Data(Self::parse_data_message(dm, envelope_timestamp))));
        }

        if let Some(ref sm) = proto.sync_message {
            return Ok(Some(Self::parse_sync_message(sm)?));
        }

        if let Some(ref tm) = proto.typing_message {
            let action = match tm.action {
                Some(a) if a == signal_rs_protos::typing_message::Action::Stopped as i32 => {
                    TypingAction::Stopped
                }
                _ => TypingAction::Started,
            };
            return Ok(Some(SignalContent::Typing(TypingContent {
                action,
                timestamp: tm.timestamp.unwrap_or(envelope_timestamp),
                group_id: tm.group_id.clone(),
            })));
        }

        if let Some(ref rm) = proto.receipt_message {
            let receipt_type = match rm.r#type {
                Some(t) if t == signal_rs_protos::receipt_message::Type::Read as i32 => {
                    ReceiptType::Read
                }
                Some(t) if t == signal_rs_protos::receipt_message::Type::Viewed as i32 => {
                    ReceiptType::Viewed
                }
                _ => ReceiptType::Delivery,
            };
            return Ok(Some(SignalContent::Receipt(ReceiptContent {
                receipt_type,
                timestamps: rm.timestamp.clone(),
            })));
        }

        if let Some(ref cm) = proto.call_message {
            let call_type = if cm.offer.is_some() {
                CallType::Offer
            } else if cm.answer.is_some() {
                CallType::Answer
            } else if !cm.ice_update.is_empty() {
                CallType::IceUpdate
            } else if cm.hangup.is_some() {
                CallType::Hangup
            } else if cm.busy.is_some() {
                CallType::Busy
            } else {
                CallType::Opaque
            };
            return Ok(Some(SignalContent::Call(CallContent { call_type })));
        }

        if let Some(ref sm) = proto.story_message {
            let attachment_info = match &sm.attachment {
                Some(signal_rs_protos::story_message::Attachment::FileAttachment(ap)) => {
                    Some(Self::parse_attachment_pointer(ap))
                }
                _ => None,
            };
            return Ok(Some(SignalContent::Story(StoryContent {
                body: None,
                attachment: attachment_info,
                allows_replies: sm.allows_replies.unwrap_or(false),
            })));
        }

        debug!("Content protobuf has no recognized fields populated");
        Ok(None)
    }

    /// Parse a protobuf DataMessage into a DataContent.
    fn parse_data_message(
        dm: &signal_rs_protos::DataMessage,
        envelope_timestamp: u64,
    ) -> DataContent {
        let group_id = dm.group_v2.as_ref().and_then(|g| g.master_key.clone());

        let attachments = dm
            .attachments
            .iter()
            .map(Self::parse_attachment_pointer)
            .collect();

        let quote = dm.quote.as_ref().map(|q| {
            crate::content::QuoteInfo {
                id: q.id.unwrap_or(0),
                author: q.author_aci.as_ref().and_then(|a| {
                    uuid::Uuid::parse_str(a).ok().map(ServiceId::aci)
                }),
                text: q.text.clone(),
            }
        });

        let reaction = dm.reaction.as_ref().map(|r| {
            crate::content::ReactionInfo {
                emoji: r.emoji.clone().unwrap_or_default(),
                is_remove: r.remove.unwrap_or(false),
                target_author: r.target_author_aci.as_ref().and_then(|a| {
                    uuid::Uuid::parse_str(a).ok().map(ServiceId::aci)
                }),
                target_sent_timestamp: r.target_sent_timestamp.unwrap_or(0),
            }
        });

        let sticker = dm.sticker.as_ref().map(|s| {
            crate::content::StickerInfo {
                pack_id: s.pack_id.clone().unwrap_or_default(),
                pack_key: s.pack_key.clone().unwrap_or_default(),
                sticker_id: s.sticker_id.unwrap_or(0),
                emoji: s.emoji.clone(),
            }
        });

        let contacts = dm
            .contact
            .iter()
            .map(|c| {
                let name = c
                    .name
                    .as_ref()
                    .and_then(|n| n.display_name.clone())
                    .unwrap_or_default();
                let phone_numbers = c
                    .number
                    .iter()
                    .filter_map(|p| p.value.clone())
                    .collect();
                crate::content::SharedContactInfo {
                    name,
                    phone_numbers,
                }
            })
            .collect();

        let previews = dm
            .preview
            .iter()
            .map(|p| crate::content::PreviewInfo {
                url: p.url.clone().unwrap_or_default(),
                title: p.title.clone(),
                description: p.description.clone(),
            })
            .collect();

        let mentions = dm
            .body_ranges
            .iter()
            .filter_map(|br| {
                if let Some(signal_rs_protos::data_message::body_range::AssociatedValue::MentionAci(
                    ref aci,
                )) = br.associated_value
                {
                    uuid::Uuid::parse_str(aci).ok().map(|uuid| {
                        crate::content::MentionInfo {
                            uuid,
                            start: br.start.unwrap_or(0),
                            length: br.length.unwrap_or(0),
                        }
                    })
                } else {
                    None
                }
            })
            .collect();

        let is_expiration_update = dm.is_expiration_update();

        DataContent {
            body: dm.body.clone(),
            attachments,
            group_id,
            quote,
            reaction,
            sticker,
            contacts,
            previews,
            mentions,
            expire_timer: dm.expire_timer,
            is_expiration_update,
            is_view_once: dm.is_view_once.unwrap_or(false),
            timestamp: dm.timestamp.unwrap_or(envelope_timestamp),
            profile_key: None,
        }
    }

    /// Parse a protobuf SyncMessage into a SignalContent.
    fn parse_sync_message(sm: &signal_rs_protos::SyncMessage) -> Result<SignalContent> {
        let kind = if let Some(ref sent) = sm.sent {
            let destination = sent.destination_service_id.as_ref().and_then(|s| {
                uuid::Uuid::parse_str(s).ok().map(ServiceId::aci)
            });
            let timestamp = sent.timestamp.unwrap_or(0);
            let content = sent.message.as_ref().map(|dm| {
                Box::new(Self::parse_data_message(dm, timestamp))
            });
            SyncKind::SentTranscript {
                destination,
                timestamp,
                content,
            }
        } else if let Some(ref req) = sm.request {
            let request_type = match req.r#type {
                Some(t) => format!("{t}"),
                None => "unknown".to_string(),
            };
            SyncKind::Request { request_type }
        } else if !sm.read.is_empty() {
            let entries = sm
                .read
                .iter()
                .filter_map(|r| {
                    let uuid = r
                        .sender_aci
                        .as_ref()
                        .and_then(|s| uuid::Uuid::parse_str(s).ok())?;
                    Some((ServiceId::aci(uuid), r.timestamp.unwrap_or(0)))
                })
                .collect();
            SyncKind::ReadReceipts { entries }
        } else if !sm.viewed.is_empty() {
            let entries = sm
                .viewed
                .iter()
                .filter_map(|v| {
                    let uuid = v
                        .sender_aci
                        .as_ref()
                        .and_then(|s| uuid::Uuid::parse_str(s).ok())?;
                    Some((ServiceId::aci(uuid), v.timestamp.unwrap_or(0)))
                })
                .collect();
            SyncKind::ViewedReceipts { entries }
        } else if sm.contacts.is_some() {
            SyncKind::Contacts
        } else if sm.configuration.is_some() {
            SyncKind::Configuration
        } else if sm.blocked.is_some() {
            SyncKind::Blocked
        } else if sm.fetch_latest.is_some() {
            SyncKind::FetchLatest
        } else if sm.keys.is_some() {
            SyncKind::Keys
        } else if sm.message_request_response.is_some() {
            SyncKind::MessageRequestResponse
        } else if sm.view_once_open.is_some() {
            SyncKind::ViewOnceOpen
        } else if sm.call_event.is_some() {
            SyncKind::CallEvent
        } else {
            // Unknown sync type, default to Configuration
            SyncKind::Configuration
        };

        Ok(SignalContent::Sync(SyncContent { kind }))
    }

    /// Parse a protobuf AttachmentPointer into an AttachmentInfo.
    fn parse_attachment_pointer(
        ap: &signal_rs_protos::AttachmentPointer,
    ) -> crate::content::AttachmentInfo {
        let (cdn_number, cdn_key) = match &ap.attachment_identifier {
            Some(signal_rs_protos::attachment_pointer::AttachmentIdentifier::CdnId(id)) => {
                (0u32, id.to_string())
            }
            Some(signal_rs_protos::attachment_pointer::AttachmentIdentifier::CdnKey(key)) => {
                (ap.cdn_number.unwrap_or(0), key.clone())
            }
            None => (0, String::new()),
        };
        crate::content::AttachmentInfo {
            cdn_number,
            cdn_key,
            content_type: ap.content_type.clone().unwrap_or_default(),
            key: ap.key.clone().unwrap_or_default(),
            size: ap.size.unwrap_or(0) as u64,
            file_name: ap.file_name.clone(),
            digest: ap.digest.clone().unwrap_or_default(),
            width: ap.width.unwrap_or(0),
            height: ap.height.unwrap_or(0),
            caption: ap.caption.clone(),
        }
    }
}
