//! Message sender -- encrypts and sends outgoing messages.
//!
//! The sender handles:
//! - Encrypting content for each recipient device
//! - Handling pre-key bundle fetching for new sessions
//! - Sealed sender (unidentified delivery) when possible
//! - Retry logic for stale sessions and missing devices (409/410)

use std::time::Duration;

use base64::Engine;
use prost::Message;
use tracing::{debug, info, warn};

use signal_rs_protocol::stores::{IdentityKeyStore, KyberPreKeyStore, PreKeyStore, SenderKeyStore, SessionStore, SignedPreKeyStore};
use signal_rs_protocol::{DeviceId, ProtocolAddress};

use crate::api::keys::KeysApi;
use crate::api::message::{MessageApi, OutgoingMessageEntity, SendMessageRequest};
use crate::content::SignalContent;
use crate::error::{Result, ServiceError};
use crate::net::connection::ConnectionManager;
use crate::pipe::cipher::SignalCipher;

/// The result of sending a message to a single recipient.
#[derive(Debug, Clone)]
pub struct SendResult {
    /// The recipient address.
    pub address: ProtocolAddress,
    /// Whether the send was successful.
    pub success: bool,
    /// Whether sealed sender (unidentified delivery) was used.
    pub is_unidentified: bool,
    /// An error message if the send failed.
    pub error: Option<String>,
    /// Whether the server indicated a sync message is needed.
    pub needs_sync: bool,
}

/// Maximum number of retry attempts on 409/410 (stale devices/sessions).
const MAX_RETRIES: u32 = 3;

/// Maximum number of retry attempts for transient failures (network, 5xx).
const MAX_TRANSIENT_RETRIES: u32 = 3;

/// Base delay for exponential backoff on transient failures.
const BACKOFF_BASE: Duration = Duration::from_secs(1);

/// Encrypts and sends messages to Signal recipients.
pub struct MessageSender<S: SessionStore + IdentityKeyStore + SenderKeyStore + SignedPreKeyStore + PreKeyStore + KyberPreKeyStore + Send + Sync> {
    /// The connection manager.
    connection: ConnectionManager,
    /// The cipher for encrypting messages.
    cipher: SignalCipher<S>,
}

impl<S: SessionStore + IdentityKeyStore + SenderKeyStore + SignedPreKeyStore + PreKeyStore + KyberPreKeyStore + Send + Sync> MessageSender<S> {
    /// Create a new message sender.
    pub fn new(connection: ConnectionManager, store: S) -> Self {
        Self {
            connection,
            cipher: SignalCipher::new(store),
        }
    }

    /// Serialize a `SignalContent` to protobuf bytes.
    ///
    /// Constructs a `signal_rs_protos::Content` protobuf from the high-level
    /// content type and encodes it with `prost::Message::encode_to_vec()`.
    fn encode_content(content: &SignalContent) -> Vec<u8> {
        let proto = Self::content_to_proto(content);
        proto.encode_to_vec()
    }

    /// Convert a `SignalContent` into a protobuf `Content` message.
    fn content_to_proto(content: &SignalContent) -> signal_rs_protos::Content {
        match content {
            SignalContent::Data(data) => {
                let data_message = signal_rs_protos::DataMessage {
                    body: data.body.clone(),
                    timestamp: Some(data.timestamp),
                    expire_timer: data.expire_timer,
                    is_view_once: Some(data.is_view_once),
                    flags: if data.is_expiration_update {
                        Some(signal_rs_protos::data_message::Flags::ExpirationTimerUpdate as i32 as u32)
                    } else {
                        None
                    },
                    group_v2: data.group_id.as_ref().map(|gid| {
                        signal_rs_protos::GroupContextV2 {
                            master_key: Some(gid.clone()),
                            revision: None,
                            group_change: None,
                        }
                    }),
                    attachments: data.attachments.iter().map(|a| {
                        signal_rs_protos::AttachmentPointer {
                            attachment_identifier: Some(
                                signal_rs_protos::attachment_pointer::AttachmentIdentifier::CdnKey(
                                    a.cdn_key.clone(),
                                ),
                            ),
                            content_type: Some(a.content_type.clone()),
                            key: Some(a.key.clone()),
                            size: Some(a.size as u32),
                            file_name: a.file_name.clone(),
                            digest: Some(a.digest.clone()),
                            width: Some(a.width),
                            height: Some(a.height),
                            caption: a.caption.clone(),
                            ..Default::default()
                        }
                    }).collect(),
                    quote: data.quote.as_ref().map(|q| {
                        signal_rs_protos::data_message::Quote {
                            id: Some(q.id),
                            author_aci: q.author.as_ref().map(|a| a.uuid.to_string()),
                            text: q.text.clone(),
                            ..Default::default()
                        }
                    }),
                    reaction: data.reaction.as_ref().map(|r| {
                        signal_rs_protos::data_message::Reaction {
                            emoji: Some(r.emoji.clone()),
                            remove: Some(r.is_remove),
                            target_author_aci: r.target_author.as_ref().map(|a| a.uuid.to_string()),
                            target_sent_timestamp: Some(r.target_sent_timestamp),
                        }
                    }),
                    sticker: data.sticker.as_ref().map(|s| {
                        signal_rs_protos::data_message::Sticker {
                            pack_id: Some(s.pack_id.clone()),
                            pack_key: Some(s.pack_key.clone()),
                            sticker_id: Some(s.sticker_id),
                            emoji: s.emoji.clone(),
                            data: None,
                        }
                    }),
                    contact: data.contacts.iter().map(|c| {
                        signal_rs_protos::data_message::Contact {
                            name: Some(signal_rs_protos::data_message::contact::Name {
                                display_name: Some(c.name.clone()),
                                ..Default::default()
                            }),
                            number: c.phone_numbers.iter().map(|p| {
                                signal_rs_protos::data_message::contact::Phone {
                                    value: Some(p.clone()),
                                    ..Default::default()
                                }
                            }).collect(),
                            ..Default::default()
                        }
                    }).collect(),
                    preview: data.previews.iter().map(|p| {
                        signal_rs_protos::Preview {
                            url: Some(p.url.clone()),
                            title: p.title.clone(),
                            description: p.description.clone(),
                            ..Default::default()
                        }
                    }).collect(),
                    body_ranges: data.mentions.iter().map(|m| {
                        signal_rs_protos::data_message::BodyRange {
                            start: Some(m.start),
                            length: Some(m.length),
                            associated_value: Some(
                                signal_rs_protos::data_message::body_range::AssociatedValue::MentionAci(
                                    m.uuid.to_string(),
                                ),
                            ),
                        }
                    }).collect(),
                    profile_key: data.profile_key.clone(),
                    ..Default::default()
                };
                signal_rs_protos::Content {
                    data_message: Some(data_message),
                    ..Default::default()
                }
            }
            SignalContent::Typing(typing) => {
                let action = match typing.action {
                    crate::content::TypingAction::Started => {
                        signal_rs_protos::typing_message::Action::Started as i32
                    }
                    crate::content::TypingAction::Stopped => {
                        signal_rs_protos::typing_message::Action::Stopped as i32
                    }
                };
                signal_rs_protos::Content {
                    typing_message: Some(signal_rs_protos::TypingMessage {
                        timestamp: Some(typing.timestamp),
                        action: Some(action),
                        group_id: typing.group_id.clone(),
                    }),
                    ..Default::default()
                }
            }
            SignalContent::Receipt(receipt) => {
                let receipt_type = match receipt.receipt_type {
                    crate::content::ReceiptType::Delivery => {
                        signal_rs_protos::receipt_message::Type::Delivery as i32
                    }
                    crate::content::ReceiptType::Read => {
                        signal_rs_protos::receipt_message::Type::Read as i32
                    }
                    crate::content::ReceiptType::Viewed => {
                        signal_rs_protos::receipt_message::Type::Viewed as i32
                    }
                };
                signal_rs_protos::Content {
                    receipt_message: Some(signal_rs_protos::ReceiptMessage {
                        r#type: Some(receipt_type),
                        timestamp: receipt.timestamps.clone(),
                    }),
                    ..Default::default()
                }
            }
            SignalContent::Call(call) => {
                let call_message = match call.call_type {
                    crate::content::CallType::Offer => signal_rs_protos::CallMessage {
                        offer: Some(signal_rs_protos::call_message::Offer {
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    crate::content::CallType::Answer => signal_rs_protos::CallMessage {
                        answer: Some(signal_rs_protos::call_message::Answer {
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    crate::content::CallType::Hangup => signal_rs_protos::CallMessage {
                        hangup: Some(signal_rs_protos::call_message::Hangup {
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    crate::content::CallType::Busy => signal_rs_protos::CallMessage {
                        busy: Some(signal_rs_protos::call_message::Busy { id: None }),
                        ..Default::default()
                    },
                    crate::content::CallType::IceUpdate => signal_rs_protos::CallMessage {
                        ice_update: vec![signal_rs_protos::call_message::IceUpdate {
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                    crate::content::CallType::Opaque => signal_rs_protos::CallMessage {
                        opaque: Some(signal_rs_protos::call_message::Opaque {
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                };
                signal_rs_protos::Content {
                    call_message: Some(call_message),
                    ..Default::default()
                }
            }
            SignalContent::Story(story) => {
                let story_message = signal_rs_protos::StoryMessage {
                    allows_replies: Some(story.allows_replies),
                    attachment: story.attachment.as_ref().map(|a| {
                        signal_rs_protos::story_message::Attachment::FileAttachment(
                            signal_rs_protos::AttachmentPointer {
                                attachment_identifier: Some(
                                    signal_rs_protos::attachment_pointer::AttachmentIdentifier::CdnKey(
                                        a.cdn_key.clone(),
                                    ),
                                ),
                                content_type: Some(a.content_type.clone()),
                                key: Some(a.key.clone()),
                                size: Some(a.size as u32),
                                file_name: a.file_name.clone(),
                                digest: Some(a.digest.clone()),
                                width: Some(a.width),
                                height: Some(a.height),
                                caption: a.caption.clone(),
                                ..Default::default()
                            },
                        )
                    }),
                    ..Default::default()
                };
                signal_rs_protos::Content {
                    story_message: Some(story_message),
                    ..Default::default()
                }
            }
            SignalContent::Sync(_sync) => {
                // Sync messages are only received, not sent by clients.
                // Return an empty Content as a safe fallback.
                signal_rs_protos::Content::default()
            }
        }
    }

    /// Send a message to a single recipient.
    ///
    /// This will:
    /// 1. Resolve all device IDs for the recipient (primary + sub-devices)
    /// 2. Encrypt the content for each device (establishing sessions as needed)
    /// 3. Attempt sealed sender delivery if `unidentified_access_key` is provided
    /// 4. Fall back to authenticated delivery on sealed sender failure
    /// 5. Retry on stale sessions (410 Gone) or missing devices (409 Conflict)
    /// 6. Retry with exponential backoff on transient failures (network, 5xx)
    /// 7. Respect rate-limit Retry-After durations from 429 responses
    pub async fn send_message(
        &self,
        recipient: &ProtocolAddress,
        content: &SignalContent,
        timestamp: u64,
        unidentified_access_key: Option<&str>,
    ) -> Result<SendResult> {
        debug!(
            recipient = %recipient,
            timestamp = timestamp,
            sealed_sender = unidentified_access_key.is_some(),
            "sending message"
        );

        let http = self.connection.get_http()?;

        // Serialize the content to protobuf bytes
        let plaintext = Self::encode_content(content);

        // Resolve all device IDs for the recipient.
        // Always include the primary device (1), plus any sub-devices.
        let mut device_ids = self.resolve_devices(&recipient.service_id).await?;
        if !device_ids.contains(&DeviceId::PRIMARY) {
            device_ids.insert(0, DeviceId::PRIMARY);
        }

        let mut attempt = 0u32;
        let mut transient_retries = 0u32;
        let mut current_device_ids = device_ids;
        let mut used_unidentified = false;

        loop {
            attempt += 1;

            // Encrypt for each device
            let mut messages = Vec::new();
            for &device_id in &current_device_ids {
                let address = ProtocolAddress::new(recipient.service_id, device_id);
                let ciphertext = self.cipher.encrypt(&address, &plaintext).await?;

                let b64 = base64::engine::general_purpose::STANDARD;
                messages.push(OutgoingMessageEntity {
                    r#type: ciphertext.message_type.as_wire_type(),
                    destination_device_id: device_id.value(),
                    destination_registration_id: ciphertext.registration_id,
                    content: b64.encode(&ciphertext.data),
                });
            }

            let request = SendMessageRequest {
                messages,
                online: false,
                urgent: true,
                timestamp,
            };

            let message_api = MessageApi::new(&http);

            // Try sealed sender first if we have the access key,
            // then fall back to authenticated send.
            let send_result = if let Some(ua_key) = unidentified_access_key {
                match message_api
                    .send_message_unidentified(&recipient.service_id.uuid, &request, ua_key)
                    .await
                {
                    Ok(response) => {
                        used_unidentified = true;
                        debug!(recipient = %recipient, "sent via sealed sender");
                        Ok(response)
                    }
                    Err(e) => {
                        // Sealed sender failed (e.g., recipient changed profile key).
                        // Fall back to authenticated delivery.
                        warn!(
                            recipient = %recipient, error = %e,
                            "sealed sender failed, falling back to authenticated"
                        );
                        used_unidentified = false;
                        message_api
                            .send_message(&recipient.service_id.uuid, &request)
                            .await
                    }
                }
            } else {
                message_api
                    .send_message(&recipient.service_id.uuid, &request)
                    .await
            };

            match send_result {
                Ok(response) => {
                    info!(
                        recipient = %recipient,
                        unidentified = used_unidentified,
                        "message sent successfully"
                    );
                    return Ok(SendResult {
                        address: recipient.clone(),
                        success: true,
                        is_unidentified: used_unidentified,
                        error: None,
                        needs_sync: response.needs_sync,
                    });
                }
                Err(ServiceError::Conflict) if attempt < MAX_RETRIES => {
                    // 409 Conflict: stale device list.
                    // Fetch fresh pre-key bundles for all devices to update device list.
                    warn!(
                        recipient = %recipient,
                        attempt = attempt,
                        "got 409 Conflict, refreshing devices and retrying"
                    );
                    let keys_api = KeysApi::new(&http);
                    match keys_api
                        .get_pre_key_bundles_for_all_devices(&recipient.service_id)
                        .await
                    {
                        Ok((_identity_key, bundles)) => {
                            current_device_ids = bundles.iter().map(|b| b.device_id).collect();
                            if !current_device_ids.contains(&DeviceId::PRIMARY) {
                                current_device_ids.insert(0, DeviceId::PRIMARY);
                            }
                            debug!(
                                device_count = current_device_ids.len(),
                                "refreshed device list from pre-key bundles"
                            );
                        }
                        Err(e) => {
                            warn!("failed to fetch pre-key bundles: {e}");
                        }
                    }
                    continue;
                }
                Err(ServiceError::Gone) if attempt < MAX_RETRIES => {
                    // 410 Gone: stale sessions.
                    // Fetch fresh pre-key bundles to re-establish sessions.
                    warn!(
                        recipient = %recipient,
                        attempt = attempt,
                        "got 410 Gone, re-fetching pre-key bundles for stale sessions"
                    );
                    let keys_api = KeysApi::new(&http);
                    match keys_api
                        .get_pre_key_bundles_for_all_devices(&recipient.service_id)
                        .await
                    {
                        Ok((_identity_key, bundles)) => {
                            current_device_ids = bundles.iter().map(|b| b.device_id).collect();
                            if !current_device_ids.contains(&DeviceId::PRIMARY) {
                                current_device_ids.insert(0, DeviceId::PRIMARY);
                            }
                            debug!(
                                device_count = current_device_ids.len(),
                                "refreshed sessions from pre-key bundles"
                            );
                        }
                        Err(e) => {
                            warn!("failed to fetch pre-key bundles for stale sessions: {e}");
                        }
                    }
                    continue;
                }
                Err(ServiceError::RateLimited(duration)) => {
                    // 429: rate limited. Respect the Retry-After duration.
                    warn!(
                        recipient = %recipient,
                        retry_after = ?duration,
                        "rate limited by server"
                    );
                    if transient_retries < MAX_TRANSIENT_RETRIES {
                        transient_retries += 1;
                        tokio::time::sleep(duration).await;
                        continue;
                    }
                    return Ok(SendResult {
                        address: recipient.clone(),
                        success: false,
                        is_unidentified: used_unidentified,
                        error: Some(format!("rate limited, retry after {duration:?}")),
                        needs_sync: false,
                    });
                }
                Err(ref e) if e.is_transient() && transient_retries < MAX_TRANSIENT_RETRIES => {
                    // Transient failure (network error, 5xx): retry with exponential backoff.
                    transient_retries += 1;
                    let delay = BACKOFF_BASE * 2u32.saturating_pow(transient_retries - 1);
                    warn!(
                        recipient = %recipient,
                        error = %e,
                        retry = transient_retries,
                        delay = ?delay,
                        "transient failure, retrying with backoff"
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
                Err(e) => {
                    warn!(recipient = %recipient, error = %e, "send failed");
                    return Ok(SendResult {
                        address: recipient.clone(),
                        success: false,
                        is_unidentified: used_unidentified,
                        error: Some(e.to_string()),
                        needs_sync: false,
                    });
                }
            }
        }
    }

    /// Send a message to multiple recipients (group send).
    ///
    /// For each recipient, resolves their full device list and sends
    /// individually. A future optimization would use sender key distribution
    /// to encrypt once and fan out.
    pub async fn send_to_group(
        &self,
        recipients: &[ProtocolAddress],
        content: &SignalContent,
        timestamp: u64,
    ) -> Vec<SendResult> {
        let mut results = Vec::with_capacity(recipients.len());

        for recipient in recipients {
            let result = self.send_message(recipient, content, timestamp, None).await;
            match result {
                Ok(send_result) => results.push(send_result),
                Err(e) => {
                    warn!(recipient = %recipient, error = %e, "group send failed for recipient");
                    results.push(SendResult {
                        address: recipient.clone(),
                        success: false,
                        is_unidentified: false,
                        error: Some(e.to_string()),
                        needs_sync: false,
                    });
                }
            }
        }

        results
    }

    /// Resolve the device list for a recipient.
    ///
    /// Attempts to fetch pre-key bundles for all of the recipient's devices.
    /// Returns the list of device IDs.
    pub async fn resolve_devices(
        &self,
        service_id: &signal_rs_protocol::ServiceId,
    ) -> Result<Vec<DeviceId>> {
        let http = self.connection.get_http()?;
        let keys_api = KeysApi::new(&http);

        match keys_api
            .get_pre_key_bundles_for_all_devices(service_id)
            .await
        {
            Ok((_identity_key, bundles)) => {
                let device_ids: Vec<DeviceId> =
                    bundles.iter().map(|b| b.device_id).collect();
                debug!(
                    service_id = %service_id,
                    devices = ?device_ids,
                    "resolved device list"
                );
                Ok(device_ids)
            }
            Err(e) => {
                warn!(
                    service_id = %service_id,
                    error = %e,
                    "failed to resolve devices, using primary only"
                );
                Ok(vec![DeviceId::PRIMARY])
            }
        }
    }
}
