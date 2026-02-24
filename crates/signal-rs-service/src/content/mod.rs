//! High-level content types.
//!
//! These types wrap the raw protobuf messages (`DataMessage`, `SyncMessage`, etc.)
//! into ergonomic Rust types that are easier to work with in the manager layer.

use signal_rs_protocol::ServiceId;
use uuid::Uuid;

/// A high-level representation of decrypted Signal message content.
///
/// Produced by the message receiver after decrypting an incoming envelope.
#[derive(Debug, Clone)]
pub enum SignalContent {
    /// A data message (text, attachments, reactions, etc.).
    Data(DataContent),
    /// A sync message (sent from another device on the same account).
    Sync(SyncContent),
    /// A typing indicator.
    Typing(TypingContent),
    /// A delivery or read receipt.
    Receipt(ReceiptContent),
    /// A call signaling message.
    Call(CallContent),
    /// A story message.
    Story(StoryContent),
}

/// A data message with parsed fields.
#[derive(Debug, Clone)]
pub struct DataContent {
    /// The message body text.
    pub body: Option<String>,
    /// Attached files.
    pub attachments: Vec<AttachmentInfo>,
    /// Group context (if this message was sent to a group).
    pub group_id: Option<Vec<u8>>,
    /// A quoted (replied-to) message.
    pub quote: Option<QuoteInfo>,
    /// A reaction to another message.
    pub reaction: Option<ReactionInfo>,
    /// A sticker.
    pub sticker: Option<StickerInfo>,
    /// A shared contact card.
    pub contacts: Vec<SharedContactInfo>,
    /// Preview links.
    pub previews: Vec<PreviewInfo>,
    /// Mentions within the message body.
    pub mentions: Vec<MentionInfo>,
    /// The expiration timer value (in seconds), if changed.
    pub expire_timer: Option<u32>,
    /// Whether this message is an expiration timer update.
    pub is_expiration_update: bool,
    /// Whether this message is a view-once message.
    pub is_view_once: bool,
    /// The message timestamp (sender's clock).
    pub timestamp: u64,
    /// The sender's profile key (32 bytes). Included so the recipient can
    /// fetch the sender's profile (name, avatar, etc.).
    pub profile_key: Option<Vec<u8>>,
}

/// Metadata about an attachment.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttachmentInfo {
    /// The CDN number.
    pub cdn_number: u32,
    /// The CDN key / attachment ID.
    pub cdn_key: String,
    /// The MIME content type.
    pub content_type: String,
    /// The encryption key for the attachment.
    pub key: Vec<u8>,
    /// The encrypted attachment size.
    pub size: u64,
    /// The file name (if provided).
    pub file_name: Option<String>,
    /// The attachment digest (for verification).
    pub digest: Vec<u8>,
    /// Width (for images/videos).
    pub width: u32,
    /// Height (for images/videos).
    pub height: u32,
    /// Caption text.
    pub caption: Option<String>,
}

/// Information about a quoted message.
#[derive(Debug, Clone)]
pub struct QuoteInfo {
    /// The quoted message's ID (timestamp).
    pub id: u64,
    /// The quoted message's author.
    pub author: Option<ServiceId>,
    /// The quoted text.
    pub text: Option<String>,
}

/// A reaction to a message.
#[derive(Debug, Clone)]
pub struct ReactionInfo {
    /// The emoji used.
    pub emoji: String,
    /// Whether this removes a previous reaction.
    pub is_remove: bool,
    /// The target message author.
    pub target_author: Option<ServiceId>,
    /// The target message timestamp.
    pub target_sent_timestamp: u64,
}

/// A sticker in a message.
#[derive(Debug, Clone)]
pub struct StickerInfo {
    /// The sticker pack ID.
    pub pack_id: Vec<u8>,
    /// The sticker pack key.
    pub pack_key: Vec<u8>,
    /// The sticker ID within the pack.
    pub sticker_id: u32,
    /// The emoji associated with this sticker.
    pub emoji: Option<String>,
}

/// A shared contact card.
#[derive(Debug, Clone)]
pub struct SharedContactInfo {
    /// The contact's name.
    pub name: String,
    /// Phone numbers.
    pub phone_numbers: Vec<String>,
}

/// A URL preview (link preview).
#[derive(Debug, Clone)]
pub struct PreviewInfo {
    /// The URL.
    pub url: String,
    /// The title.
    pub title: Option<String>,
    /// The description.
    pub description: Option<String>,
}

/// A mention of a user within a message.
#[derive(Debug, Clone)]
pub struct MentionInfo {
    /// The mentioned user's ACI UUID.
    pub uuid: Uuid,
    /// The start position in the message text (UTF-16 offset).
    pub start: u32,
    /// The length of the mention placeholder in the text.
    pub length: u32,
}

/// A sync message from another device on the same account.
#[derive(Debug, Clone)]
pub struct SyncContent {
    /// The type of sync message.
    pub kind: SyncKind,
}

/// The kind of sync message.
#[derive(Debug, Clone)]
pub enum SyncKind {
    /// A sent message transcript.
    SentTranscript {
        /// The destination of the original message.
        destination: Option<ServiceId>,
        /// The timestamp of the sent message.
        timestamp: u64,
        /// The data content that was sent.
        content: Option<Box<DataContent>>,
    },
    /// A request for sync data.
    Request {
        /// The type of data requested.
        request_type: String,
    },
    /// Read receipts synced from another device.
    ReadReceipts {
        /// The read receipt entries.
        entries: Vec<(ServiceId, u64)>,
    },
    /// Viewed receipts synced from another device (e.g. view-once messages).
    ViewedReceipts {
        /// The viewed receipt entries.
        entries: Vec<(ServiceId, u64)>,
    },
    /// Contact sync data.
    Contacts,
    /// Group sync data.
    Groups,
    /// Configuration sync.
    Configuration,
    /// Blocked list sync.
    Blocked,
    /// Fetch latest data request.
    FetchLatest,
    /// Keys sync.
    Keys,
    /// Message request response sync.
    MessageRequestResponse,
    /// View-once open sync.
    ViewOnceOpen,
    /// Call event sync.
    CallEvent,
}

/// A typing indicator.
#[derive(Debug, Clone)]
pub struct TypingContent {
    /// Whether the user started or stopped typing.
    pub action: TypingAction,
    /// The timestamp.
    pub timestamp: u64,
    /// The group ID if this is a group typing indicator.
    pub group_id: Option<Vec<u8>>,
}

/// Typing indicator action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypingAction {
    /// The user started typing.
    Started,
    /// The user stopped typing.
    Stopped,
}

/// A delivery or read receipt.
#[derive(Debug, Clone)]
pub struct ReceiptContent {
    /// The receipt type.
    pub receipt_type: ReceiptType,
    /// The timestamps of the messages being acknowledged.
    pub timestamps: Vec<u64>,
}

/// The type of receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptType {
    /// The message was delivered to the recipient's device.
    Delivery,
    /// The message was read by the recipient.
    Read,
    /// The message was viewed (for view-once messages).
    Viewed,
}

/// A call signaling message.
#[derive(Debug, Clone)]
pub struct CallContent {
    /// The call type.
    pub call_type: CallType,
}

/// The type of call signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallType {
    /// An offer to start a call.
    Offer,
    /// An answer to a call offer.
    Answer,
    /// An ICE candidate update.
    IceUpdate,
    /// The call was hung up.
    Hangup,
    /// The call was marked as busy.
    Busy,
    /// An opaque call message (new calling protocol).
    Opaque,
}

/// A story message.
#[derive(Debug, Clone)]
pub struct StoryContent {
    /// The story body text.
    pub body: Option<String>,
    /// Attached media.
    pub attachment: Option<AttachmentInfo>,
    /// Whether replies are allowed.
    pub allows_replies: bool,
}

// ---------------------------------------------------------------------------
// Protobuf conversion: SignalContent <-> proto types
// ---------------------------------------------------------------------------

use signal_rs_protos as proto;

fn parse_service_id(s: &str) -> Option<ServiceId> {
    s.parse().ok()
}

// -- AttachmentInfo <-> AttachmentPointer --

impl From<&AttachmentInfo> for proto::AttachmentPointer {
    fn from(a: &AttachmentInfo) -> Self {
        proto::AttachmentPointer {
            content_type: Some(a.content_type.clone()),
            key: Some(a.key.clone()),
            size: Some(a.size as u32),
            digest: Some(a.digest.clone()),
            file_name: a.file_name.clone(),
            width: Some(a.width),
            height: Some(a.height),
            caption: a.caption.clone(),
            cdn_number: Some(a.cdn_number),
            attachment_identifier: Some(
                proto::attachment_pointer::AttachmentIdentifier::CdnKey(a.cdn_key.clone()),
            ),
            // Fields we don't track in AttachmentInfo
            thumbnail: None,
            incremental_digest: None,
            incremental_mac_chunk_size: None,
            flags: None,
            blur_hash: None,
            upload_timestamp: None,
            uuid: None,
        }
    }
}

impl From<proto::AttachmentPointer> for AttachmentInfo {
    fn from(ap: proto::AttachmentPointer) -> Self {
        let cdn_key = match ap.attachment_identifier {
            Some(proto::attachment_pointer::AttachmentIdentifier::CdnKey(k)) => k,
            Some(proto::attachment_pointer::AttachmentIdentifier::CdnId(id)) => id.to_string(),
            None => String::new(),
        };
        AttachmentInfo {
            cdn_number: ap.cdn_number.unwrap_or(0),
            cdn_key,
            content_type: ap.content_type.unwrap_or_default(),
            key: ap.key.unwrap_or_default(),
            size: ap.size.unwrap_or(0) as u64,
            file_name: ap.file_name,
            digest: ap.digest.unwrap_or_default(),
            width: ap.width.unwrap_or(0),
            height: ap.height.unwrap_or(0),
            caption: ap.caption,
        }
    }
}

// -- QuoteInfo <-> DataMessage.Quote --

impl From<&QuoteInfo> for proto::data_message::Quote {
    fn from(q: &QuoteInfo) -> Self {
        proto::data_message::Quote {
            id: Some(q.id),
            author_aci: q.author.map(|a| a.to_string()),
            text: q.text.clone(),
            attachments: Vec::new(),
            body_ranges: Vec::new(),
            r#type: None,
        }
    }
}

impl From<proto::data_message::Quote> for QuoteInfo {
    fn from(q: proto::data_message::Quote) -> Self {
        QuoteInfo {
            id: q.id.unwrap_or(0),
            author: q.author_aci.as_deref().and_then(parse_service_id),
            text: q.text,
        }
    }
}

// -- ReactionInfo <-> DataMessage.Reaction --

impl From<&ReactionInfo> for proto::data_message::Reaction {
    fn from(r: &ReactionInfo) -> Self {
        proto::data_message::Reaction {
            emoji: Some(r.emoji.clone()),
            remove: Some(r.is_remove),
            target_author_aci: r.target_author.map(|a| a.to_string()),
            target_sent_timestamp: Some(r.target_sent_timestamp),
        }
    }
}

impl From<proto::data_message::Reaction> for ReactionInfo {
    fn from(r: proto::data_message::Reaction) -> Self {
        ReactionInfo {
            emoji: r.emoji.unwrap_or_default(),
            is_remove: r.remove.unwrap_or(false),
            target_author: r.target_author_aci.as_deref().and_then(parse_service_id),
            target_sent_timestamp: r.target_sent_timestamp.unwrap_or(0),
        }
    }
}

// -- MentionInfo <-> DataMessage.BodyRange (mention_aci variant only) --

impl From<&MentionInfo> for proto::data_message::BodyRange {
    fn from(m: &MentionInfo) -> Self {
        proto::data_message::BodyRange {
            start: Some(m.start),
            length: Some(m.length),
            associated_value: Some(
                proto::data_message::body_range::AssociatedValue::MentionAci(
                    m.uuid.to_string(),
                ),
            ),
        }
    }
}

// -- DataContent <-> DataMessage --

impl From<&DataContent> for proto::DataMessage {
    fn from(d: &DataContent) -> Self {
        let mut flags: u32 = 0;
        if d.is_expiration_update {
            flags |= proto::data_message::Flags::ExpirationTimerUpdate as i32 as u32;
        }

        proto::DataMessage {
            body: d.body.clone(),
            attachments: d.attachments.iter().map(proto::AttachmentPointer::from).collect(),
            group: None,
            group_v2: d.group_id.as_ref().map(|gid| proto::GroupContextV2 {
                master_key: Some(gid.clone()),
                revision: None,
                group_change: None,
            }),
            flags: if flags != 0 { Some(flags) } else { None },
            expire_timer: d.expire_timer,
            profile_key: d.profile_key.clone(),
            timestamp: Some(d.timestamp),
            quote: d.quote.as_ref().map(proto::data_message::Quote::from),
            contact: d.contacts.iter().map(|c| {
                proto::data_message::Contact {
                    name: Some(proto::data_message::contact::Name {
                        display_name: Some(c.name.clone()),
                        given_name: None,
                        family_name: None,
                        prefix: None,
                        suffix: None,
                        middle_name: None,
                    }),
                    number: c.phone_numbers.iter().map(|p| {
                        proto::data_message::contact::Phone {
                            value: Some(p.clone()),
                            r#type: None,
                            label: None,
                        }
                    }).collect(),
                    email: Vec::new(),
                    address: Vec::new(),
                    avatar: None,
                    organization: None,
                }
            }).collect(),
            preview: d.previews.iter().map(|p| proto::Preview {
                url: Some(p.url.clone()),
                title: p.title.clone(),
                image: None,
                description: p.description.clone(),
                date: None,
            }).collect(),
            sticker: d.sticker.as_ref().map(|s| proto::data_message::Sticker {
                pack_id: Some(s.pack_id.clone()),
                pack_key: Some(s.pack_key.clone()),
                sticker_id: Some(s.sticker_id),
                data: None,
                emoji: s.emoji.clone(),
            }),
            required_protocol_version: None,
            is_view_once: Some(d.is_view_once),
            reaction: d.reaction.as_ref().map(proto::data_message::Reaction::from),
            delete: None,
            body_ranges: d.mentions.iter().map(proto::data_message::BodyRange::from).collect(),
            group_call_update: None,
            payment: None,
            story_context: None,
            gift_badge: None,
        }
    }
}

impl From<proto::DataMessage> for DataContent {
    fn from(dm: proto::DataMessage) -> Self {
        let group_id = dm.group_v2.as_ref()
            .and_then(|g| g.master_key.clone())
            .or_else(|| dm.group.as_ref().and_then(|g| g.id.clone()));

        let is_expiration_update = dm.flags
            .map(|f| f & (proto::data_message::Flags::ExpirationTimerUpdate as i32 as u32) != 0)
            .unwrap_or(false);

        let mentions: Vec<MentionInfo> = dm.body_ranges.iter().filter_map(|br| {
            if let Some(proto::data_message::body_range::AssociatedValue::MentionAci(ref aci)) =
                br.associated_value
            {
                let uuid = Uuid::parse_str(aci).ok()?;
                Some(MentionInfo {
                    uuid,
                    start: br.start.unwrap_or(0),
                    length: br.length.unwrap_or(0),
                })
            } else {
                None
            }
        }).collect();

        let contacts: Vec<SharedContactInfo> = dm.contact.into_iter().map(|c| {
            let name = c.name
                .and_then(|n| {
                    n.display_name
                        .or(n.given_name)
                })
                .unwrap_or_default();
            let phone_numbers = c.number.into_iter()
                .filter_map(|p| p.value)
                .collect();
            SharedContactInfo { name, phone_numbers }
        }).collect();

        let previews: Vec<PreviewInfo> = dm.preview.into_iter().map(|p| {
            PreviewInfo {
                url: p.url.unwrap_or_default(),
                title: p.title,
                description: p.description,
            }
        }).collect();

        DataContent {
            body: dm.body,
            attachments: dm.attachments.into_iter().map(AttachmentInfo::from).collect(),
            group_id,
            quote: dm.quote.map(QuoteInfo::from),
            reaction: dm.reaction.map(ReactionInfo::from),
            sticker: dm.sticker.map(|s| StickerInfo {
                pack_id: s.pack_id.unwrap_or_default(),
                pack_key: s.pack_key.unwrap_or_default(),
                sticker_id: s.sticker_id.unwrap_or(0),
                emoji: s.emoji,
            }),
            contacts,
            previews,
            mentions,
            expire_timer: dm.expire_timer,
            is_expiration_update,
            is_view_once: dm.is_view_once.unwrap_or(false),
            timestamp: dm.timestamp.unwrap_or(0),
            profile_key: dm.profile_key,
        }
    }
}

// -- SyncContent <-> SyncMessage --

impl From<&SyncContent> for proto::SyncMessage {
    fn from(s: &SyncContent) -> Self {
        let mut msg = proto::SyncMessage {
            sent: None,
            contacts: None,
            request: None,
            read: Vec::new(),
            blocked: None,
            verified: None,
            configuration: None,
            padding: None,
            sticker_pack_operation: Vec::new(),
            view_once_open: None,
            fetch_latest: None,
            keys: None,
            message_request_response: None,
            viewed: Vec::new(),
            pni_change_number: None,
            call_event: None,
            call_log_event: None,
            delete_for_me: None,
        };

        match &s.kind {
            SyncKind::SentTranscript { destination, timestamp, content } => {
                msg.sent = Some(proto::sync_message::Sent {
                    destination_service_id: destination.map(|d| d.to_string()),
                    timestamp: Some(*timestamp),
                    message: content.as_ref().map(|c| proto::DataMessage::from(c.as_ref())),
                    expiration_start_timestamp: None,
                    unidentified_status: Vec::new(),
                    is_recipient_update: None,
                    story_message: None,
                    story_message_recipients: Vec::new(),
                    edit_message: None,
                });
            }
            SyncKind::Request { request_type } => {
                let req_type = match request_type.as_str() {
                    "CONTACTS" => proto::sync_message::request::Type::Contacts as i32,
                    "BLOCKED" => proto::sync_message::request::Type::Blocked as i32,
                    "CONFIGURATION" => proto::sync_message::request::Type::Configuration as i32,
                    "KEYS" => proto::sync_message::request::Type::Keys as i32,
                    "PNI_IDENTITY" => proto::sync_message::request::Type::PniIdentity as i32,
                    _ => proto::sync_message::request::Type::Unknown as i32,
                };
                msg.request = Some(proto::sync_message::Request {
                    r#type: Some(req_type),
                });
            }
            SyncKind::ReadReceipts { entries } => {
                msg.read = entries.iter().map(|(sid, ts)| {
                    proto::sync_message::Read {
                        sender_aci: Some(sid.to_string()),
                        timestamp: Some(*ts),
                    }
                }).collect();
            }
            SyncKind::ViewedReceipts { entries } => {
                msg.viewed = entries.iter().map(|(sid, ts)| {
                    proto::sync_message::Viewed {
                        sender_aci: Some(sid.to_string()),
                        timestamp: Some(*ts),
                    }
                }).collect();
            }
            SyncKind::Contacts => {
                msg.contacts = Some(proto::sync_message::Contacts {
                    blob: None,
                    complete: None,
                });
            }
            SyncKind::ViewOnceOpen => {
                msg.view_once_open = Some(proto::sync_message::ViewOnceOpen {
                    sender_aci: None,
                    timestamp: None,
                });
            }
            SyncKind::Configuration => {
                msg.configuration = Some(proto::sync_message::Configuration {
                    read_receipts: None,
                    unidentified_delivery_indicators: None,
                    typing_indicators: None,
                    provisioning_version: None,
                    link_previews: None,
                });
            }
            SyncKind::Blocked => {
                msg.blocked = Some(proto::sync_message::Blocked {
                    numbers: Vec::new(),
                    acis: Vec::new(),
                    group_ids: Vec::new(),
                });
            }
            SyncKind::FetchLatest => {
                msg.fetch_latest = Some(proto::sync_message::FetchLatest {
                    r#type: None,
                });
            }
            SyncKind::Keys => {
                msg.keys = Some(proto::sync_message::Keys {
                    storage_service_key: None,
                    master: None,
                });
            }
            SyncKind::MessageRequestResponse => {
                msg.message_request_response = Some(proto::sync_message::MessageRequestResponse {
                    thread_aci: None,
                    group_id: None,
                    r#type: None,
                });
            }
            SyncKind::CallEvent => {
                msg.call_event = Some(proto::sync_message::CallEvent {
                    conversation_id: None,
                    id: None,
                    timestamp: None,
                    r#type: None,
                    direction: None,
                    event: None,
                });
            }
            SyncKind::Groups => {}
        }

        msg
    }
}

impl From<proto::SyncMessage> for SyncContent {
    fn from(sm: proto::SyncMessage) -> Self {
        let kind = if let Some(sent) = sm.sent {
            let destination = sent.destination_service_id
                .as_deref()
                .and_then(parse_service_id);
            let timestamp = sent.timestamp.unwrap_or(0);
            let content = sent.message.map(|dm| Box::new(DataContent::from(dm)));
            SyncKind::SentTranscript { destination, timestamp, content }
        } else if let Some(req) = sm.request {
            let request_type = req.r#type
                .and_then(|t| proto::sync_message::request::Type::try_from(t).ok())
                .map(|t| t.as_str_name().to_string())
                .unwrap_or_else(|| "UNKNOWN".to_string());
            SyncKind::Request { request_type }
        } else if !sm.read.is_empty() {
            let entries = sm.read.into_iter().filter_map(|r| {
                let sid = r.sender_aci.as_deref().and_then(parse_service_id)?;
                Some((sid, r.timestamp.unwrap_or(0)))
            }).collect();
            SyncKind::ReadReceipts { entries }
        } else if !sm.viewed.is_empty() {
            let entries = sm.viewed.into_iter().filter_map(|v| {
                let sid = v.sender_aci.as_deref().and_then(parse_service_id)?;
                Some((sid, v.timestamp.unwrap_or(0)))
            }).collect();
            SyncKind::ViewedReceipts { entries }
        } else if sm.contacts.is_some() {
            SyncKind::Contacts
        } else if sm.view_once_open.is_some() {
            SyncKind::ViewOnceOpen
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
        } else if sm.call_event.is_some() {
            SyncKind::CallEvent
        } else {
            SyncKind::Groups
        };

        SyncContent { kind }
    }
}

// -- TypingContent <-> TypingMessage --

impl From<&TypingContent> for proto::TypingMessage {
    fn from(t: &TypingContent) -> Self {
        proto::TypingMessage {
            timestamp: Some(t.timestamp),
            action: Some(match t.action {
                TypingAction::Started => proto::typing_message::Action::Started as i32,
                TypingAction::Stopped => proto::typing_message::Action::Stopped as i32,
            }),
            group_id: t.group_id.clone(),
        }
    }
}

impl From<proto::TypingMessage> for TypingContent {
    fn from(tm: proto::TypingMessage) -> Self {
        let action = tm.action
            .and_then(|a| proto::typing_message::Action::try_from(a).ok())
            .map(|a| match a {
                proto::typing_message::Action::Started => TypingAction::Started,
                proto::typing_message::Action::Stopped => TypingAction::Stopped,
            })
            .unwrap_or(TypingAction::Started);
        TypingContent {
            action,
            timestamp: tm.timestamp.unwrap_or(0),
            group_id: tm.group_id,
        }
    }
}

// -- ReceiptContent <-> ReceiptMessage --

impl From<&ReceiptContent> for proto::ReceiptMessage {
    fn from(r: &ReceiptContent) -> Self {
        proto::ReceiptMessage {
            r#type: Some(match r.receipt_type {
                ReceiptType::Delivery => proto::receipt_message::Type::Delivery as i32,
                ReceiptType::Read => proto::receipt_message::Type::Read as i32,
                ReceiptType::Viewed => proto::receipt_message::Type::Viewed as i32,
            }),
            timestamp: r.timestamps.clone(),
        }
    }
}

impl From<proto::ReceiptMessage> for ReceiptContent {
    fn from(rm: proto::ReceiptMessage) -> Self {
        let receipt_type = rm.r#type
            .and_then(|t| proto::receipt_message::Type::try_from(t).ok())
            .map(|t| match t {
                proto::receipt_message::Type::Delivery => ReceiptType::Delivery,
                proto::receipt_message::Type::Read => ReceiptType::Read,
                proto::receipt_message::Type::Viewed => ReceiptType::Viewed,
            })
            .unwrap_or(ReceiptType::Delivery);
        ReceiptContent {
            receipt_type,
            timestamps: rm.timestamp,
        }
    }
}

// -- CallContent <-> CallMessage --

impl From<&CallContent> for proto::CallMessage {
    fn from(c: &CallContent) -> Self {
        let mut msg = proto::CallMessage {
            offer: None,
            answer: None,
            ice_update: Vec::new(),
            hangup: None,
            busy: None,
            profile_key: None,
            opaque: None,
            multi_ring: None,
            destination_device_id: None,
        };
        match c.call_type {
            CallType::Offer => {
                msg.offer = Some(proto::call_message::Offer {
                    id: None,
                    r#type: None,
                    opaque: None,
                });
            }
            CallType::Answer => {
                msg.answer = Some(proto::call_message::Answer {
                    id: None,
                    opaque: None,
                });
            }
            CallType::IceUpdate => {
                msg.ice_update.push(proto::call_message::IceUpdate {
                    id: None,
                    opaque: None,
                });
            }
            CallType::Hangup => {
                msg.hangup = Some(proto::call_message::Hangup {
                    id: None,
                    r#type: None,
                    device_id: None,
                });
            }
            CallType::Busy => {
                msg.busy = Some(proto::call_message::Busy { id: None });
            }
            CallType::Opaque => {
                msg.opaque = Some(proto::call_message::Opaque {
                    data: None,
                    urgency: None,
                });
            }
        }
        msg
    }
}

impl From<proto::CallMessage> for CallContent {
    fn from(cm: proto::CallMessage) -> Self {
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
        CallContent { call_type }
    }
}

// -- StoryContent <-> StoryMessage --

impl From<&StoryContent> for proto::StoryMessage {
    fn from(s: &StoryContent) -> Self {
        proto::StoryMessage {
            profile_key: None,
            group: None,
            allows_replies: Some(s.allows_replies),
            body_ranges: Vec::new(),
            attachment: s.attachment.as_ref().map(|a| {
                proto::story_message::Attachment::FileAttachment(
                    proto::AttachmentPointer::from(a),
                )
            }),
        }
    }
}

impl From<proto::StoryMessage> for StoryContent {
    fn from(sm: proto::StoryMessage) -> Self {
        let attachment = match sm.attachment {
            Some(proto::story_message::Attachment::FileAttachment(ap)) => {
                Some(AttachmentInfo::from(ap))
            }
            _ => None,
        };
        StoryContent {
            body: None,
            attachment,
            allows_replies: sm.allows_replies.unwrap_or(false),
        }
    }
}

// -- SignalContent <-> proto::Content --

impl From<&SignalContent> for proto::Content {
    fn from(content: &SignalContent) -> Self {
        let mut c = proto::Content {
            data_message: None,
            sync_message: None,
            call_message: None,
            null_message: None,
            receipt_message: None,
            typing_message: None,
            sender_key_distribution_message: None,
            decryption_error_message: None,
            story_message: None,
            pni_signature_message: None,
            edit_message: None,
        };
        match content {
            SignalContent::Data(d) => c.data_message = Some(proto::DataMessage::from(d)),
            SignalContent::Sync(s) => c.sync_message = Some(proto::SyncMessage::from(s)),
            SignalContent::Typing(t) => c.typing_message = Some(proto::TypingMessage::from(t)),
            SignalContent::Receipt(r) => c.receipt_message = Some(proto::ReceiptMessage::from(r)),
            SignalContent::Call(call) => c.call_message = Some(proto::CallMessage::from(call)),
            SignalContent::Story(s) => c.story_message = Some(proto::StoryMessage::from(s)),
        }
        c
    }
}

impl From<proto::Content> for SignalContent {
    fn from(c: proto::Content) -> Self {
        if let Some(dm) = c.data_message {
            SignalContent::Data(DataContent::from(dm))
        } else if let Some(sm) = c.sync_message {
            SignalContent::Sync(SyncContent::from(sm))
        } else if let Some(tm) = c.typing_message {
            SignalContent::Typing(TypingContent::from(tm))
        } else if let Some(rm) = c.receipt_message {
            SignalContent::Receipt(ReceiptContent::from(rm))
        } else if let Some(cm) = c.call_message {
            SignalContent::Call(CallContent::from(cm))
        } else if let Some(sm) = c.story_message {
            SignalContent::Story(StoryContent::from(sm))
        } else {
            // Fallback for empty or unrecognized content
            SignalContent::Data(DataContent {
                body: None,
                attachments: Vec::new(),
                group_id: None,
                quote: None,
                reaction: None,
                sticker: None,
                contacts: Vec::new(),
                previews: Vec::new(),
                mentions: Vec::new(),
                expire_timer: None,
                is_expiration_update: false,
                is_view_once: false,
                timestamp: 0,
                profile_key: None,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Encode / Decode helpers
// ---------------------------------------------------------------------------

use prost::Message;
use crate::error::{ServiceError, Result};

/// Encode a `SignalContent` to padded protobuf wire bytes ready for encryption.
///
/// The content is serialized to protobuf, then padded with a `0x80` boundary
/// byte followed by zero bytes to reach Signal's exponential bucket size.
/// This prevents message length analysis.
pub fn encode_content(content: &SignalContent) -> Vec<u8> {
    let proto_content = proto::Content::from(content);
    let raw = proto_content.encode_to_vec();
    pad_plaintext(&raw)
}

/// Encode a `SignalContent` to raw (unpadded) protobuf wire bytes.
pub fn encode_content_unpadded(content: &SignalContent) -> Vec<u8> {
    let proto_content = proto::Content::from(content);
    proto_content.encode_to_vec()
}

/// Pad raw protobuf bytes using Signal's exponential bucket scheme.
///
/// Use this when you have already-serialized protobuf bytes that need padding
/// before encryption (e.g. sync transcripts built outside `encode_content`).
pub fn pad_plaintext_public(content: &[u8]) -> Vec<u8> {
    pad_plaintext(content)
}

/// Pad plaintext using Signal's exponential bucket scheme.
///
/// Format: `[content][0x80][0x00...]` up to `padded_size(content.len() + 1)` bytes.
/// The recipient strips padding by scanning from the end for the `0x80` marker.
fn pad_plaintext(content: &[u8]) -> Vec<u8> {
    let with_boundary = content.len() + 1; // +1 for the 0x80 byte
    let padded_size = get_padded_size(with_boundary);
    let mut padded = Vec::with_capacity(padded_size);
    padded.extend_from_slice(content);
    padded.push(0x80);
    padded.resize(padded_size, 0x00);
    padded
}

/// Calculate the padded message size using Signal's exponential bucket scheme.
///
/// Returns `max(541, floor(1.05^ceil(log(size) / log(1.05))))`.
fn get_padded_size(size: usize) -> usize {
    let size_f = size as f64;
    let bucket = (1.05_f64).powf((size_f.ln() / 1.05_f64.ln()).ceil());
    std::cmp::max(541, bucket.floor() as usize)
}

/// Decode protobuf wire bytes into a `SignalContent`.
///
/// Strips Signal's content padding (trailing `0x80` + zeros) before parsing.
pub fn decode_content(bytes: &[u8]) -> Result<SignalContent> {
    let unpadded = strip_content_padding(bytes);
    let proto_content = proto::Content::decode(unpadded)
        .map_err(ServiceError::Protocol)?;
    Ok(SignalContent::from(proto_content))
}

/// Strip Signal content padding from decrypted plaintext.
///
/// Scans from the end for the `0x80` boundary byte, skipping over trailing zeros.
/// If no `0x80` marker is found (unpadded content), returns the input unchanged.
pub fn strip_content_padding(bytes: &[u8]) -> &[u8] {
    for i in (0..bytes.len()).rev() {
        if bytes[i] == 0x80 {
            return &bytes[..i];
        } else if bytes[i] != 0x00 {
            // Non-zero, non-0x80 byte — no padding present
            return bytes;
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- encode/decode roundtrip ----

    fn make_data_content(body: &str, timestamp: u64) -> DataContent {
        DataContent {
            body: Some(body.to_string()),
            attachments: Vec::new(),
            group_id: None,
            quote: None,
            reaction: None,
            sticker: None,
            contacts: Vec::new(),
            previews: Vec::new(),
            mentions: Vec::new(),
            expire_timer: None,
            is_expiration_update: false,
            is_view_once: false,
            timestamp,
            profile_key: None,
        }
    }

    #[test]
    fn encode_decode_data_content_roundtrip() {
        let content = SignalContent::Data(make_data_content("Hello, world!", 1700000000));

        let bytes = encode_content(&content);
        assert!(!bytes.is_empty());

        let decoded = decode_content(&bytes).unwrap();
        let SignalContent::Data(d) = decoded else {
            unreachable!("decode of encoded Data should always yield Data variant");
        };
        assert_eq!(d.body.as_deref(), Some("Hello, world!"));
        assert_eq!(d.timestamp, 1700000000);
        assert!(!d.is_view_once);
        assert!(!d.is_expiration_update);
    }

    #[test]
    fn encode_decode_typing_started_roundtrip() {
        let content = SignalContent::Typing(TypingContent {
            action: TypingAction::Started,
            timestamp: 1700000001,
            group_id: None,
        });

        let bytes = encode_content(&content);
        let decoded = decode_content(&bytes).unwrap();
        let SignalContent::Typing(t) = decoded else {
            unreachable!("decode of encoded Typing should always yield Typing variant");
        };
        assert_eq!(t.action, TypingAction::Started);
        assert_eq!(t.timestamp, 1700000001);
        assert!(t.group_id.is_none());
    }

    #[test]
    fn encode_decode_typing_stopped_roundtrip() {
        let content = SignalContent::Typing(TypingContent {
            action: TypingAction::Stopped,
            timestamp: 42,
            group_id: Some(vec![1, 2, 3]),
        });

        let bytes = encode_content(&content);
        let decoded = decode_content(&bytes).unwrap();
        let SignalContent::Typing(t) = decoded else {
            unreachable!("decode of encoded Typing should always yield Typing variant");
        };
        assert_eq!(t.action, TypingAction::Stopped);
        assert_eq!(t.group_id.as_deref(), Some(&[1u8, 2, 3][..]));
    }

    #[test]
    fn encode_decode_receipt_read_roundtrip() {
        let content = SignalContent::Receipt(ReceiptContent {
            receipt_type: ReceiptType::Read,
            timestamps: vec![100, 200, 300],
        });

        let bytes = encode_content(&content);
        let decoded = decode_content(&bytes).unwrap();
        let SignalContent::Receipt(r) = decoded else {
            unreachable!("decode of encoded Receipt should always yield Receipt variant");
        };
        assert_eq!(r.receipt_type, ReceiptType::Read);
        assert_eq!(r.timestamps, vec![100, 200, 300]);
    }

    #[test]
    fn encode_decode_receipt_delivery_roundtrip() {
        let content = SignalContent::Receipt(ReceiptContent {
            receipt_type: ReceiptType::Delivery,
            timestamps: vec![999],
        });

        let bytes = encode_content(&content);
        let decoded = decode_content(&bytes).unwrap();
        let SignalContent::Receipt(r) = decoded else {
            unreachable!("decode of encoded Receipt should always yield Receipt variant");
        };
        assert_eq!(r.receipt_type, ReceiptType::Delivery);
        assert_eq!(r.timestamps, vec![999]);
    }

    #[test]
    fn encode_decode_receipt_viewed_roundtrip() {
        let content = SignalContent::Receipt(ReceiptContent {
            receipt_type: ReceiptType::Viewed,
            timestamps: vec![500],
        });

        let bytes = encode_content(&content);
        let decoded = decode_content(&bytes).unwrap();
        let SignalContent::Receipt(r) = decoded else {
            unreachable!("decode of encoded Receipt should always yield Receipt variant");
        };
        assert_eq!(r.receipt_type, ReceiptType::Viewed);
    }

    // ---- DataContent <-> proto::DataMessage conversion ----

    #[test]
    fn data_content_with_reaction_roundtrip() {
        let uuid = uuid::Uuid::parse_str("a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5").unwrap();
        let original = DataContent {
            body: None,
            attachments: Vec::new(),
            group_id: None,
            quote: None,
            reaction: Some(ReactionInfo {
                emoji: "thumbsup".to_string(),
                is_remove: false,
                target_author: Some(ServiceId::aci(uuid)),
                target_sent_timestamp: 12345,
            }),
            sticker: None,
            contacts: Vec::new(),
            previews: Vec::new(),
            mentions: Vec::new(),
            expire_timer: None,
            is_expiration_update: false,
            is_view_once: false,
            timestamp: 67890,
            profile_key: None,
        };

        let proto_dm = proto::DataMessage::from(&original);
        let restored = DataContent::from(proto_dm);

        let r = restored.reaction.unwrap();
        assert_eq!(r.emoji, "thumbsup");
        assert!(!r.is_remove);
        assert_eq!(r.target_sent_timestamp, 12345);
        assert_eq!(restored.timestamp, 67890);
    }

    #[test]
    fn data_content_with_quote_roundtrip() {
        let original = DataContent {
            body: Some("reply text".into()),
            attachments: Vec::new(),
            group_id: None,
            quote: Some(QuoteInfo {
                id: 11111,
                author: None,
                text: Some("quoted text".into()),
            }),
            reaction: None,
            sticker: None,
            contacts: Vec::new(),
            previews: Vec::new(),
            mentions: Vec::new(),
            expire_timer: None,
            is_expiration_update: false,
            is_view_once: false,
            timestamp: 22222,
            profile_key: None,
        };

        let proto_dm = proto::DataMessage::from(&original);
        let restored = DataContent::from(proto_dm);

        assert_eq!(restored.body.as_deref(), Some("reply text"));
        let q = restored.quote.unwrap();
        assert_eq!(q.id, 11111);
        assert_eq!(q.text.as_deref(), Some("quoted text"));
    }

    #[test]
    fn data_content_view_once_flag() {
        let original = DataContent {
            body: Some("secret".into()),
            attachments: Vec::new(),
            group_id: None,
            quote: None,
            reaction: None,
            sticker: None,
            contacts: Vec::new(),
            previews: Vec::new(),
            mentions: Vec::new(),
            expire_timer: None,
            is_expiration_update: false,
            is_view_once: true,
            timestamp: 33333,
            profile_key: None,
        };

        let proto_dm = proto::DataMessage::from(&original);
        let restored = DataContent::from(proto_dm);
        assert!(restored.is_view_once);
    }

    #[test]
    fn data_content_expiration_update_flag() {
        let original = DataContent {
            body: None,
            attachments: Vec::new(),
            group_id: None,
            quote: None,
            reaction: None,
            sticker: None,
            contacts: Vec::new(),
            previews: Vec::new(),
            mentions: Vec::new(),
            expire_timer: Some(3600),
            is_expiration_update: true,
            is_view_once: false,
            timestamp: 44444,
            profile_key: None,
        };

        let proto_dm = proto::DataMessage::from(&original);
        let restored = DataContent::from(proto_dm);
        assert!(restored.is_expiration_update);
        assert_eq!(restored.expire_timer, Some(3600));
    }

    #[test]
    fn data_content_with_group_id() {
        let group_key = vec![0xAA; 32];
        let original = DataContent {
            body: Some("group msg".into()),
            attachments: Vec::new(),
            group_id: Some(group_key.clone()),
            quote: None,
            reaction: None,
            sticker: None,
            contacts: Vec::new(),
            previews: Vec::new(),
            mentions: Vec::new(),
            expire_timer: None,
            is_expiration_update: false,
            is_view_once: false,
            timestamp: 55555,
            profile_key: None,
        };

        let proto_dm = proto::DataMessage::from(&original);
        let restored = DataContent::from(proto_dm);
        assert_eq!(restored.group_id.as_deref(), Some(group_key.as_slice()));
    }

    // ---- TypingContent <-> proto::TypingMessage ----

    #[test]
    fn typing_content_proto_roundtrip() {
        let original = TypingContent {
            action: TypingAction::Started,
            timestamp: 99999,
            group_id: None,
        };

        let proto_tm = proto::TypingMessage::from(&original);
        let restored = TypingContent::from(proto_tm);
        assert_eq!(restored.action, TypingAction::Started);
        assert_eq!(restored.timestamp, 99999);
    }

    // ---- ReceiptContent <-> proto::ReceiptMessage ----

    #[test]
    fn receipt_content_proto_roundtrip() {
        let original = ReceiptContent {
            receipt_type: ReceiptType::Read,
            timestamps: vec![10, 20, 30],
        };

        let proto_rm = proto::ReceiptMessage::from(&original);
        let restored = ReceiptContent::from(proto_rm);
        assert_eq!(restored.receipt_type, ReceiptType::Read);
        assert_eq!(restored.timestamps, vec![10, 20, 30]);
    }

    // ---- CallContent <-> proto::CallMessage ----

    #[test]
    fn call_content_offer_roundtrip() {
        let original = CallContent { call_type: CallType::Offer };
        let proto_cm = proto::CallMessage::from(&original);
        let restored = CallContent::from(proto_cm);
        assert_eq!(restored.call_type, CallType::Offer);
    }

    #[test]
    fn call_content_hangup_roundtrip() {
        let original = CallContent { call_type: CallType::Hangup };
        let proto_cm = proto::CallMessage::from(&original);
        let restored = CallContent::from(proto_cm);
        assert_eq!(restored.call_type, CallType::Hangup);
    }

    #[test]
    fn call_content_busy_roundtrip() {
        let original = CallContent { call_type: CallType::Busy };
        let proto_cm = proto::CallMessage::from(&original);
        let restored = CallContent::from(proto_cm);
        assert_eq!(restored.call_type, CallType::Busy);
    }

    // ---- AttachmentInfo <-> proto::AttachmentPointer ----

    #[test]
    fn attachment_info_proto_roundtrip() {
        let original = AttachmentInfo {
            cdn_number: 2,
            cdn_key: "abc123".to_string(),
            content_type: "image/png".to_string(),
            key: vec![0xDE; 32],
            size: 4096,
            file_name: Some("photo.png".to_string()),
            digest: vec![0xAA; 32],
            width: 640,
            height: 480,
            caption: Some("a photo".to_string()),
        };

        let proto_ap = proto::AttachmentPointer::from(&original);
        let restored = AttachmentInfo::from(proto_ap);

        assert_eq!(restored.cdn_number, 2);
        assert_eq!(restored.cdn_key, "abc123");
        assert_eq!(restored.content_type, "image/png");
        assert_eq!(restored.key, vec![0xDE; 32]);
        assert_eq!(restored.size, 4096);
        assert_eq!(restored.file_name.as_deref(), Some("photo.png"));
        assert_eq!(restored.digest, vec![0xAA; 32]);
        assert_eq!(restored.width, 640);
        assert_eq!(restored.height, 480);
        assert_eq!(restored.caption.as_deref(), Some("a photo"));
    }

    // ---- SignalContent <-> proto::Content ----

    #[test]
    fn signal_content_data_proto_roundtrip() {
        let content = SignalContent::Data(make_data_content("test", 12345));
        let proto_c = proto::Content::from(&content);
        let restored = SignalContent::from(proto_c);
        let SignalContent::Data(d) = restored else {
            unreachable!("proto roundtrip of Data should always yield Data variant");
        };
        assert_eq!(d.body.as_deref(), Some("test"));
        assert_eq!(d.timestamp, 12345);
    }

    #[test]
    fn empty_content_proto_defaults_to_data() {
        let empty = proto::Content::default();
        let content = SignalContent::from(empty);
        let SignalContent::Data(d) = content else {
            unreachable!("empty proto::Content should fall back to Data variant");
        };
        assert!(d.body.is_none());
        assert_eq!(d.timestamp, 0);
    }

    #[test]
    fn decode_invalid_bytes_fails() {
        let result = decode_content(&[0xFF, 0xFF, 0xFF]);
        // Protobuf decoding may succeed or fail on random bytes;
        // but we test that the function does not panic.
        let _ = result;
    }

    #[test]
    fn decode_empty_bytes_yields_empty_data() {
        // Empty protobuf Content should decode to the fallback DataContent
        let result = decode_content(&[]).unwrap();
        let SignalContent::Data(d) = result else {
            unreachable!("empty bytes should decode to Data fallback variant");
        };
        assert!(d.body.is_none());
    }

    // ---- StoryContent <-> proto::StoryMessage ----

    #[test]
    fn story_content_roundtrip() {
        let content = SignalContent::Story(StoryContent {
            body: None,
            attachment: None,
            allows_replies: true,
        });

        let bytes = encode_content(&content);
        let decoded = decode_content(&bytes).unwrap();
        let SignalContent::Story(s) = decoded else {
            unreachable!("decode of encoded Story should always yield Story variant");
        };
        assert!(s.allows_replies);
        assert!(s.attachment.is_none());
    }

    // ---- SyncContent <-> proto::SyncMessage ----

    #[test]
    fn sync_contacts_roundtrip() {
        let content = SignalContent::Sync(SyncContent {
            kind: SyncKind::Contacts,
        });

        let proto_c = proto::Content::from(&content);
        let restored = SignalContent::from(proto_c);
        let SignalContent::Sync(s) = restored else {
            unreachable!("proto roundtrip of Sync should always yield Sync variant");
        };
        assert!(
            matches!(s.kind, SyncKind::Contacts),
            "expected Contacts, got {:?}",
            s.kind
        );
    }

    #[test]
    fn sync_configuration_roundtrip() {
        let content = SignalContent::Sync(SyncContent {
            kind: SyncKind::Configuration,
        });

        let proto_c = proto::Content::from(&content);
        let restored = SignalContent::from(proto_c);
        let SignalContent::Sync(s) = restored else {
            unreachable!("proto roundtrip of Sync should always yield Sync variant");
        };
        assert!(
            matches!(s.kind, SyncKind::Configuration),
            "expected Configuration, got {:?}",
            s.kind
        );
    }

    #[test]
    fn sync_blocked_roundtrip() {
        let content = SignalContent::Sync(SyncContent {
            kind: SyncKind::Blocked,
        });

        let proto_c = proto::Content::from(&content);
        let restored = SignalContent::from(proto_c);
        let SignalContent::Sync(s) = restored else {
            unreachable!("proto roundtrip of Sync should always yield Sync variant");
        };
        assert!(
            matches!(s.kind, SyncKind::Blocked),
            "expected Blocked, got {:?}",
            s.kind
        );
    }
}
