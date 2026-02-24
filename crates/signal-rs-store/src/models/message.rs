//! Message and related data models for TUI display.

use rusqlite::Row;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The type of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i64)]
pub enum MessageType {
    /// A normal text message.
    Normal = 0,
    /// A reaction to another message.
    Reaction = 1,
    /// An edit of a previous message.
    Edit = 2,
    /// A delete of a previous message.
    Delete = 3,
    /// A group update message (membership change, settings change, etc.).
    GroupUpdate = 4,
    /// An expiration timer update.
    ExpirationUpdate = 5,
}

impl MessageType {
    /// Convert from an integer value.
    pub fn from_i64(value: i64) -> Self {
        match value {
            0 => Self::Normal,
            1 => Self::Reaction,
            2 => Self::Edit,
            3 => Self::Delete,
            4 => Self::GroupUpdate,
            5 => Self::ExpirationUpdate,
            _ => Self::Normal,
        }
    }
}

/// A message record from the `message` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Primary key.
    pub id: i64,
    /// The thread this message belongs to.
    pub thread_id: i64,
    /// The sender's recipient ID (NULL for outgoing messages from self).
    pub sender_id: Option<i64>,
    /// Client-side timestamp (milliseconds since epoch).
    pub timestamp: i64,
    /// Server-side timestamp (milliseconds since epoch).
    pub server_timestamp: Option<i64>,
    /// Message body text.
    pub body: Option<String>,
    /// The message type.
    pub message_type: MessageType,
    /// The ID of the quoted message, if this is a reply.
    pub quote_id: Option<i64>,
    /// Disappearing message timer in seconds.
    pub expires_in: Option<i64>,
    /// When the expiration timer started.
    pub expire_start: Option<i64>,
    /// Whether this message has been read.
    pub read: bool,
    /// JSON-encoded attachment metadata.
    pub attachments_json: Option<String>,
    /// When this message expires (Unix millis). NULL means no expiration.
    pub expires_at: Option<i64>,
    /// JSON-encoded mentions array: [{start, length, uuid}].
    pub mentions: Option<String>,
    /// Original body text preserved before the first edit.
    pub original_body: Option<String>,
}

impl Message {
    /// Construct a `Message` from a `rusqlite::Row`.
    ///
    /// Expects all columns from `SELECT * FROM message`.
    pub fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("_id")?,
            thread_id: row.get("thread_id")?,
            sender_id: row.get("sender_id")?,
            timestamp: row.get("timestamp")?,
            server_timestamp: row.get("server_timestamp")?,
            body: row.get("body")?,
            message_type: MessageType::from_i64(row.get("message_type")?),
            quote_id: row.get("quote_id")?,
            expires_in: row.get("expires_in")?,
            expire_start: row.get("expire_start")?,
            read: row.get::<_, i64>("read")? != 0,
            attachments_json: row.get("attachments_json")?,
            expires_at: row.get("expires_at")?,
            mentions: row.get("mentions")?,
            original_body: row.get("original_body")?,
        })
    }
}

/// A single mention within a message body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mention {
    /// Start position in the message body (UTF-16 offset).
    pub start: u32,
    /// Length of the mention placeholder in the body.
    pub length: u32,
    /// The ACI UUID of the mentioned user.
    pub uuid: String,
}

/// A reaction to a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reaction {
    /// Primary key.
    pub id: i64,
    /// The message this reaction is attached to.
    pub message_id: i64,
    /// The ACI of the user who reacted.
    pub sender_aci: String,
    /// The emoji used for the reaction.
    pub emoji: String,
    /// When the reaction was sent (millis since epoch).
    pub timestamp_ms: i64,
}

impl Reaction {
    /// Construct a `Reaction` from a `rusqlite::Row`.
    pub fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("_id")?,
            message_id: row.get("message_id")?,
            sender_aci: row.get("sender_aci")?,
            emoji: row.get("emoji")?,
            timestamp_ms: row.get("timestamp_ms")?,
        })
    }
}

/// A summary of reactions for a message: emoji -> count.
pub type ReactionSummary = HashMap<String, u32>;

/// A call log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallLogEntry {
    /// Primary key.
    pub id: i64,
    /// Unique call identifier.
    pub call_id: String,
    /// The ACI of the peer in the call.
    pub peer_aci: String,
    /// Call type (e.g. "AUDIO", "VIDEO").
    pub call_type: String,
    /// Call direction ("INCOMING" or "OUTGOING").
    pub direction: String,
    /// When the call occurred (millis since epoch).
    pub timestamp_ms: i64,
    /// Duration of the call in seconds, if answered.
    pub duration_seconds: Option<i64>,
    /// Call status: MISSED, ANSWERED, DECLINED, BUSY.
    pub status: String,
}

impl CallLogEntry {
    /// Construct a `CallLogEntry` from a `rusqlite::Row`.
    pub fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("_id")?,
            call_id: row.get("call_id")?,
            peer_aci: row.get("peer_aci")?,
            call_type: row.get("type")?,
            direction: row.get("direction")?,
            timestamp_ms: row.get("timestamp_ms")?,
            duration_seconds: row.get("duration_seconds")?,
            status: row.get("status")?,
        })
    }
}
