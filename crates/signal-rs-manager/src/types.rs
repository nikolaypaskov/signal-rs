//! Public types used by CLI/TUI frontends.
//!
//! These types form the public API boundary between the manager and the
//! user-facing layers. They are designed to be display-friendly and
//! serializable.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use signal_rs_protocol::TrustLevel;

// ---------------------------------------------------------------------------
// Message sending results
// ---------------------------------------------------------------------------

/// The result of sending a message to one or more recipients.
#[derive(Debug, Clone, Serialize)]
pub struct SendResult {
    /// The message timestamp (used as the message ID).
    pub timestamp: u64,
    /// Per-recipient results.
    pub results: Vec<SendMessageResult>,
}

/// The result of sending a message to a single recipient.
#[derive(Debug, Clone, Serialize)]
pub struct SendMessageResult {
    /// The recipient identifier.
    pub recipient: RecipientIdentifier,
    /// Whether the send was successful.
    pub success: bool,
    /// Whether sealed sender (unidentified delivery) was used.
    pub is_unidentified: bool,
    /// An error description if the send failed.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Recipient identification
// ---------------------------------------------------------------------------

/// How a recipient is identified by the user.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecipientIdentifier {
    /// By ACI UUID.
    Uuid(Uuid),
    /// By E.164 phone number (e.g., "+15551234567").
    PhoneNumber(String),
    /// By Signal username (e.g., "alice.42").
    Username(String),
}

impl std::fmt::Display for RecipientIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecipientIdentifier::Uuid(uuid) => write!(f, "{uuid}"),
            RecipientIdentifier::PhoneNumber(number) => write!(f, "{number}"),
            RecipientIdentifier::Username(username) => write!(f, "{username}"),
        }
    }
}

// ---------------------------------------------------------------------------
// User status (CDSI lookup result)
// ---------------------------------------------------------------------------

/// The registration status of a user.
#[derive(Debug, Clone)]
pub struct UserStatus {
    /// The user's ACI UUID (if registered).
    pub aci: Option<Uuid>,
    /// Whether the user is registered on Signal.
    pub registered: bool,
}

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

/// Information about a linked device.
#[derive(Debug, Clone, Serialize, Deserialize, tabled::Tabled)]
pub struct Device {
    /// The device ID.
    pub id: u32,
    /// The device name (decrypted).
    #[tabled(display_with = "display_option")]
    pub name: Option<String>,
    /// When the device was created (Unix millis).
    pub created: u64,
    /// When the device was last seen (Unix millis).
    pub last_seen: u64,
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name.as_deref().unwrap_or("(unnamed)");
        write!(f, "Device {} ({}), last seen: {}", self.id, name, self.last_seen)
    }
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

/// A Signal Groups v2 group.
#[derive(Debug, Clone, Serialize, Deserialize, tabled::Tabled)]
pub struct Group {
    /// The group ID (base64-encoded group master key hash).
    pub id: String,
    /// The group title.
    pub name: String,
    /// The group description.
    #[tabled(display_with = "display_option")]
    pub description: Option<String>,
    /// The group members.
    #[tabled(display_with = "display_member_count")]
    pub members: Vec<GroupMember>,
    /// The group revision number.
    pub revision: u32,
    /// Whether the group invite link is enabled.
    pub invite_link_enabled: bool,
    /// The group's disappearing message timer (seconds), 0 = disabled.
    pub disappearing_messages_timer: u32,
}

impl fmt::Display for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({} members)", self.name, self.members.len())
    }
}

/// A member of a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    /// The member's ACI UUID.
    pub uuid: Uuid,
    /// The member's role.
    pub role: GroupMemberRole,
    /// When the member joined (Unix millis).
    pub joined_at_revision: u32,
}

/// A group member's role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupMemberRole {
    /// A regular member.
    Member,
    /// An administrator.
    Administrator,
}

// ---------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------

/// A stored identity (safety number) for a contact.
#[derive(Debug, Clone, Serialize, tabled::Tabled)]
pub struct Identity {
    /// The recipient's ACI UUID.
    pub address: Uuid,
    /// The trust level.
    #[tabled(display_with = "display_trust_level")]
    pub trust_level: TrustLevel,
    /// The safety number fingerprint (displayable string).
    pub fingerprint: String,
    /// When this identity was first seen (Unix millis).
    pub added: u64,
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let trust = match self.trust_level {
            TrustLevel::Untrusted => "UNTRUSTED",
            TrustLevel::TrustedUnverified => "TRUSTED_UNVERIFIED",
            TrustLevel::TrustedVerified => "TRUSTED_VERIFIED",
        };
        write!(f, "{} [{}] fingerprint: {}", self.address, trust, self.fingerprint)
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// A message as presented to the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// The message text body.
    pub text: Option<String>,
    /// Attached file paths or references.
    pub attachments: Vec<String>,
    /// A quoted message (reply).
    pub quote: Option<QuoteRef>,
    /// A reaction emoji.
    pub reaction: Option<String>,
    /// The message timestamp.
    pub timestamp: u64,
    /// The sender's identifier (None for outgoing/sync transcript).
    pub sender: Option<String>,
    /// The conversation partner UUID (sender for incoming, destination for outgoing sync).
    pub destination: Option<String>,
    /// The group ID (if a group message).
    pub group_id: Option<String>,
    /// Whether this is a view-once message.
    pub is_view_once: bool,
}

/// A reference to a quoted (replied-to) message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteRef {
    /// The quoted message's timestamp.
    pub id: u64,
    /// The quoted message's author.
    pub author: String,
    /// The quoted text.
    pub text: Option<String>,
}

// ---------------------------------------------------------------------------
// Tabled helper display functions
// ---------------------------------------------------------------------------

fn display_option(o: &Option<String>) -> String {
    o.as_deref().unwrap_or("").to_string()
}

fn display_member_count(members: &[GroupMember]) -> String {
    format!("{}", members.len())
}

fn display_trust_level(level: &TrustLevel) -> String {
    match level {
        TrustLevel::Untrusted => "UNTRUSTED".to_string(),
        TrustLevel::TrustedUnverified => "TRUSTED_UNVERIFIED".to_string(),
        TrustLevel::TrustedVerified => "TRUSTED_VERIFIED".to_string(),
    }
}

