//! Signal Protocol Buffer definitions compiled with prost.
//!
//! This crate contains all the protobuf message types used by the Signal
//! messaging protocol, including:
//!
//! - **SignalService**: Core message types (Envelope, Content, DataMessage, SyncMessage, etc.)
//! - **SubProtocol**: WebSocket framing messages
//! - **Groups**: Groups v2 protocol messages
//! - **Provisioning**: Device provisioning messages
//! - **StorageService**: Encrypted storage service messages

#[allow(clippy::large_enum_variant)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/signalservice.rs"));
}
pub use proto::*;

pub mod wire_format {
    include!(concat!(env!("OUT_DIR"), "/signal.proto.wire.rs"));
}

#[allow(clippy::large_enum_variant)]
pub mod sealed_sender_proto {
    include!(concat!(env!("OUT_DIR"), "/signal.proto.sealed_sender.rs"));
}

// ---------------------------------------------------------------------------
// Convenience type aliases
// ---------------------------------------------------------------------------

/// Alias for the envelope type enum values.
pub type EnvelopeType = envelope::Type;

/// Alias for the data message flags.
pub type DataMessageFlags = data_message::Flags;

/// Alias for the attachment pointer flags.
pub type AttachmentFlags = attachment_pointer::Flags;

/// Alias for the receipt message type.
pub type ReceiptType = receipt_message::Type;

/// Alias for the typing action.
pub type TypingAction = typing_message::Action;

/// Alias for the verified state.
pub type VerifiedState = verified::State;

/// Alias for the WebSocket message type.
pub type WebSocketMessageType = web_socket_message::Type;

/// Alias for the group member role.
pub type MemberRole = member::Role;

/// Alias for the access control level.
pub type AccessRequired = access_control::AccessRequired;

// ---------------------------------------------------------------------------
// Helper implementations
// ---------------------------------------------------------------------------

impl Envelope {
    /// Returns true if this envelope contains an urgent message.
    pub fn is_urgent(&self) -> bool {
        self.urgent.unwrap_or(true)
    }

    /// Returns the envelope type as an enum, defaulting to `Unknown`.
    pub fn envelope_type(&self) -> envelope::Type {
        self.r#type
            .and_then(|t| envelope::Type::try_from(t).ok())
            .unwrap_or(envelope::Type::Unknown)
    }
}

impl DataMessage {
    /// Returns true if this message has the end-session flag set.
    pub fn is_end_session(&self) -> bool {
        self.flags
            .map(|f| f & (data_message::Flags::EndSession as i32 as u32) != 0)
            .unwrap_or(false)
    }

    /// Returns true if this message has the expiration timer update flag set.
    pub fn is_expiration_update(&self) -> bool {
        self.flags
            .map(|f| f & (data_message::Flags::ExpirationTimerUpdate as i32 as u32) != 0)
            .unwrap_or(false)
    }

    /// Returns true if this message has the profile key update flag set.
    pub fn is_profile_key_update(&self) -> bool {
        self.flags
            .map(|f| f & (data_message::Flags::ProfileKeyUpdate as i32 as u32) != 0)
            .unwrap_or(false)
    }
}

impl WebSocketMessage {
    /// Returns true if this is a request message.
    pub fn is_request(&self) -> bool {
        self.r#type
            .and_then(|t| web_socket_message::Type::try_from(t).ok())
            .map(|t| t == web_socket_message::Type::Request)
            .unwrap_or(false)
    }

    /// Returns true if this is a response message.
    pub fn is_response(&self) -> bool {
        self.r#type
            .and_then(|t| web_socket_message::Type::try_from(t).ok())
            .map(|t| t == web_socket_message::Type::Response)
            .unwrap_or(false)
    }
}
