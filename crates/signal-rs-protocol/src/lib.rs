//! Signal Protocol types and traits for signal-rs.
//!
//! This crate provides a thin adapter layer over the Signal Protocol. For Phase 1,
//! it defines our own protocol types that mirror libsignal's interfaces. These will
//! later be replaced with actual libsignal integration once the complex build
//! requirements (specific git revisions, FFI components) are resolved.
//!
//! # Modules
//!
//! - [`error`] - Protocol error types
//! - [`types`] - Core type definitions (ServiceId, DeviceId)
//! - [`identity`] - Identity key types and trust levels
//! - [`keys`] - Pre-key, signed pre-key, and Kyber pre-key types
//! - [`address`] - Protocol addressing (ServiceId + DeviceId)
//! - [`session`] - Session record types
//! - [`sealed_sender`] - Sealed sender / unidentified delivery types
//! - [`sender_key`] - Sender key distribution types
//! - [`stores`] - Protocol store traits for persistence

pub mod error;
pub mod types;
pub mod identity;
pub mod keys;
pub mod address;
pub mod session;
pub mod message;
pub mod sealed_sender;
pub mod sender_key;
pub mod stores;

// Re-export key types at the crate root for convenience.
pub use error::ProtocolError;
pub use types::{DeviceId, ServiceId, ServiceIdKind};
pub use identity::{IdentityKey, IdentityKeyPair, TrustLevel};
pub use keys::{
    KyberPreKeyId, KyberPreKeyRecord, PreKeyBundle, PreKeyId, PreKeyRecord, SignedPreKeyId,
    SignedPreKeyRecord, generate_registration_id, generate_pre_keys, generate_signed_pre_key,
    generate_kyber_pre_key, PREKEY_BATCH_SIZE, PREKEY_MAXIMUM_ID,
};
pub use address::ProtocolAddress;
pub use session::SessionRecord;
pub use message::{WireSignalMessage, WirePreKeySignalMessage, WireSenderKeyMessage, SIGNAL_MESSAGE_VERSION};
pub use sealed_sender::{
    seal as seal_sealed_sender, unseal as unseal_sealed_sender,
    validate_certificate_expiry, validate_certificate_sender,
    SenderCertificate, UnidentifiedAccessMode, UnsealedMessage,
};
pub use sender_key::SenderKeyRecord;
pub use stores::{
    IdentityKeyStore, KyberPreKeyStore, PreKeyStore, SenderKeyStore, SessionStore,
    SignedPreKeyStore,
};
