//! Protocol store traits for persistence.
//!
//! These traits define the storage interface that the protocol engine needs.
//! Implementations are provided by the `signal-rs-store` crate.
//!
//! All methods are synchronous for simplicity in Phase 1. When we integrate
//! the real libsignal crate, we will migrate to async traits.

use crate::address::ProtocolAddress;
use crate::error::ProtocolError;
use crate::identity::{IdentityKey, IdentityKeyPair, TrustLevel};
use crate::keys::{
    KyberPreKeyId, KyberPreKeyRecord, PreKeyId, PreKeyRecord, SignedPreKeyId, SignedPreKeyRecord,
};
use crate::sender_key::SenderKeyRecord;
use crate::session::SessionRecord;
use crate::types::DeviceId;

// ---------------------------------------------------------------------------
// IdentityKeyStore
// ---------------------------------------------------------------------------

/// Persistence for identity keys and trust decisions.
pub trait IdentityKeyStore {
    /// Return the local identity key pair.
    fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, ProtocolError>;

    /// Return the local registration ID.
    fn get_local_registration_id(&self) -> Result<u32, ProtocolError>;

    /// Save or update the identity key for a remote address.
    ///
    /// Returns `true` if an existing key was replaced (i.e. the identity changed).
    fn save_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool, ProtocolError>;

    /// Check whether the given identity key is trusted for the specified address.
    fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        trust_level: TrustLevel,
    ) -> Result<bool, ProtocolError>;

    /// Retrieve the stored identity key for a remote address, if any.
    fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, ProtocolError>;
}

// ---------------------------------------------------------------------------
// PreKeyStore
// ---------------------------------------------------------------------------

/// Persistence for one-time pre-keys.
pub trait PreKeyStore {
    /// Load a pre-key by its ID.
    fn get_pre_key(&self, id: PreKeyId) -> Result<PreKeyRecord, ProtocolError>;

    /// Save a pre-key.
    fn save_pre_key(&self, id: PreKeyId, record: &PreKeyRecord) -> Result<(), ProtocolError>;

    /// Remove a pre-key after it has been used.
    fn remove_pre_key(&self, id: PreKeyId) -> Result<(), ProtocolError>;
}

// ---------------------------------------------------------------------------
// SignedPreKeyStore
// ---------------------------------------------------------------------------

/// Persistence for signed pre-keys.
pub trait SignedPreKeyStore {
    /// Load a signed pre-key by its ID.
    fn get_signed_pre_key(
        &self,
        id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, ProtocolError>;

    /// Save a signed pre-key.
    fn save_signed_pre_key(
        &self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), ProtocolError>;
}

// ---------------------------------------------------------------------------
// KyberPreKeyStore
// ---------------------------------------------------------------------------

/// Persistence for Kyber (post-quantum) pre-keys.
pub trait KyberPreKeyStore {
    /// Load a Kyber pre-key by its ID.
    fn get_kyber_pre_key(
        &self,
        id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, ProtocolError>;

    /// Save a Kyber pre-key.
    fn save_kyber_pre_key(
        &self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), ProtocolError>;

    /// Mark a Kyber pre-key as used (it may be deleted unless it is a last-resort key).
    fn mark_kyber_pre_key_used(&self, id: KyberPreKeyId) -> Result<(), ProtocolError>;
}

// ---------------------------------------------------------------------------
// SessionStore
// ---------------------------------------------------------------------------

/// Persistence for session state.
pub trait SessionStore {
    /// Load the session for a given address.
    fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, ProtocolError>;

    /// Store a session for a given address.
    fn store_session(
        &self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), ProtocolError>;

    /// Delete the session for a given address.
    fn delete_session(&self, address: &ProtocolAddress) -> Result<(), ProtocolError>;

    /// Return all sub-device session device IDs for the given service ID.
    ///
    /// This should return all device IDs (excluding the primary device, device 1)
    /// for which a session exists.
    fn get_sub_device_sessions(
        &self,
        service_id: &crate::types::ServiceId,
    ) -> Result<Vec<DeviceId>, ProtocolError>;
}

// ---------------------------------------------------------------------------
// SenderKeyStore
// ---------------------------------------------------------------------------

/// Persistence for sender keys (used in group messaging).
pub trait SenderKeyStore {
    /// Store a sender key record for the given (sender address, distribution ID) pair.
    fn store_sender_key(
        &self,
        sender: &ProtocolAddress,
        distribution_id: uuid::Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), ProtocolError>;

    /// Load the sender key record for the given (sender address, distribution ID) pair.
    fn load_sender_key(
        &self,
        sender: &ProtocolAddress,
        distribution_id: uuid::Uuid,
    ) -> Result<Option<SenderKeyRecord>, ProtocolError>;
}
