//! Protocol error types.

/// Errors that can occur during Signal Protocol operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProtocolError {
    /// The provided key material is invalid or malformed.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// A cryptographic signature failed verification.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// The remote identity key is not trusted.
    #[error("untrusted identity: {0}")]
    UntrustedIdentity(String),

    /// A message with this counter has already been received.
    #[error("duplicate message")]
    DuplicateMessage,

    /// The message could not be decoded or decrypted.
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// No session exists for the given address.
    #[error("no session for {0}")]
    NoSession(String),

    /// The key material is outdated and should be refreshed.
    #[error("stale key material: {0}")]
    StaleKeyMaterial(String),

    /// A session was expected but not found.
    #[error("session not found: {0}")]
    SessionNotFound(String),

    /// The protocol state machine is in an unexpected state.
    #[error("invalid state: {0}")]
    InvalidState(String),

    /// An error occurred in the underlying storage layer.
    #[error("storage error: {0}")]
    StorageError(String),
}

/// Convenience alias for protocol results.
pub type Result<T> = std::result::Result<T, ProtocolError>;
