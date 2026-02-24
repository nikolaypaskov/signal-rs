//! Manager error types.

use signal_rs_protocol::ProtocolError;
use signal_rs_service::error::ServiceError;
use signal_rs_store::StoreError;

/// Errors that can occur in the manager layer.
#[derive(Debug, thiserror::Error)]
pub enum ManagerError {
    /// An error from the service layer (network, API, etc.).
    #[error("service error: {0}")]
    Service(#[from] ServiceError),

    /// An error from the storage layer (database).
    #[error("store error: {0}")]
    Store(#[from] StoreError),

    /// An error from the protocol layer (crypto, sessions).
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    /// The account is not registered (operation requires registration).
    #[error("account is not registered")]
    NotRegistered,

    /// The provided phone number is invalid.
    #[error("invalid phone number: {0}")]
    InvalidPhoneNumber(String),

    /// The specified group is invalid or not found.
    #[error("invalid group: {0}")]
    InvalidGroup(String),

    /// The attachment exceeds the maximum allowed size.
    #[error("attachment too large: {size} bytes (max {max} bytes)")]
    AttachmentTooLarge {
        /// The actual size of the attachment.
        size: u64,
        /// The maximum allowed size.
        max: u64,
    },

    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A cryptographic operation failed (AES, HMAC, Argon2, HKDF, etc.).
    #[error("crypto error: {0}")]
    CryptoError(String),

    /// The caller does not have permission for the requested operation.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// A catch-all error for miscellaneous failures.
    #[error("{0}")]
    Other(String),
}

/// Convenience alias for manager results.
pub type Result<T> = std::result::Result<T, ManagerError>;
