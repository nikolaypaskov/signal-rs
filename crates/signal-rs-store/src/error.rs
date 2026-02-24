//! Store error types.

use signal_rs_protocol::ProtocolError;

/// Errors that can occur in the storage layer.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// An error from the underlying SQLite database.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// An error from the protocol layer.
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    /// The requested item was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// The stored data is invalid or could not be deserialized.
    #[error("invalid data: {0}")]
    InvalidData(String),

    /// A migration error occurred.
    #[error("migration error: {0}")]
    Migration(String),

    /// The database passphrase is incorrect.
    #[error("wrong passphrase: could not decrypt database")]
    WrongPassphrase,

    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience alias for store results.
pub type Result<T> = std::result::Result<T, StoreError>;
