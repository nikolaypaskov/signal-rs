//! Service error types.

use std::time::Duration;

/// Errors that can occur during communication with the Signal service.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// A network-level error (DNS failure, connection refused, etc.).
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    /// A WebSocket-level error.
    #[error("websocket error: {0}")]
    WebSocket(String),

    /// The server returned an HTTP error response.
    #[error("HTTP {0}: {1}")]
    Http(u16, String),

    /// A protobuf encoding/decoding error.
    #[error("protocol error: {0}")]
    Protocol(#[from] prost::DecodeError),

    /// Authentication failed (HTTP 401 or 403).
    #[error("authentication failed")]
    Authentication,

    /// The server rate-limited us; retry after the given duration.
    #[error("rate limited, retry after {0:?}")]
    RateLimited(Duration),

    /// The requested resource was not found (HTTP 404).
    #[error("not found")]
    NotFound,

    /// A conflict occurred (HTTP 409), usually stale device list.
    #[error("conflict")]
    Conflict,

    /// A resource is gone (HTTP 410), usually stale sessions.
    #[error("gone (stale session)")]
    Gone,

    /// A server-side error with a descriptive message.
    #[error("server error: {0}")]
    ServerError(String),

    /// The request timed out.
    #[error("request timed out")]
    Timeout,

    /// The server returned an unexpected or malformed response.
    #[error("invalid response: {0}")]
    InvalidResponse(String),

    /// An error occurred in the provisioning cipher (ECDH/HKDF/AES).
    #[error("provisioning cipher error: {0}")]
    ProvisioningCipher(String),

    /// The server requires a captcha challenge to proceed.
    #[error("captcha required")]
    CaptchaRequired,

    /// The account is registration-locked (PIN required).
    #[error("registration locked, retry after {0:?}")]
    RegistrationLocked(Duration),

    /// JSON serialization/deserialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

impl ServiceError {
    /// Returns true for transient errors that may succeed on retry
    /// (network errors and 5xx server errors).
    pub fn is_transient(&self) -> bool {
        matches!(self, ServiceError::Network(_) | ServiceError::ServerError(_) | ServiceError::Timeout)
    }
}

/// Convenience alias for service results.
pub type Result<T> = std::result::Result<T, ServiceError>;
