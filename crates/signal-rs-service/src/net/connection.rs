//! Connection manager — multiplexes HTTP and WebSocket connections.
//!
//! Provides a single entry point for obtaining authenticated/unauthenticated
//! WebSocket connections and HTTP clients, handling reconnection logic.

use crate::config::ServiceConfig;
use crate::credentials::ServiceCredentials;
use crate::error::Result;
use crate::net::http::HttpClient;
use crate::net::websocket::SignalWebSocket;

/// Manages connections to the Signal service.
///
/// Holds the configuration and optional credentials, and creates
/// HTTP clients and WebSocket connections as needed.
pub struct ConnectionManager {
    /// The service configuration.
    config: ServiceConfig,
    /// The credentials for authenticated connections (None pre-registration).
    credentials: Option<ServiceCredentials>,
}

impl ConnectionManager {
    /// Create a new connection manager with credentials.
    pub fn new(config: ServiceConfig, credentials: ServiceCredentials) -> Self {
        Self {
            config,
            credentials: Some(credentials),
        }
    }

    /// Create a new connection manager without credentials (pre-registration).
    pub fn unauthenticated(config: ServiceConfig) -> Self {
        Self {
            config,
            credentials: None,
        }
    }

    /// Return a reference to the service configuration.
    pub fn config(&self) -> &ServiceConfig {
        &self.config
    }

    /// Return a reference to the service credentials, if available.
    pub fn credentials(&self) -> Option<&ServiceCredentials> {
        self.credentials.as_ref()
    }

    /// Set (or replace) the credentials.
    pub fn set_credentials(&mut self, credentials: ServiceCredentials) {
        self.credentials = Some(credentials);
    }

    /// Get an authenticated WebSocket connection.
    ///
    /// The WebSocket is connected to `wss://chat.signal.org/v1/websocket/`
    /// with credentials appended as query parameters.
    pub async fn get_authenticated_ws(&self) -> Result<SignalWebSocket> {
        let url = self.config.ws_url("/v1/websocket/");
        SignalWebSocket::connect(&url, self.credentials.as_ref()).await
    }

    /// Get an unauthenticated WebSocket connection.
    ///
    /// Used for receiving sealed-sender messages.
    pub async fn get_unauthenticated_ws(&self) -> Result<SignalWebSocket> {
        let url = self.config.ws_url("/v1/websocket/");
        SignalWebSocket::connect(&url, None).await
    }

    /// Get a provisioning WebSocket connection.
    ///
    /// Used during device linking — connects to `/v1/websocket/provisioning/`.
    pub async fn get_provisioning_ws(&self) -> Result<SignalWebSocket> {
        let url = self.config.ws_url("/v1/websocket/provisioning/");
        SignalWebSocket::connect(&url, None).await
    }

    /// Get an HTTP client configured with the current credentials.
    pub fn get_http(&self) -> Result<HttpClient> {
        HttpClient::new(self.config.clone(), self.credentials.clone())
    }

    /// Get an unauthenticated HTTP client (for public endpoints).
    pub fn get_unauthenticated_http(&self) -> Result<HttpClient> {
        HttpClient::new(self.config.clone(), None)
    }
}
