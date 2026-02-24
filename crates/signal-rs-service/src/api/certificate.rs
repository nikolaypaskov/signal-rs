//! Sender certificate API.
//!
//! Used for sealed sender (unidentified delivery):
//! - GET /v1/certificate/delivery -- get a sender certificate for unidentified sending
//! - GET /v1/certificate/auth/group -- get group auth credentials (see groups_v2)

use serde::Deserialize;
use tracing::debug;

use crate::error::Result;
use crate::net::http::HttpClient;

/// A sender certificate as returned by the server.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SenderCertificateResponse {
    /// The base64-encoded serialized sender certificate.
    ///
    /// This certificate binds the sender's UUID, E.164, device ID, and identity key
    /// to a server-signed certificate. It is included in sealed-sender messages so
    /// the recipient can verify the sender without the server knowing who sent what.
    pub certificate: String,
}

/// API client for certificate endpoints.
pub struct CertificateApi<'a> {
    /// The HTTP client.
    http: &'a HttpClient,
}

impl<'a> CertificateApi<'a> {
    /// Create a new certificate API client.
    pub fn new(http: &'a HttpClient) -> Self {
        Self { http }
    }

    /// Get a sender certificate for sealed-sender delivery.
    ///
    /// GET /v1/certificate/delivery?includeE164={include_e164}
    ///
    /// If `include_e164` is true, the certificate will contain the sender's
    /// phone number. If false, the certificate will only contain the sender's
    /// UUID, providing stronger anonymity (the recipient won't see the phone number).
    ///
    /// The returned certificate is signed by the server and has a limited validity
    /// period (typically 24 hours). Clients should cache the certificate and refresh
    /// it before it expires.
    pub async fn get_sender_certificate(
        &self,
        include_e164: bool,
    ) -> Result<SenderCertificateResponse> {
        let path = format!("/v1/certificate/delivery?includeE164={include_e164}");
        debug!(include_e164 = include_e164, "fetching sender certificate");
        self.http.get_json(&path).await
    }
}
