//! HTTP client for the Signal REST API.
//!
//! Wraps `reqwest::Client` with Signal-specific authentication headers,
//! user-agent strings, and error handling.

use bytes::Bytes;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::time::Duration;

use crate::config::ServiceConfig;
use crate::credentials::ServiceCredentials;
use crate::error::{Result, ServiceError};

/// User-Agent string mimicking an official Signal client to avoid server rejection.
const USER_AGENT: &str = "Signal-Android/7.26.3 signal-rs/0.1.0";

/// Timeout for establishing a TCP+TLS connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for the entire request (connect + send + receive response).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Build a rustls root certificate store that trusts both Signal's root CA
/// and the system's native certificates.
fn build_root_cert_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();

    // Add Signal's self-signed root CA.
    let mut reader = std::io::BufReader::new(super::websocket::SIGNAL_ROOT_CA_PEM);
    for cert in rustls_pemfile::certs(&mut reader).flatten() {
        roots.add(cert).ok();
    }

    // Add system native certs.
    for cert in rustls_native_certs::load_native_certs().certs {
        roots.add(cert).ok();
    }

    roots
}

/// An HTTP client configured for the Signal service.
pub struct HttpClient {
    /// The underlying reqwest client.
    inner: reqwest::Client,
    /// The service configuration (base URLs, etc.).
    config: ServiceConfig,
    /// The credentials used for authenticated requests.
    credentials: Option<ServiceCredentials>,
}

impl HttpClient {
    /// Create a new HTTP client for the given config and credentials.
    pub fn new(config: ServiceConfig, credentials: Option<ServiceCredentials>) -> Result<Self> {
        // Ensure a crypto provider is installed (ring).
        let _ = rustls::crypto::ring::default_provider().install_default();

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(build_root_cert_store())
            .with_no_client_auth();

        let inner = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .use_preconfigured_tls(tls_config)
            .build()
            .map_err(ServiceError::Network)?;

        Ok(Self {
            inner,
            config,
            credentials,
        })
    }

    /// Return a reference to the service configuration.
    pub fn config(&self) -> &ServiceConfig {
        &self.config
    }

    // -----------------------------------------------------------------------
    // Raw request methods
    // -----------------------------------------------------------------------

    /// Perform an authenticated GET request to the given path.
    pub async fn get(&self, path: &str) -> Result<Bytes> {
        let url = self.url(path);
        let mut req = self.inner.get(&url);
        if let Some(auth) = self.authorization_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;
        Self::check_status(status, &String::from_utf8_lossy(&body))?;
        Ok(body)
    }

    /// Perform an authenticated GET request against the storage/groups host.
    ///
    /// Identical to [`get`] but uses `storage_url` as the base URL.
    /// Groups v2 API endpoints live on `storage.signal.org`.
    pub async fn get_from_storage(&self, path: &str) -> Result<Bytes> {
        let url = self.storage_path_url(path);
        let mut req = self.inner.get(&url);
        if let Some(auth) = self.authorization_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;
        Self::check_status(status, &String::from_utf8_lossy(&body))?;
        Ok(body)
    }

    /// Perform an authenticated PUT request against the storage/groups host.
    pub async fn put_to_storage(&self, path: &str, body: Bytes) -> Result<Bytes> {
        let url = self.storage_path_url(path);
        let mut req = self.inner.put(&url)
            .header("Content-Type", "application/octet-stream")
            .body(body);
        if let Some(auth) = self.authorization_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let resp_body = resp.bytes().await?;
        Self::check_status(status, &String::from_utf8_lossy(&resp_body))?;
        Ok(resp_body)
    }

    /// Perform an authenticated PATCH request against the storage/groups host.
    pub async fn patch_storage(&self, path: &str, body: Bytes) -> Result<Bytes> {
        let url = self.storage_path_url(path);
        let mut req = self.inner.patch(&url)
            .header("Content-Type", "application/octet-stream")
            .body(body);
        if let Some(auth) = self.authorization_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let resp_body = resp.bytes().await?;
        Self::check_status(status, &String::from_utf8_lossy(&resp_body))?;
        Ok(resp_body)
    }

    /// GET a JSON response from the storage/groups host, deserializing into `T`.
    pub async fn get_json_from_storage<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = self.storage_path_url(path);
        let mut req = self.inner.get(&url)
            .header("Accept", "application/json");
        if let Some(auth) = self.authorization_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Self::check_status(status, &text)?;
        serde_json::from_str(&text).map_err(ServiceError::Json)
    }

    /// Perform an authenticated POST request with a raw body.
    pub async fn post(&self, path: &str, body: Bytes) -> Result<Bytes> {
        let url = self.url(path);
        let mut req = self.inner.post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(body);
        if let Some(auth) = self.authorization_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let resp_body = resp.bytes().await?;
        Self::check_status(status, &String::from_utf8_lossy(&resp_body))?;
        Ok(resp_body)
    }

    /// Perform an authenticated PUT request with a raw body.
    pub async fn put(&self, path: &str, body: Bytes) -> Result<Bytes> {
        let url = self.url(path);
        let mut req = self.inner.put(&url)
            .header("Content-Type", "application/octet-stream")
            .body(body);
        if let Some(auth) = self.authorization_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let resp_body = resp.bytes().await?;
        Self::check_status(status, &String::from_utf8_lossy(&resp_body))?;
        Ok(resp_body)
    }

    /// Perform an authenticated DELETE request.
    pub async fn delete(&self, path: &str) -> Result<()> {
        let url = self.url(path);
        let mut req = self.inner.delete(&url);
        if let Some(auth) = self.authorization_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Self::check_status(status, &body)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // JSON convenience methods
    // -----------------------------------------------------------------------

    /// GET a JSON response, deserializing it into `T`.
    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = self.url(path);
        tracing::debug!(url = %url, "GET JSON request");
        let mut req = self.inner.get(&url)
            .header("Accept", "application/json");
        if let Some(auth) = self.authorization_header() {
            // Log username portion only (not the full header which contains the password)
            if let Some(creds) = &self.credentials {
                tracing::debug!(username = %creds.username().unwrap_or_default(), "using auth credentials");
            }
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Self::check_status(status, &text)?;
        serde_json::from_str(&text).map_err(ServiceError::Json)
    }

    /// PUT a JSON body and deserialize the JSON response into `T`.
    pub async fn put_json<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let url = self.url(path);
        tracing::debug!(url = %url, "PUT JSON request");
        let mut req = self.inner.put(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(body);
        if let Some(auth) = self.authorization_header() {
            if let Some(creds) = &self.credentials {
                tracing::debug!(username = %creds.username().unwrap_or_default(), "using auth credentials");
            }
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Self::check_status(status, &text)?;
        serde_json::from_str(&text).map_err(ServiceError::Json)
    }

    /// POST a JSON body and deserialize the JSON response into `T`.
    pub async fn post_json<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let url = self.url(path);
        let mut req = self.inner.post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(body);
        if let Some(auth) = self.authorization_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Self::check_status(status, &text)?;
        serde_json::from_str(&text).map_err(ServiceError::Json)
    }

    /// POST a JSON body without authentication and deserialize the response.
    pub async fn post_json_unauthenticated<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let url = self.url(path);
        let resp = self.inner.post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Self::check_status(status, &text)?;
        serde_json::from_str(&text).map_err(ServiceError::Json)
    }

    /// PATCH a JSON body and deserialize the JSON response into `T`.
    pub async fn patch_json<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let url = self.url(path);
        let mut req = self.inner.patch(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(body);
        if let Some(auth) = self.authorization_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Self::check_status(status, &text)?;
        serde_json::from_str(&text).map_err(ServiceError::Json)
    }

    /// PUT a JSON body without expecting a response body.
    pub async fn put_json_no_response<B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<()> {
        let url = self.url(path);
        let mut req = self.inner.put(&url)
            .header("Content-Type", "application/json")
            .json(body);
        if let Some(auth) = self.authorization_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Self::check_status(status, &text)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Unauthenticated and specialized methods
    // -----------------------------------------------------------------------

    /// PUT a JSON body without authentication and deserialize the response.
    pub async fn put_json_unauthenticated<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let url = self.url(path);
        let resp = self.inner.put(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Self::check_status(status, &text)?;
        serde_json::from_str(&text).map_err(ServiceError::Json)
    }

    /// GET without authentication, returning raw bytes. Useful for CDN downloads.
    pub async fn get_unauthenticated(&self, url: &str) -> Result<Bytes> {
        let resp = self.inner.get(url).send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;
        Self::check_status(status, &String::from_utf8_lossy(&body))?;
        Ok(body)
    }

    /// PUT raw bytes to a URL with the given content type.
    pub async fn put_bytes(&self, url: &str, data: &[u8], content_type: &str) -> Result<()> {
        let resp = self.inner.put(url)
            .header("Content-Type", content_type)
            .body(data.to_vec())
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Self::check_status(status, &text)?;
        Ok(())
    }

    /// Perform an authenticated PATCH request with a raw body.
    pub async fn patch(&self, path: &str, body: Bytes) -> Result<Bytes> {
        let url = self.url(path);
        let mut req = self.inner.patch(&url)
            .header("Content-Type", "application/octet-stream")
            .body(body);
        if let Some(auth) = self.authorization_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let resp_body = resp.bytes().await?;
        Self::check_status(status, &String::from_utf8_lossy(&resp_body))?;
        Ok(resp_body)
    }

    /// PUT a JSON body with an unidentified access key instead of the
    /// standard Authorization header.  Used for sealed-sender delivery.
    ///
    /// The `Unidentified-Access-Key` header replaces `Authorization` so that
    /// the server cannot identify the sender.
    pub async fn put_json_with_unidentified_access<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
        unidentified_access_key: &str,
    ) -> Result<T> {
        let url = self.url(path);
        let resp = self.inner.put(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Unidentified-Access-Key", unidentified_access_key)
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Self::check_status(status, &text)?;
        serde_json::from_str(&text).map_err(ServiceError::Json)
    }

    /// Perform an authenticated DELETE request with a JSON body.
    pub async fn delete_with_json_body<B: Serialize>(&self, path: &str, body: &B) -> Result<()> {
        let url = self.url(path);
        let mut req = self.inner.delete(&url)
            .header("Content-Type", "application/json")
            .json(body);
        if let Some(auth) = self.authorization_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Self::check_status(status, &text)?;
        Ok(())
    }

    /// Perform a GET request with a custom header.
    pub async fn get_with_header(
        &self,
        path: &str,
        header_name: &str,
        header_value: &str,
    ) -> Result<Bytes> {
        let url = self.url(path);
        let mut req = self.inner.get(&url)
            .header(header_name, header_value);
        if let Some(auth) = self.authorization_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;
        Self::check_status(status, &String::from_utf8_lossy(&body))?;
        Ok(body)
    }

    /// GET a JSON response with a custom header.
    pub async fn get_json_with_header<T: DeserializeOwned>(
        &self,
        path: &str,
        header_name: &str,
        header_value: &str,
    ) -> Result<T> {
        let url = self.url(path);
        let mut req = self.inner.get(&url)
            .header("Accept", "application/json")
            .header(header_name, header_value);
        if let Some(auth) = self.authorization_header() {
            req = req.header("Authorization", auth);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Self::check_status(status, &text)?;
        serde_json::from_str(&text).map_err(ServiceError::Json)
    }

    /// GET a JSON response without authentication.
    pub async fn get_json_unauthenticated<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = self.url(path);
        let resp = self.inner.get(&url)
            .header("Accept", "application/json")
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Self::check_status(status, &text)?;
        serde_json::from_str(&text).map_err(ServiceError::Json)
    }

    // -----------------------------------------------------------------------
    // URL helpers
    // -----------------------------------------------------------------------

    /// Return the CDN base URL for the given CDN number.
    pub fn cdn_url(&self, cdn_number: u32) -> String {
        self.config
            .cdn_urls
            .get(&cdn_number)
            .cloned()
            .unwrap_or_else(|| {
                // Fallback: construct from pattern
                format!("https://cdn{cdn_number}.signal.org")
            })
    }

    /// Return the storage service base URL.
    pub fn storage_url(&self) -> String {
        self.config.storage_url.clone()
    }

    // -----------------------------------------------------------------------
    // Absolute-URL request methods (for external services like storage)
    // -----------------------------------------------------------------------

    /// Perform a GET request to an absolute URL with a custom auth header.
    pub async fn get_abs_with_auth(&self, url: &str, auth: &str) -> Result<Bytes> {
        let resp = self.inner.get(url)
            .header("Authorization", auth)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.bytes().await?;
        Self::check_status(status, &String::from_utf8_lossy(&body))?;
        Ok(body)
    }

    /// Perform a PUT request with a raw body to an absolute URL with a custom auth header.
    pub async fn put_abs_with_auth(&self, url: &str, body: Bytes, auth: &str) -> Result<Bytes> {
        let resp = self.inner.put(url)
            .header("Content-Type", "application/octet-stream")
            .header("Authorization", auth)
            .body(body)
            .send()
            .await?;
        let status = resp.status();
        let resp_body = resp.bytes().await?;
        Self::check_status(status, &String::from_utf8_lossy(&resp_body))?;
        Ok(resp_body)
    }

    /// Perform a PUT request with a protobuf body to an absolute URL with a custom auth header.
    pub async fn put_abs_protobuf_with_auth(&self, url: &str, body: Bytes, auth: &str) -> Result<Bytes> {
        let resp = self.inner.put(url)
            .header("Content-Type", "application/x-protobuf")
            .header("Authorization", auth)
            .body(body)
            .send()
            .await?;
        let status = resp.status();
        let resp_body = resp.bytes().await?;
        Self::check_status(status, &String::from_utf8_lossy(&resp_body))?;
        Ok(resp_body)
    }

    /// Perform a DELETE request to an absolute URL with a custom auth header.
    pub async fn delete_abs_with_auth(&self, url: &str, auth: &str) -> Result<()> {
        let resp = self.inner.delete(url)
            .header("Authorization", auth)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Self::check_status(status, &body)?;
        Ok(())
    }

    /// Perform a DELETE request with a JSON body to an absolute URL with a custom auth header.
    pub async fn delete_abs_with_json_body_and_auth<B: Serialize>(&self, url: &str, body: &B, auth: &str) -> Result<()> {
        let resp = self.inner.delete(url)
            .header("Content-Type", "application/json")
            .header("Authorization", auth)
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Self::check_status(status, &text)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Build the full URL from a path (uses service_url as base).
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.config.service_url, path)
    }

    /// Build the full URL using the storage/groups base URL instead of service_url.
    fn storage_path_url(&self, path: &str) -> String {
        format!("{}{}", self.config.storage_url, path)
    }

    /// Build the authorization header value, if credentials are available.
    fn authorization_header(&self) -> Option<String> {
        self.credentials
            .as_ref()
            .and_then(|c| c.authorization())
            .map(|a| a.as_header_value())
    }

    /// Map a reqwest response status to a `ServiceError` if it indicates failure.
    fn check_status(status: reqwest::StatusCode, body: &str) -> Result<()> {
        if status.is_success() {
            return Ok(());
        }
        // Truncate body to avoid leaking tokens or large payloads into logs/errors.
        let truncated: &str = if body.len() > 512 { &body[..512] } else { body };
        tracing::debug!(status = status.as_u16(), body = %truncated, "HTTP error response");
        match status.as_u16() {
            401 | 403 => {
                tracing::warn!(status = status.as_u16(), body = %truncated, "authentication failed");
                Err(ServiceError::Authentication)
            }
            404 => Err(ServiceError::NotFound),
            409 => Err(ServiceError::Conflict),
            410 => Err(ServiceError::Gone),
            413 | 429 => {
                // Try to parse Retry-After header value from body (server may embed it)
                let seconds = truncated.parse::<u64>().unwrap_or(60);
                Err(ServiceError::RateLimited(Duration::from_secs(seconds)))
            }
            423 => {
                // Registration locked (PIN required)
                let seconds = truncated.parse::<u64>().unwrap_or(3600);
                Err(ServiceError::RegistrationLocked(Duration::from_secs(seconds)))
            }
            428 => Err(ServiceError::CaptchaRequired),
            500..=599 => Err(ServiceError::ServerError(truncated.to_string())),
            code => Err(ServiceError::Http(code, truncated.to_string())),
        }
    }
}
