//! Storage Service API.
//!
//! The Storage Service stores encrypted contact, group, and account records.
//! It is used for syncing data across linked devices.
//!
//! The storage service runs on a separate host (storage.signal.org) and uses
//! its own credentials obtained from `GET /v1/storage/auth` on the chat server.
//!
//! Endpoints (base: https://storage.signal.org):
//! - GET    /v1/storage/manifest         -- get the storage manifest
//! - PUT    /v1/storage/manifest         -- write the storage manifest
//! - PUT    /v1/storage/read             -- read specific storage records
//! - PUT    /v1/storage                  -- write storage records
//! - DELETE /v1/storage                  -- delete storage records
//! - GET    /v1/storage/manifest/version/{version} -- get manifest if newer

use base64::Engine;
use bytes::Bytes;
use prost::Message;
use serde::Deserialize;
use tracing::debug;

use signal_rs_protos::ReadOperation;

use crate::error::{Result, ServiceError};
use crate::net::http::HttpClient;


/// The storage manifest version.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageManifestVersion {
    /// The manifest version number.
    pub version: u64,
}

/// Credentials for the storage service, obtained from the chat server.
#[derive(Debug, Clone, Deserialize)]
pub struct StorageServiceCredentials {
    /// The storage service username.
    pub username: String,
    /// The storage service password.
    pub password: String,
}

/// Fetch storage service credentials from the chat server.
///
/// GET /v1/storage/auth (on chat.signal.org, with account credentials)
pub async fn get_storage_auth(http: &HttpClient) -> Result<StorageServiceCredentials> {
    debug!("fetching storage service credentials");
    http.get_json("/v1/storage/auth").await
}

/// API client for the storage service.
pub struct StorageApi<'a> {
    /// The HTTP client (used for its TLS config and reqwest inner client).
    http: &'a HttpClient,
    /// The storage service base URL (e.g. "https://storage.signal.org").
    base_url: String,
    /// Storage-specific credentials (username:password for Basic auth).
    credentials: StorageServiceCredentials,
}

impl<'a> StorageApi<'a> {
    /// Create a new storage API client with storage-specific credentials.
    pub fn new(http: &'a HttpClient, credentials: StorageServiceCredentials) -> Self {
        let base_url = http.config().storage_url.clone();
        Self { http, base_url, credentials }
    }

    /// Build a full URL for a storage service path.
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Build the Basic auth header value for storage service requests.
    fn auth_header(&self) -> String {
        use base64::engine::general_purpose::STANDARD;
        let encoded = STANDARD.encode(format!("{}:{}", self.credentials.username, self.credentials.password));
        format!("Basic {encoded}")
    }

    /// Get the storage manifest (version + list of record keys).
    ///
    /// GET /v1/storage/manifest
    ///
    /// Returns the raw protobuf-encoded StorageManifest.
    pub async fn get_manifest(&self) -> Result<Vec<u8>> {
        debug!("fetching storage manifest");
        let bytes = self.http.get_abs_with_auth(
            &self.url("/v1/storage/manifest"),
            &self.auth_header(),
        ).await?;
        Ok(bytes.to_vec())
    }

    /// Get the storage manifest only if there is a newer version.
    ///
    /// GET /v1/storage/manifest/version/{current_version}
    ///
    /// Returns `Ok(Some(bytes))` if a newer manifest exists,
    /// `Ok(None)` if the server returns 204 (no newer version).
    pub async fn get_manifest_if_different(&self, current_version: u64) -> Result<Option<Vec<u8>>> {
        let path = format!("/v1/storage/manifest/version/{current_version}");
        debug!(
            version = current_version,
            "fetching storage manifest if different"
        );
        match self.http.get_abs_with_auth(&self.url(&path), &self.auth_header()).await {
            Ok(bytes) => Ok(Some(bytes.to_vec())),
            Err(ServiceError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Write/update the storage manifest.
    ///
    /// PUT /v1/storage/manifest
    ///
    /// The body is a protobuf-encoded WriteOperation message.
    pub async fn write_manifest(&self, manifest: &[u8]) -> Result<()> {
        debug!(size = manifest.len(), "writing storage manifest");
        self.http
            .put_abs_protobuf_with_auth(
                &self.url("/v1/storage/manifest"),
                Bytes::copy_from_slice(manifest),
                &self.auth_header(),
            )
            .await?;
        Ok(())
    }

    /// Read specific storage records by their keys.
    ///
    /// PUT /v1/storage/read (yes, it's PUT with a protobuf body)
    ///
    /// Returns the raw protobuf-encoded StorageItems response.
    pub async fn read_records(&self, keys: &[Vec<u8>]) -> Result<Vec<u8>> {
        let read_op = ReadOperation {
            read_key: keys.to_vec(),
        };
        let body = read_op.encode_to_vec();
        debug!(count = keys.len(), body_len = body.len(), "reading storage records");

        let response_bytes = self
            .http
            .put_abs_protobuf_with_auth(
                &self.url("/v1/storage/read"),
                Bytes::from(body),
                &self.auth_header(),
            )
            .await?;

        Ok(response_bytes.to_vec())
    }

    /// Write new storage records.
    ///
    /// PUT /v1/storage
    ///
    /// The body is a protobuf-encoded WriteOperation.
    pub async fn write_records(&self, write_op: &[u8]) -> Result<()> {
        debug!(body_len = write_op.len(), "writing storage records");
        self.http.put_abs_protobuf_with_auth(
            &self.url("/v1/storage"),
            Bytes::copy_from_slice(write_op),
            &self.auth_header(),
        ).await?;
        Ok(())
    }

    /// Delete all storage records (reset).
    ///
    /// DELETE /v1/storage
    pub async fn delete_records(&self) -> Result<()> {
        debug!("deleting all storage records");
        self.http.delete_abs_with_auth(&self.url("/v1/storage"), &self.auth_header()).await
    }

    /// Reset the storage service (delete all records and manifest).
    ///
    /// DELETE /v1/storage
    ///
    /// This is used when re-initializing storage from scratch.
    pub async fn reset_storage(&self) -> Result<()> {
        debug!("resetting storage service");
        self.http.delete_abs_with_auth(&self.url("/v1/storage"), &self.auth_header()).await
    }
}
