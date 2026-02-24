//! Groups v2 API.
//!
//! Endpoints for creating, fetching, and modifying Groups v2:
//! - GET    /v1/groups/                  -- get group state
//! - PUT    /v1/groups/                  -- create a group
//! - PATCH  /v1/groups/                  -- update a group
//! - GET    /v1/groups/logs/{from}       -- get group change logs
//! - GET    /v1/groups/joined_at_version -- get the version at which we joined
//! - GET    /v1/certificate/auth/group   -- get group auth credentials
//!
//! Base URL: https://storage.signal.org (groups endpoint lives on storage service)

use base64::Engine;
use bytes::Bytes;
use serde::Deserialize;
use tracing::debug;

use crate::error::Result;
use crate::net::http::HttpClient;

/// Credentials for authenticating group requests.
///
/// Group requests use a separate authorization mechanism based on
/// zkgroup auth credentials, not the normal account credentials.
pub struct GroupAuthCredential {
    /// The base64-encoded auth credential token.
    pub token: String,
}

/// Response containing group auth credentials from the server.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupAuthCredentialResponse {
    /// The list of auth credential entries (one per day, covering the requested range).
    pub credentials: Vec<GroupAuthCredentialEntry>,
}

/// A single group auth credential entry for a specific day.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupAuthCredentialEntry {
    /// The day (in seconds since epoch, truncated to midnight UTC).
    pub redemption_time: u64,
    /// The base64-encoded credential.
    pub credential: String,
}

/// The version at which the local account joined the group.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinedAtVersionResponse {
    /// The group revision at which we joined.
    pub version: u32,
}

/// External group state used for joining via invite link.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupExternalCredential {
    /// The base64-encoded token for external group access.
    pub token: String,
}

/// API client for Groups v2 endpoints.
pub struct GroupsV2Api<'a> {
    /// The HTTP client.
    http: &'a HttpClient,
}

impl<'a> GroupsV2Api<'a> {
    /// Create a new Groups v2 API client.
    pub fn new(http: &'a HttpClient) -> Self {
        Self { http }
    }

    /// Get auth credentials for group operations.
    ///
    /// GET /v1/certificate/auth/group?redemptionStartSeconds={start}&redemptionEndSeconds={end}
    ///
    /// Returns credentials for a range of days. These are used to authenticate
    /// group API requests without revealing the account identity to the group server.
    pub async fn get_group_auth_credentials(
        &self,
        redemption_start_seconds: u64,
        redemption_end_seconds: u64,
    ) -> Result<GroupAuthCredentialResponse> {
        let path = format!(
            "/v1/certificate/auth/group?redemptionStartSeconds={}&redemptionEndSeconds={}",
            redemption_start_seconds, redemption_end_seconds
        );
        debug!(
            start = redemption_start_seconds,
            end = redemption_end_seconds,
            "fetching group auth credentials"
        );
        self.http.get_json(&path).await
    }

    /// Get the current group state.
    ///
    /// GET /v1/groups/  (on storage.signal.org)
    /// Authorization: basic account credentials
    pub async fn get_group(&self, group_secret_params: &[u8]) -> Result<Vec<u8>> {
        debug!("fetching group state");
        let path = format!(
            "/v1/groups/?groupSecretParams={}",
            base64::engine::general_purpose::STANDARD.encode(group_secret_params)
        );
        let bytes = self.http.get_from_storage(&path).await?;
        Ok(bytes.to_vec())
    }

    /// Create a new group.
    ///
    /// PUT /v1/groups/  (on storage.signal.org)
    pub async fn create_group(&self, group: &[u8]) -> Result<()> {
        debug!("creating new group");
        self.http
            .put_to_storage("/v1/groups/", Bytes::copy_from_slice(group))
            .await?;
        Ok(())
    }

    /// Modify a group by applying a set of change actions.
    ///
    /// PATCH /v1/groups/  (on storage.signal.org)
    ///
    /// The body is a serialized GroupChange.Actions protobuf.
    pub async fn modify_group(&self, actions: &[u8]) -> Result<Vec<u8>> {
        debug!("modifying group");
        let bytes = self
            .http
            .patch_storage("/v1/groups/", Bytes::copy_from_slice(actions))
            .await?;
        Ok(bytes.to_vec())
    }

    /// Get group change logs since a given version.
    ///
    /// GET /v1/groups/logs/{from_version}  (on storage.signal.org)
    pub async fn get_group_logs(
        &self,
        from_version: u32,
        group_secret_params: &[u8],
    ) -> Result<Vec<u8>> {
        let path = format!(
            "/v1/groups/logs/{}?groupSecretParams={}",
            from_version,
            base64::engine::general_purpose::STANDARD.encode(group_secret_params)
        );
        debug!(from_version = from_version, "fetching group logs");
        let bytes = self.http.get_from_storage(&path).await?;
        Ok(bytes.to_vec())
    }

    /// Get the group join info (for joining via invite link).
    ///
    /// GET /v1/groups/join/{invite_link_password}  (on storage.signal.org)
    pub async fn get_group_join_info(&self, invite_link_password: &[u8]) -> Result<Vec<u8>> {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(invite_link_password);
        let path = format!("/v1/groups/join/{encoded}");
        debug!("fetching group join info");
        let bytes = self.http.get_from_storage(&path).await?;
        Ok(bytes.to_vec())
    }

    /// Get the revision at which we joined the group.
    ///
    /// GET /v1/groups/joined_at_version  (on storage.signal.org)
    pub async fn get_joined_at_version(
        &self,
        group_secret_params: &[u8],
    ) -> Result<JoinedAtVersionResponse> {
        let path = format!(
            "/v1/groups/joined_at_version?groupSecretParams={}",
            base64::engine::general_purpose::STANDARD.encode(group_secret_params)
        );
        debug!("fetching joined_at_version");
        self.http.get_json_from_storage(&path).await
    }

    /// Get an external group credential (for invite link operations).
    ///
    /// GET /v1/groups/token  (on storage.signal.org)
    pub async fn get_group_external_credential(
        &self,
        group_secret_params: &[u8],
    ) -> Result<GroupExternalCredential> {
        let path = format!(
            "/v1/groups/token?groupSecretParams={}",
            base64::engine::general_purpose::STANDARD.encode(group_secret_params)
        );
        debug!("fetching group external credential");
        self.http.get_json_from_storage(&path).await
    }
}
