//! Profile API.
//!
//! Endpoints for fetching and updating user profiles.
//!
//! - GET  /v1/profile/{identifier}                           -- fetch a profile (authenticated)
//! - GET  /v1/profile/{identifier}/{version}                 -- fetch versioned profile
//! - GET  /v1/profile/{identifier}/{version}/{credential_request} -- fetch with credential
//! - PUT  /v1/profile                                        -- set own profile
//! - PUT  /v1/profile/name/{encrypted}                       -- set encrypted profile name

use serde::{Deserialize, Serialize};
use tracing::debug;
use uuid::Uuid;

use crate::error::Result;
use crate::net::http::HttpClient;

/// A Signal user profile as returned by the server.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalProfile {
    /// The profile name (encrypted, base64).
    pub name: Option<String>,
    /// The profile about text (encrypted, base64).
    pub about: Option<String>,
    /// The profile about emoji.
    pub about_emoji: Option<String>,
    /// The avatar CDN path.
    pub avatar: Option<String>,
    /// The unidentified access mode.
    pub unidentified_access: Option<String>,
    /// Capabilities.
    pub capabilities: Option<ProfileCapabilities>,
    /// The profile badge list.
    pub badges: Vec<serde_json::Value>,
    /// The profile credential (present in versioned responses with credential request).
    pub credential: Option<String>,
    /// The payment address (encrypted, base64).
    pub payment_address: Option<String>,
}

/// Capabilities reported in a profile.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileCapabilities {
    /// Whether the user supports delete-sync.
    pub delete_sync: bool,
}

/// API client for profile endpoints.
pub struct ProfileApi<'a> {
    /// The HTTP client.
    http: &'a HttpClient,
}

impl<'a> ProfileApi<'a> {
    /// Create a new profile API client.
    pub fn new(http: &'a HttpClient) -> Self {
        Self { http }
    }

    /// Fetch a user's profile (authenticated).
    ///
    /// GET /v1/profile/{identifier}
    pub async fn get_profile(&self, identifier: &Uuid) -> Result<SignalProfile> {
        let path = format!("/v1/profile/{identifier}");
        debug!(identifier = %identifier, "fetching profile");
        self.http.get_json(&path).await
    }

    /// Fetch a user's profile with a specific profile key version.
    ///
    /// GET /v1/profile/{identifier}/{version}
    ///
    /// The version is derived from the profile key using HMAC-SHA256.
    /// This endpoint returns cached profile data associated with the given version.
    pub async fn get_versioned_profile(
        &self,
        identifier: &Uuid,
        version: &str,
    ) -> Result<SignalProfile> {
        let path = format!("/v1/profile/{identifier}/{version}");
        debug!(
            identifier = %identifier,
            version = version,
            "fetching versioned profile"
        );
        self.http.get_json(&path).await
    }

    /// Fetch a user's profile with credential request.
    ///
    /// GET /v1/profile/{identifier}/{version}/{credential_request}
    ///
    /// Returns the profile along with an ExpiringProfileKeyCredentialResponse
    /// that can be used for anonymous profile operations.
    pub async fn get_versioned_profile_with_credential(
        &self,
        identifier: &Uuid,
        version: &str,
        credential_request: &str,
    ) -> Result<SignalProfile> {
        let path = format!(
            "/v1/profile/{identifier}/{version}/{credential_request}",
        );
        debug!(
            identifier = %identifier,
            version = version,
            "fetching versioned profile with credential"
        );
        self.http.get_json(&path).await
    }

    /// Fetch a user's profile with unidentified access (sealed sender).
    ///
    /// GET /v1/profile/{identifier} with Unidentified-Access-Key header
    ///
    /// Uses the recipient's unidentified access key to fetch the profile
    /// without revealing the requester's identity.
    pub async fn get_profile_unidentified(
        &self,
        identifier: &Uuid,
        unidentified_access_key: &str,
    ) -> Result<SignalProfile> {
        let path = format!("/v1/profile/{identifier}");
        debug!(identifier = %identifier, "fetching profile (unidentified)");
        self.http
            .get_json_with_header(
                &path,
                "Unidentified-Access-Key",
                unidentified_access_key,
            )
            .await
    }

    /// Fetch a versioned profile with unidentified access (sealed sender).
    ///
    /// GET /v1/profile/{identifier}/{version} with Unidentified-Access-Key header
    pub async fn get_versioned_profile_unidentified(
        &self,
        identifier: &Uuid,
        version: &str,
        unidentified_access_key: &str,
    ) -> Result<SignalProfile> {
        let path = format!("/v1/profile/{identifier}/{version}");
        debug!(
            identifier = %identifier,
            version = version,
            "fetching versioned profile (unidentified)"
        );
        self.http
            .get_json_with_header(
                &path,
                "Unidentified-Access-Key",
                unidentified_access_key,
            )
            .await
    }

    /// Upload/update the authenticated user's profile.
    ///
    /// PUT /v1/profile
    pub async fn set_profile(&self, profile: &SetProfileRequest) -> Result<()> {
        debug!("updating profile");
        self.http.put_json_no_response("/v1/profile", profile).await
    }

    /// Download a profile avatar from the CDN.
    ///
    /// GET cdn{cdn_number}.signal.org/{path}
    ///
    /// The avatar path is obtained from the profile response.
    pub async fn get_avatar(&self, avatar_path: &str) -> Result<Vec<u8>> {
        let cdn_base = self.http.cdn_url(0);
        let url = format!("{cdn_base}/{avatar_path}");
        debug!(url = %url, "downloading profile avatar");
        let bytes = self.http.get_unauthenticated(&url).await?;
        Ok(bytes.to_vec())
    }
}

/// Request body for setting the profile.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetProfileRequest {
    /// The base64-encoded encrypted profile name.
    pub name: Option<String>,
    /// The base64-encoded encrypted about text.
    pub about: Option<String>,
    /// The about emoji.
    pub about_emoji: Option<String>,
    /// Whether to retain the existing avatar.
    pub retain_avatar: bool,
    /// The commitment for the profile key.
    pub commitment: String,
    /// The profile key version string.
    pub version: Option<String>,
    /// The payment address (encrypted, base64).
    pub payment_address: Option<String>,
    /// Badge IDs to display on the profile.
    pub badge_ids: Option<Vec<String>>,
}
