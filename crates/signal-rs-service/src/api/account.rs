//! Account management API.
//!
//! Endpoints for account settings, device management, etc.:
//! - GET    /v1/accounts/whoami            -- get current account info
//! - PUT    /v1/accounts/attributes        -- update account attributes
//! - DELETE /v1/accounts/me                -- delete the account
//! - GET    /v1/devices/                   -- list linked devices
//! - DELETE /v1/devices/{device_id}        -- remove a linked device
//! - PUT    /v1/accounts/username_hash     -- set username hash
//! - DELETE /v1/accounts/username_hash     -- delete username
//! - PUT    /v1/accounts/username_hash/confirm -- confirm username
//! - GET    /v1/accounts/username_hash/{hash} -- look up username by hash
//! - PUT    /v1/accounts/phone_number_discoverability -- set phone number visibility

use serde::{Deserialize, Serialize};
use tracing::debug;
use uuid::Uuid;

use signal_rs_protocol::DeviceId;

use crate::error::Result;
use crate::net::http::HttpClient;

/// Account info returned by the "whoami" endpoint.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WhoAmIResponse {
    /// The account's ACI UUID.
    pub uuid: Uuid,
    /// The account's PNI UUID.
    pub pni: Uuid,
    /// The account's E.164 phone number.
    pub number: String,
}

/// Information about a linked device.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    /// The device ID.
    pub id: u32,
    /// The encrypted device name (base64).
    pub name: Option<String>,
    /// When the device was created (Unix millis).
    pub created: u64,
    /// When the device was last seen (Unix millis).
    pub last_seen: u64,
}

/// Wrapper for the devices list response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicesResponse {
    /// The list of linked devices.
    pub devices: Vec<DeviceInfo>,
}

/// Request body for setting the username hash.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsernameHashRequest {
    /// The username hashes to reserve.
    pub username_hashes: Vec<String>,
}

/// Response body from username hash reservation.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsernameHashResponse {
    /// The username hash that was successfully reserved.
    pub username_hash: String,
}

/// Request body for confirming a reserved username.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmUsernameRequest {
    /// The username hash to confirm.
    pub username_hash: String,
    /// The zkproof for the username.
    pub zk_proof: String,
    /// The encrypted username (base64).
    pub encrypted_username: Option<String>,
}

/// Response from looking up a username hash.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsernameLookupResponse {
    /// The UUID associated with the username hash, if found.
    pub uuid: Uuid,
}

/// Request body for setting phone number discoverability.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhoneNumberDiscoverabilityRequest {
    /// Whether the phone number should be discoverable.
    pub discoverable_by_phone_number: bool,
}

/// Request body for starting a phone number change.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeNumberRequest {
    /// The new phone number.
    pub number: String,
    /// The verification code delivery transport ("sms" or "voice").
    pub transport: String,
    /// Optional CAPTCHA token for rate-limit bypass.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captcha: Option<String>,
}

/// Response from starting a phone number change.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeNumberResponse {
    /// The verification session ID for the number change.
    pub session_id: String,
}

/// Request body for completing a phone number change.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishChangeNumberRequest {
    /// The new phone number.
    pub number: String,
    /// The verification code.
    pub code: String,
    /// The PNI identity key (base64-encoded).
    pub pni_identity_key: String,
    /// Optional registration lock PIN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_lock: Option<String>,
}

/// Request body for updating a linked device's name.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDeviceNameRequest {
    /// The new encrypted device name (base64-encoded).
    pub device_name: String,
}

/// Request body for submitting a rate limit challenge.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitRateLimitChallengeRequest {
    /// The challenge type (always "captcha" for CAPTCHA challenges).
    pub r#type: String,
    /// The challenge token from the server's 428 response.
    pub token: String,
    /// The CAPTCHA solution token.
    pub captcha: String,
}

/// API client for account management endpoints.
pub struct AccountApi<'a> {
    /// The HTTP client.
    http: &'a HttpClient,
}

impl<'a> AccountApi<'a> {
    /// Create a new account API client.
    pub fn new(http: &'a HttpClient) -> Self {
        Self { http }
    }

    /// Get current account info.
    ///
    /// GET /v1/accounts/whoami
    pub async fn whoami(&self) -> Result<WhoAmIResponse> {
        self.http.get_json("/v1/accounts/whoami").await
    }

    /// Update account attributes.
    ///
    /// PUT /v1/accounts/attributes
    pub async fn update_attributes(
        &self,
        attributes: &super::registration::AccountAttributes,
    ) -> Result<()> {
        self.http
            .put_json_no_response("/v1/accounts/attributes", attributes)
            .await
    }

    /// Delete the account.
    ///
    /// DELETE /v1/accounts/me
    pub async fn delete_account(&self) -> Result<()> {
        self.http.delete("/v1/accounts/me").await
    }

    /// List all linked devices.
    ///
    /// GET /v1/devices/
    ///
    /// Returns device information including ID, name, creation time, and last seen.
    pub async fn get_devices(&self) -> Result<Vec<DeviceInfo>> {
        debug!("listing linked devices");
        let response: DevicesResponse = self.http.get_json("/v1/devices/").await?;
        Ok(response.devices)
    }

    /// Remove a linked device.
    ///
    /// DELETE /v1/devices/{device_id}
    pub async fn remove_device(&self, device_id: DeviceId) -> Result<()> {
        let path = format!("/v1/devices/{device_id}");
        debug!(device_id = %device_id, "removing device");
        self.http.delete(&path).await
    }

    /// Reserve a username hash.
    ///
    /// PUT /v1/accounts/username_hash
    ///
    /// The server will attempt to reserve one of the provided hashes.
    /// Returns the hash that was successfully reserved.
    pub async fn set_username_hash(
        &self,
        request: &UsernameHashRequest,
    ) -> Result<UsernameHashResponse> {
        debug!("setting username hash");
        self.http
            .put_json("/v1/accounts/username_hash", request)
            .await
    }

    /// Confirm a previously reserved username.
    ///
    /// PUT /v1/accounts/username_hash/confirm
    pub async fn confirm_username(
        &self,
        request: &ConfirmUsernameRequest,
    ) -> Result<()> {
        debug!("confirming username");
        self.http
            .put_json_no_response("/v1/accounts/username_hash/confirm", request)
            .await
    }

    /// Delete the current username.
    ///
    /// DELETE /v1/accounts/username_hash
    pub async fn delete_username(&self) -> Result<()> {
        debug!("deleting username");
        self.http.delete("/v1/accounts/username_hash").await
    }

    /// Look up a user by their username hash.
    ///
    /// GET /v1/accounts/username_hash/{usernameHash}
    pub async fn lookup_username_hash(&self, username_hash: &str) -> Result<UsernameLookupResponse> {
        let path = format!("/v1/accounts/username_hash/{username_hash}");
        debug!("looking up username hash");
        self.http.get_json(&path).await
    }

    /// Set the phone number discoverability preference.
    ///
    /// PUT /v1/accounts/phone_number_discoverability
    pub async fn set_phone_number_discoverability(&self, discoverable: bool) -> Result<()> {
        let request = PhoneNumberDiscoverabilityRequest {
            discoverable_by_phone_number: discoverable,
        };
        debug!(
            discoverable = discoverable,
            "setting phone number discoverability"
        );
        self.http
            .put_json_no_response("/v1/accounts/phone_number_discoverability", &request)
            .await
    }

    /// Start a phone number change by requesting a verification code for the new number.
    ///
    /// PUT /v2/accounts/number
    pub async fn start_change_number(
        &self,
        request: &ChangeNumberRequest,
    ) -> Result<ChangeNumberResponse> {
        debug!(number = %request.number, "starting phone number change");
        self.http
            .put_json("/v2/accounts/number", request)
            .await
    }

    /// Complete a phone number change with the verification code.
    ///
    /// PUT /v2/accounts/number
    pub async fn finish_change_number(
        &self,
        request: &FinishChangeNumberRequest,
    ) -> Result<()> {
        debug!(number = %request.number, "finishing phone number change");
        self.http
            .put_json_no_response("/v2/accounts/number", request)
            .await
    }

    /// Update a linked device's name.
    ///
    /// PUT /v1/accounts/name
    pub async fn update_device_name(
        &self,
        request: &UpdateDeviceNameRequest,
    ) -> Result<()> {
        debug!("updating device name");
        self.http
            .put_json_no_response("/v1/accounts/name", request)
            .await
    }

    /// Submit a rate limit challenge (CAPTCHA solution).
    ///
    /// PUT /v1/challenge
    pub async fn submit_rate_limit_challenge(
        &self,
        request: &SubmitRateLimitChallengeRequest,
    ) -> Result<()> {
        debug!("submitting rate limit challenge");
        self.http
            .put_json_no_response("/v1/challenge", request)
            .await
    }
}
