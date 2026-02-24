//! Account registration API.
//!
//! Signal registration flow (v2):
//! 1. POST /v1/verification/session           — create a verification session
//! 2. POST /v1/verification/session/{id}/code  — request SMS/voice code
//! 3. PUT  /v1/verification/session/{id}/code  — submit verification code
//! 4. POST /v1/registration                    — register the account

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Result, ServiceError};
use crate::net::http::HttpClient;

/// The transport type for verification code delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationTransport {
    /// Send the code via SMS.
    Sms,
    /// Deliver the code via a phone call.
    Voice,
}

/// Account attributes sent during registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountAttributes {
    /// Whether this device will poll for messages via WebSocket (no push tokens).
    #[serde(default)]
    pub fetches_messages: bool,
    /// The client's ACI registration ID (for Signal Protocol sessions).
    pub registration_id: u32,
    /// The client's PNI registration ID.
    pub pni_registration_id: u32,
    /// The base64-encoded encrypted device name.
    pub name: Option<String>,
    /// Capabilities advertised by this device.
    pub capabilities: AccountCapabilities,
    /// Whether the account is discoverable by phone number.
    #[serde(default = "default_true")]
    pub discoverable_by_phone_number: bool,
    /// The unidentified access key (sealed sender).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unidentified_access_key: Option<String>,
    /// Whether unrestricted unidentified access is enabled.
    #[serde(default)]
    pub unrestricted_unidentified_access: bool,
    /// The registration lock token (from PIN/SVR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_lock: Option<String>,
    /// Recovery password.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_password: Option<String>,
}

fn default_true() -> bool { true }

impl AccountAttributes {
    /// Create default account attributes with the given registration IDs.
    pub fn with_registration_ids(aci_reg_id: u32, pni_reg_id: u32) -> Self {
        Self {
            fetches_messages: true,
            registration_id: aci_reg_id,
            pni_registration_id: pni_reg_id,
            name: None,
            capabilities: AccountCapabilities {
                storage: true,
                transfer: false,
                attachment_backfill: false,
                spqr: true,
            },
            discoverable_by_phone_number: true,
            unidentified_access_key: None,
            unrestricted_unidentified_access: false,
            registration_lock: None,
            recovery_password: None,
        }
    }
}

/// Device capability flags advertised during registration.
///
/// Signal-Server expects a map of capability names to booleans.
/// Valid capabilities: storage, transfer, attachmentBackfill, spqr.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountCapabilities {
    /// Whether the client supports encrypted storage service.
    #[serde(default)]
    pub storage: bool,
    /// Whether the client supports device transfer.
    #[serde(default)]
    pub transfer: bool,
    /// Whether the client supports attachment backfill.
    #[serde(default)]
    pub attachment_backfill: bool,
    /// Whether the client supports sparse post-quantum ratchet.
    #[serde(default)]
    pub spqr: bool,
}

/// A verification session as returned by the server.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationSession {
    /// The session ID.
    pub id: String,
    /// Whether a verification code has been verified.
    #[serde(default)]
    pub verified: bool,
    /// Whether the client is allowed to request a verification code.
    #[serde(default)]
    pub allowed_to_request_code: bool,
    /// Requested information (e.g., "pushChallenge", "captcha").
    #[serde(default)]
    pub requested_information: Option<Vec<String>>,
}

/// Request body for creating a new verification session.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionRequest {
    number: String,
}

/// Request body for requesting a verification code.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestCodeRequest {
    transport: String,
    client: String,
}

/// Request body for submitting a verification code.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitCodeRequest {
    code: String,
}

/// Full registration request body.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRequest {
    /// The verification session ID.
    pub session_id: String,
    /// Account attributes.
    pub account_attributes: AccountAttributes,
    /// Base64-encoded ACI identity key (33 bytes, with 0x05 prefix).
    pub aci_identity_key: String,
    /// Base64-encoded PNI identity key (33 bytes, with 0x05 prefix).
    pub pni_identity_key: String,
    /// ACI signed pre-key.
    pub aci_signed_pre_key: RegistrationSignedPreKey,
    /// PNI signed pre-key.
    pub pni_signed_pre_key: RegistrationSignedPreKey,
    /// ACI last-resort Kyber pre-key.
    pub aci_pq_last_resort_pre_key: RegistrationKyberPreKey,
    /// PNI last-resort Kyber pre-key.
    pub pni_pq_last_resort_pre_key: RegistrationKyberPreKey,
    /// Whether to skip device transfer.
    #[serde(default)]
    pub skip_device_transfer: bool,
}

/// A signed pre-key for the registration request.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationSignedPreKey {
    /// The key ID.
    pub key_id: u32,
    /// Base64-encoded public key.
    pub public_key: String,
    /// Base64-encoded signature.
    pub signature: String,
}

/// A Kyber pre-key for the registration request.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationKyberPreKey {
    /// The key ID.
    pub key_id: u32,
    /// Base64-encoded public key.
    pub public_key: String,
    /// Base64-encoded signature.
    pub signature: String,
}

/// The result of a successful registration.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredAccount {
    /// The assigned ACI UUID.
    pub uuid: Uuid,
    /// The assigned PNI UUID.
    pub pni: Uuid,
    /// Whether storage service data needs to be restored.
    #[serde(default)]
    pub storage_capable: bool,
}

/// API client for the registration endpoints.
pub struct RegistrationApi<'a> {
    /// The HTTP client to use for requests.
    http: &'a HttpClient,
}

impl<'a> RegistrationApi<'a> {
    /// Create a new registration API client.
    pub fn new(http: &'a HttpClient) -> Self {
        Self { http }
    }

    /// Create a new verification session for the given phone number.
    ///
    /// POST /v1/verification/session
    pub async fn create_session(&self, number: &str) -> Result<VerificationSession> {
        let body = CreateSessionRequest {
            number: number.to_string(),
        };
        self.http
            .post_json_unauthenticated("/v1/verification/session", &body)
            .await
    }

    /// Request a verification code via SMS or voice call.
    ///
    /// POST /v1/verification/session/{session_id}/code
    pub async fn request_verification_code(
        &self,
        session_id: &str,
        transport: VerificationTransport,
    ) -> Result<VerificationSession> {
        let transport_str = match transport {
            VerificationTransport::Sms => "sms",
            VerificationTransport::Voice => "voice",
        };

        let body = RequestCodeRequest {
            transport: transport_str.to_string(),
            client: "android".to_string(),
        };

        let path = format!("/v1/verification/session/{session_id}/code");
        self.http
            .post_json_unauthenticated(&path, &body)
            .await
    }

    /// Submit the received verification code.
    ///
    /// PUT /v1/verification/session/{session_id}/code
    pub async fn submit_verification_code(
        &self,
        session_id: &str,
        code: &str,
    ) -> Result<VerificationSession> {
        let body = SubmitCodeRequest {
            code: code.to_string(),
        };

        let path = format!("/v1/verification/session/{session_id}/code");

        // PUT with no auth
        let url = format!("{}{}", self.http.config().service_url, path);
        let client = reqwest::Client::builder()
            .user_agent("Signal-Android/7.26.3 signal-rs/0.1.0")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(ServiceError::Network)?;

        let resp = client
            .put(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            match status.as_u16() {
                401 | 403 => return Err(ServiceError::Authentication),
                404 => return Err(ServiceError::NotFound),
                409 => return Err(ServiceError::Conflict),
                428 => return Err(ServiceError::CaptchaRequired),
                429 => return Err(ServiceError::RateLimited(std::time::Duration::from_secs(60))),
                code => return Err(ServiceError::Http(code, text)),
            }
        }

        serde_json::from_str(&text).map_err(ServiceError::Json)
    }

    /// Register the account after verification is complete.
    ///
    /// POST /v1/registration
    pub async fn register_account(
        &self,
        request: &RegistrationRequest,
    ) -> Result<RegisteredAccount> {
        self.http
            .post_json_unauthenticated("/v1/registration", request)
            .await
    }
}
