//! Device provisioning (linking) API.
//!
//! When linking a new device:
//! 1. The new device opens a provisioning WebSocket
//! 2. The server assigns a provisioning UUID and sends it
//! 3. The new device encodes the UUID + its public key into a `sgnl://` URI
//! 4. The primary device scans the QR code and sends a ProvisionMessage
//! 5. The new device decrypts it and completes registration
//!
//! Endpoint: wss://chat.signal.org/v1/websocket/provisioning/

use base64::Engine;
use prost::Message;
use serde::{Deserialize, Serialize};
use tracing::debug;
use uuid::Uuid;

use signal_rs_protos::{ProvisionEnvelope, ProvisionMessage, ProvisioningUuid};

use crate::api::provisioning_cipher::ProvisioningCipher;
use crate::api::registration::AccountAttributes;
use crate::config::ServiceConfig;
use crate::error::{Result, ServiceError};
use crate::net::http::HttpClient;
use crate::net::websocket::SignalWebSocket;

/// Decoded provisioning message containing account details from the primary device.
#[derive(Debug)]
pub struct DecryptedProvisionMessage {
    /// ACI identity key pair (public bytes).
    pub aci_identity_key_public: Vec<u8>,
    /// ACI identity key pair (private bytes).
    pub aci_identity_key_private: Vec<u8>,
    /// PNI identity key pair (public bytes).
    pub pni_identity_key_public: Vec<u8>,
    /// PNI identity key pair (private bytes).
    pub pni_identity_key_private: Vec<u8>,
    /// The account's ACI UUID.
    pub aci: Option<String>,
    /// The account's PNI UUID.
    pub pni: Option<String>,
    /// The account's phone number.
    pub number: Option<String>,
    /// The provisioning code (used to complete device linking).
    pub provisioning_code: Option<String>,
    /// The profile key.
    pub profile_key: Option<Vec<u8>>,
    /// Whether read receipts are enabled.
    pub read_receipts: Option<bool>,
    /// The master key (may be derived from AEP by the primary device).
    pub master_key: Option<Vec<u8>>,
    /// The Account Entropy Pool (64-char alphanumeric string).
    /// If present, the master key should be derived from this.
    pub account_entropy_pool: Option<String>,
}

impl From<ProvisionMessage> for DecryptedProvisionMessage {
    fn from(msg: ProvisionMessage) -> Self {
        Self {
            aci_identity_key_public: msg.aci_identity_key_public.unwrap_or_default(),
            aci_identity_key_private: msg.aci_identity_key_private.unwrap_or_default(),
            pni_identity_key_public: msg.pni_identity_key_public.unwrap_or_default(),
            pni_identity_key_private: msg.pni_identity_key_private.unwrap_or_default(),
            aci: msg.aci,
            pni: msg.pni,
            number: msg.number,
            provisioning_code: msg.provisioning_code,
            profile_key: msg.profile_key,
            read_receipts: msg.read_receipts,
            master_key: msg.master_key,
            account_entropy_pool: msg.account_entropy_pool,
        }
    }
}

/// The response from finishing device linking.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishDeviceLinkResponse {
    /// The assigned device ID for this linked device.
    pub device_id: u32,
    /// The account's ACI UUID.
    pub uuid: Uuid,
    /// The account's PNI UUID.
    pub pni: Uuid,
}

/// Request body for finishing device linking.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishDeviceLinkRequest {
    /// The provisioning code from the primary device.
    pub verification_code: String,
    /// Account attributes for the new device.
    pub account_attributes: AccountAttributes,
    /// ACI signed pre-key.
    pub aci_signed_pre_key: super::registration::RegistrationSignedPreKey,
    /// PNI signed pre-key.
    pub pni_signed_pre_key: super::registration::RegistrationSignedPreKey,
    /// ACI last-resort Kyber pre-key.
    pub aci_pq_last_resort_pre_key: super::registration::RegistrationKyberPreKey,
    /// PNI last-resort Kyber pre-key.
    pub pni_pq_last_resort_pre_key: super::registration::RegistrationKyberPreKey,
}

/// API client for device provisioning (linking).
pub struct ProvisioningApi;

impl ProvisioningApi {
    /// Start the provisioning process.
    ///
    /// Opens a WebSocket to the provisioning endpoint, waits for the server
    /// to assign a provisioning UUID, and creates a provisioning cipher.
    ///
    /// Returns (provisioning UUID, cipher, websocket).
    pub async fn start_provisioning(
        config: &ServiceConfig,
    ) -> Result<(String, ProvisioningCipher, SignalWebSocket)> {
        let cipher = ProvisioningCipher::new();

        let url = config.ws_url("/v1/websocket/provisioning/");
        let ws = SignalWebSocket::connect(&url, None).await?;

        debug!("provisioning WebSocket connected, waiting for UUID...");

        // Receive first server-push request containing the ProvisioningUuid
        let request = ws.receive_request().await?;
        debug!(path = %request.path, "received provisioning request");

        let uuid = if let Some(body) = &request.body {
            let provisioning_uuid = ProvisioningUuid::decode(body.as_slice())
                .map_err(|e| ServiceError::ProvisioningCipher(format!(
                    "failed to decode ProvisioningUuid: {e}"
                )))?;
            provisioning_uuid.uuid.ok_or_else(|| {
                ServiceError::ProvisioningCipher("missing UUID in provisioning response".into())
            })?
        } else {
            return Err(ServiceError::ProvisioningCipher(
                "provisioning request has no body".into(),
            ));
        };

        // Acknowledge the request
        ws.send_response(request.id, 200).await?;

        debug!(uuid = %uuid, "received provisioning UUID");

        Ok((uuid, cipher, ws))
    }

    /// Wait for and decrypt the provision message from the primary device.
    pub async fn receive_provision_message(
        ws: &SignalWebSocket,
        cipher: &ProvisioningCipher,
    ) -> Result<DecryptedProvisionMessage> {
        debug!("waiting for provision message from primary device...");

        let request = ws.receive_request().await?;
        debug!(path = %request.path, "received provision envelope");

        let envelope = if let Some(body) = &request.body {
            ProvisionEnvelope::decode(body.as_slice())
                .map_err(|e| ServiceError::ProvisioningCipher(format!(
                    "failed to decode ProvisionEnvelope: {e}"
                )))?
        } else {
            return Err(ServiceError::ProvisioningCipher(
                "provision envelope request has no body".into(),
            ));
        };

        // Acknowledge
        ws.send_response(request.id, 200).await?;

        // Decrypt
        let provision_message = cipher.decrypt(&envelope)?;
        Ok(provision_message.into())
    }

    /// Build the device link URI from the provisioning UUID and public key.
    ///
    /// Format: `sgnl://linkdevice?uuid=<urlencoded>&pub_key=<base64-no-padding-urlencoded>`
    pub fn build_device_link_uri(uuid: &str, public_key_bytes: &[u8]) -> String {
        let encoded_key = base64::engine::general_purpose::STANDARD_NO_PAD
            .encode(public_key_bytes);
        let encoded_uuid = urlencoding::encode(uuid);
        let encoded_pub_key = urlencoding::encode(&encoded_key);
        format!("sgnl://linkdevice?uuid={encoded_uuid}&pub_key={encoded_pub_key}")
    }

    /// Complete device linking by sending the finish request to the server.
    ///
    /// PUT /v1/devices/link
    pub async fn finish_device_linking(
        http: &HttpClient,
        request: &FinishDeviceLinkRequest,
    ) -> Result<FinishDeviceLinkResponse> {
        http.put_json("/v1/devices/link", request).await
    }
}
