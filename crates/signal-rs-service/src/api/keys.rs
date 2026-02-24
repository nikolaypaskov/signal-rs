//! Pre-key management API.
//!
//! Endpoints for uploading and fetching pre-keys, signed pre-keys,
//! and Kyber pre-keys.
//!
//! - GET  /v2/keys?identity={aci|pni}      -- get pre-key count
//! - PUT  /v2/keys?identity={aci|pni}      -- upload new pre-keys
//! - GET  /v2/keys/{identifier}/{device_id} -- get pre-key bundle
//! - PUT  /v2/keys/signed                   -- upload signed pre-key
//! - GET  /v2/keys/check                    -- check pre-key staleness

use base64::Engine;
use base64::engine::{GeneralPurpose, GeneralPurposeConfig, DecodePaddingMode};
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Base64 engine that tolerates missing padding (Signal server may omit '=' padding).
fn b64_lenient() -> GeneralPurpose {
    GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    )
}

use signal_rs_protocol::{
    DeviceId, IdentityKey, KyberPreKeyId, PreKeyBundle, PreKeyId, ServiceId, ServiceIdKind,
    SignedPreKeyId,
};

use crate::error::{Result, ServiceError};
use crate::net::http::HttpClient;

/// The server's response to a pre-key count query.
///
/// Signal-Server returns `{"count": N, "pqCount": N}`.
#[derive(Debug, Clone, Deserialize)]
pub struct PreKeyCount {
    /// Number of one-time EC pre-keys remaining on the server.
    #[serde(alias = "ecCount")]
    pub count: u32,
    /// Number of Kyber (post-quantum) pre-keys remaining.
    #[serde(alias = "kyberCount", rename = "pqCount")]
    pub pq_count: u32,
}

/// A set of pre-keys to upload to the server.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyUpload {
    /// One-time EC pre-keys.
    pub pre_keys: Vec<PreKeyUploadItem>,
    /// The new signed pre-key.
    pub signed_pre_key: SignedPreKeyUploadItem,
    /// The new last-resort Kyber pre-key.
    #[serde(rename = "pqLastResortPreKey")]
    pub last_resort_kyber_pre_key: Option<KyberPreKeyUploadItem>,
    /// One-time Kyber pre-keys.
    #[serde(rename = "pqPreKeys")]
    pub kyber_pre_keys: Vec<KyberPreKeyUploadItem>,
}

/// A single EC pre-key for upload.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyUploadItem {
    /// The pre-key ID.
    pub key_id: u32,
    /// The base64-encoded public key.
    pub public_key: String,
}

/// A signed pre-key for upload.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPreKeyUploadItem {
    /// The signed pre-key ID.
    pub key_id: u32,
    /// The base64-encoded public key.
    pub public_key: String,
    /// The base64-encoded signature.
    pub signature: String,
}

/// A Kyber pre-key for upload.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KyberPreKeyUploadItem {
    /// The Kyber pre-key ID.
    pub key_id: u32,
    /// The base64-encoded public key.
    pub public_key: String,
    /// The base64-encoded signature.
    pub signature: String,
}

/// The server's response when fetching a pre-key bundle for a remote device.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyBundleResponse {
    /// The remote device's identity key (base64).
    pub identity_key: String,
    /// The list of device pre-key bundles (usually one per device).
    pub devices: Vec<DevicePreKeyBundle>,
}

/// Pre-key material for a single device within a bundle response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePreKeyBundle {
    /// The device ID.
    pub device_id: u32,
    /// The device's registration ID.
    pub registration_id: u32,
    /// The signed pre-key entity.
    pub signed_pre_key: SignedPreKeyEntity,
    /// The optional one-time pre-key entity.
    pub pre_key: Option<PreKeyEntity>,
    /// The optional Kyber pre-key entity.
    /// Signal server returns this as "pqPreKey" (post-quantum pre-key).
    #[serde(alias = "pqPreKey")]
    pub kyber_pre_key: Option<KyberPreKeyEntity>,
}

/// A signed pre-key as returned by the server.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPreKeyEntity {
    /// The key ID.
    pub key_id: u32,
    /// The base64-encoded public key.
    pub public_key: String,
    /// The base64-encoded signature.
    pub signature: String,
}

/// A one-time pre-key as returned by the server.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyEntity {
    /// The key ID.
    pub key_id: u32,
    /// The base64-encoded public key.
    pub public_key: String,
}

/// A Kyber pre-key as returned by the server.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KyberPreKeyEntity {
    /// The key ID.
    pub key_id: u32,
    /// The base64-encoded public key.
    pub public_key: String,
    /// The base64-encoded signature.
    pub signature: String,
}

/// Pre-key staleness check response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyStaleResponse {
    /// Whether the signed pre-key is stale and should be rotated.
    pub stale: bool,
}

/// API client for pre-key management endpoints.
pub struct KeysApi<'a> {
    /// The HTTP client.
    http: &'a HttpClient,
}

impl<'a> KeysApi<'a> {
    /// Create a new keys API client.
    pub fn new(http: &'a HttpClient) -> Self {
        Self { http }
    }

    /// Get the count of remaining pre-keys on the server.
    ///
    /// GET /v2/keys?identity={aci|pni}
    pub async fn get_pre_key_count(&self, identity: ServiceIdKind) -> Result<PreKeyCount> {
        let identity_str = match identity {
            ServiceIdKind::Aci => "aci",
            ServiceIdKind::Pni => "pni",
        };
        let path = format!("/v2/keys?identity={identity_str}");
        self.http.get_json(&path).await
    }

    /// Upload a new batch of pre-keys to the server.
    ///
    /// PUT /v2/keys?identity={aci|pni}
    pub async fn upload_pre_keys(
        &self,
        upload: &PreKeyUpload,
        identity: ServiceIdKind,
    ) -> Result<()> {
        let identity_str = match identity {
            ServiceIdKind::Aci => "aci",
            ServiceIdKind::Pni => "pni",
        };
        let path = format!("/v2/keys?identity={identity_str}");
        if let Ok(json) = serde_json::to_string(upload) {
            let preview = if json.len() > 500 { &json[..500] } else { &json };
            debug!(path = %path, json_preview = %preview, "uploading pre-keys");
        }
        self.http.put_json_no_response(&path, upload).await
    }

    /// Fetch the pre-key bundle for a remote recipient's device.
    ///
    /// GET /v2/keys/{identifier}/{device_id}
    ///
    /// Returns a `PreKeyBundle` that can be used to establish a new session
    /// with the recipient. The bundle contains their identity key, signed pre-key,
    /// optional one-time pre-key, and optional Kyber pre-key.
    pub async fn get_pre_key_bundle(
        &self,
        address: &ServiceId,
        device_id: DeviceId,
    ) -> Result<PreKeyBundle> {
        let path = format!("/v2/keys/{address}/{device_id}");
        debug!(path = %path, "fetching pre-key bundle");

        let response: PreKeyBundleResponse = self.http.get_json(&path).await?;

        let b64 = &b64_lenient();

        // Decode the identity key
        let identity_key_bytes = b64
            .decode(&response.identity_key)
            .map_err(|e| ServiceError::InvalidResponse(format!("invalid identity key: {e}")))?;
        let identity_key = IdentityKey::from_bytes(&identity_key_bytes)
            .map_err(|e| ServiceError::InvalidResponse(format!("invalid identity key: {e}")))?;

        // Find the matching device bundle
        let device_bundle = response
            .devices
            .into_iter()
            .find(|d| d.device_id == device_id.value())
            .ok_or_else(|| {
                ServiceError::InvalidResponse(format!(
                    "no bundle for device {device_id} in response"
                ))
            })?;

        // Decode signed pre-key
        let spk_public = b64
            .decode(&device_bundle.signed_pre_key.public_key)
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("invalid signed pre-key public: {e}"))
            })?;
        let spk_signature = b64
            .decode(&device_bundle.signed_pre_key.signature)
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("invalid signed pre-key signature: {e}"))
            })?;

        // Decode optional one-time pre-key
        let pre_key = if let Some(pk) = device_bundle.pre_key {
            let pk_public = b64.decode(&pk.public_key).map_err(|e| {
                ServiceError::InvalidResponse(format!("invalid pre-key public: {e}"))
            })?;
            Some((PreKeyId(pk.key_id), pk_public))
        } else {
            None
        };

        // Decode optional Kyber pre-key
        let kyber_pre_key = if let Some(kpk) = device_bundle.kyber_pre_key {
            let kpk_public = b64.decode(&kpk.public_key).map_err(|e| {
                ServiceError::InvalidResponse(format!("invalid kyber pre-key public: {e}"))
            })?;
            let kpk_signature = b64.decode(&kpk.signature).map_err(|e| {
                ServiceError::InvalidResponse(format!("invalid kyber pre-key signature: {e}"))
            })?;
            Some((KyberPreKeyId(kpk.key_id), kpk_public, kpk_signature))
        } else {
            None
        };

        Ok(PreKeyBundle {
            registration_id: device_bundle.registration_id,
            device_id: DeviceId(device_bundle.device_id),
            pre_key,
            signed_pre_key: (
                SignedPreKeyId(device_bundle.signed_pre_key.key_id),
                spk_public,
                spk_signature,
            ),
            identity_key,
            kyber_pre_key,
        })
    }

    /// Fetch pre-key bundles for all devices of a remote recipient.
    ///
    /// GET /v2/keys/{identifier}/*
    ///
    /// The wildcard device_id `*` returns bundles for all devices.
    /// This is useful when sending a message to a recipient for the first time
    /// and needing to establish sessions with all their devices.
    pub async fn get_pre_key_bundles_for_all_devices(
        &self,
        address: &ServiceId,
    ) -> Result<(IdentityKey, Vec<PreKeyBundle>)> {
        let path = format!("/v2/keys/{address}/*");
        debug!(path = %path, "fetching pre-key bundles for all devices");

        let response: PreKeyBundleResponse = self.http.get_json(&path).await?;

        let b64 = &b64_lenient();

        // Decode the identity key
        let identity_key_bytes = b64
            .decode(&response.identity_key)
            .map_err(|e| ServiceError::InvalidResponse(format!("invalid identity key: {e}")))?;
        let identity_key = IdentityKey::from_bytes(&identity_key_bytes)
            .map_err(|e| ServiceError::InvalidResponse(format!("invalid identity key: {e}")))?;

        let mut bundles = Vec::with_capacity(response.devices.len());

        for device_bundle in response.devices {
            // Decode signed pre-key
            let spk_public = b64
                .decode(&device_bundle.signed_pre_key.public_key)
                .map_err(|e| {
                    ServiceError::InvalidResponse(format!("invalid signed pre-key public: {e}"))
                })?;
            let spk_signature = b64
                .decode(&device_bundle.signed_pre_key.signature)
                .map_err(|e| {
                    ServiceError::InvalidResponse(format!(
                        "invalid signed pre-key signature: {e}"
                    ))
                })?;

            // Decode optional one-time pre-key
            let pre_key = if let Some(pk) = device_bundle.pre_key {
                let pk_public = b64.decode(&pk.public_key).map_err(|e| {
                    ServiceError::InvalidResponse(format!("invalid pre-key public: {e}"))
                })?;
                Some((PreKeyId(pk.key_id), pk_public))
            } else {
                None
            };

            // Decode optional Kyber pre-key
            let kyber_pre_key = if let Some(kpk) = device_bundle.kyber_pre_key {
                let kpk_public = b64.decode(&kpk.public_key).map_err(|e| {
                    ServiceError::InvalidResponse(format!("invalid kyber pre-key public: {e}"))
                })?;
                let kpk_signature = b64.decode(&kpk.signature).map_err(|e| {
                    ServiceError::InvalidResponse(format!(
                        "invalid kyber pre-key signature: {e}"
                    ))
                })?;
                Some((KyberPreKeyId(kpk.key_id), kpk_public, kpk_signature))
            } else {
                None
            };

            bundles.push(PreKeyBundle {
                registration_id: device_bundle.registration_id,
                device_id: DeviceId(device_bundle.device_id),
                pre_key,
                signed_pre_key: (
                    SignedPreKeyId(device_bundle.signed_pre_key.key_id),
                    spk_public,
                    spk_signature,
                ),
                identity_key: identity_key.clone(),
                kyber_pre_key,
            });
        }

        Ok((identity_key, bundles))
    }

    /// Check whether the signed pre-key is stale and needs rotation.
    ///
    /// GET /v2/keys/check
    pub async fn check_pre_key_staleness(&self) -> Result<PreKeyStaleResponse> {
        debug!("checking pre-key staleness");
        self.http.get_json("/v2/keys/check").await
    }
}
