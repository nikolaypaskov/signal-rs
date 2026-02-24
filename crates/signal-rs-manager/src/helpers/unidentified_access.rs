//! Unidentified access helper -- sealed sender management.
//!
//! Responsible for:
//! - Computing unidentified access keys from profile keys
//! - Fetching and caching sender certificates
//! - Determining whether to use sealed sender for each recipient
//! - Managing the unidentified access mode per contact

use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use base64::Engine;
use tracing::{debug, info, warn};

use signal_rs_service::api::certificate::CertificateApi;
use signal_rs_store::Database;

use crate::error::{ManagerError, Result};

/// Key in the key-value store for caching the sender certificate.
const SENDER_CERTIFICATE_KEY: &str = "sender_certificate";

/// Key in the key-value store for caching the certificate expiration (millis).
const SENDER_CERTIFICATE_EXPIRY_KEY: &str = "sender_certificate_expiry";

/// Refresh a certificate when it will expire within this many milliseconds (1 hour).
const CERTIFICATE_REFRESH_WINDOW_MS: u64 = 60 * 60 * 1000;

/// Helper for unidentified (sealed sender) access.
#[derive(Default)]
pub struct UnidentifiedAccessHelper;

impl UnidentifiedAccessHelper {
    /// Create a new unidentified access helper.
    pub fn new() -> Self {
        Self
    }

    /// Get or refresh the sender certificate for sealed-sender delivery.
    ///
    /// Checks the local cache first. If the cached certificate is expired or
    /// will expire within 1 hour, fetches a new certificate from the server.
    pub async fn get_sender_certificate(
        &self,
        db: &Database,
        certificate_api: &CertificateApi<'_>,
    ) -> Result<Vec<u8>> {
        debug!("getting sender certificate");

        // Check if we have a cached certificate that is still valid
        if let Some(cached) = db.get_kv_blob(SENDER_CERTIFICATE_KEY)?
            && !cached.is_empty() {
                // Check if the cached certificate is still valid (not expired or expiring soon)
                if let Some(expiry_str) = db.get_kv_string(SENDER_CERTIFICATE_EXPIRY_KEY)? {
                    if let Ok(expiry_ms) = expiry_str.parse::<u64>() {
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;

                        if expiry_ms > now_ms + CERTIFICATE_REFRESH_WINDOW_MS {
                            debug!("using cached sender certificate (expires in {}s)",
                                (expiry_ms - now_ms) / 1000);
                            return Ok(cached);
                        }
                        debug!("cached sender certificate expires soon, refreshing");
                    }
                } else {
                    // No expiry stored -- certificate was cached before this logic.
                    // Treat as expired to force a refresh and store the expiry.
                    warn!("cached sender certificate has no stored expiry, refreshing");
                }
            }

        // Fetch a new certificate from the server.
        // include_e164 = true so the certificate contains our phone number
        // (needed for recipients who don't support sealed sender without e164).
        let response = certificate_api.get_sender_certificate(true).await?;

        let b64 = &base64::engine::general_purpose::STANDARD;
        let cert_bytes = b64.decode(&response.certificate).map_err(|e| {
            ManagerError::Other(format!("failed to decode sender certificate: {e}"))
        })?;

        // Try to extract the certificate expiry timestamp.
        // The certificate is a serialized protobuf; try to parse it to get the expiry.
        // If parsing fails, default to 24 hours from now (standard Signal cert lifetime).
        let expiry_ms = extract_certificate_expiry(&cert_bytes).unwrap_or_else(|| {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            now_ms + 24 * 60 * 60 * 1000
        });

        // Cache the certificate and its expiry
        db.set_kv_blob(SENDER_CERTIFICATE_KEY, &cert_bytes)?;
        db.set_kv_string(SENDER_CERTIFICATE_EXPIRY_KEY, &expiry_ms.to_string())?;

        info!(expires_in_hours = (expiry_ms.saturating_sub(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
        )) / 3_600_000, "sender certificate fetched and cached");
        Ok(cert_bytes)
    }

    /// Compute the unidentified access key for a recipient from their profile key.
    ///
    /// Per Signal's protocol, the access key is computed by encrypting 16 zero bytes
    /// with AES-256-GCM using the profile key and a 12-byte zero nonce, then taking
    /// the first 16 bytes of the ciphertext.
    pub fn compute_access_key(&self, profile_key: &[u8]) -> Result<Vec<u8>> {
        debug!("computing unidentified access key");

        if profile_key.len() != 32 {
            return Err(ManagerError::Other(format!(
                "invalid profile key length: expected 32, got {}",
                profile_key.len()
            )));
        }

        let cipher = Aes256Gcm::new_from_slice(profile_key)
            .map_err(|e| ManagerError::Other(format!("AES-GCM init failed: {e}")))?;
        let nonce = Nonce::default(); // 12 zero bytes
        let plaintext = [0u8; 16];
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| ManagerError::Other(format!("AES-GCM encrypt failed: {e}")))?;

        Ok(ciphertext[..16].to_vec())
    }

    /// Determine whether sealed sender should be used for a recipient.
    pub fn should_use_sealed_sender(&self, _recipient_uuid: &uuid::Uuid) -> bool {
        // Default to trying sealed sender for all recipients.
        true
    }
}

/// Try to extract the expiration timestamp from a serialized sender certificate.
///
/// The sender certificate is a protobuf `SenderCertificate` that contains an
/// `expires` field. This function attempts a lightweight parse to extract it.
/// Returns `None` if parsing fails.
fn extract_certificate_expiry(cert_bytes: &[u8]) -> Option<u64> {
    // The SenderCertificate protobuf has the following structure:
    //   message SenderCertificate {
    //     message Certificate {
    //       ...
    //       fixed64 expires = 5;
    //       ...
    //     }
    //     bytes certificate = 1;
    //     bytes signature = 2;
    //   }
    // We try to parse the outer certificate field (field 1, wire type 2) and then
    // look for field 5 (fixed64) inside it.
    //
    // For simplicity, try to deserialize using serde_json if it's JSON, or
    // do a simple protobuf varint walk.
    let mut offset = 0;
    while offset < cert_bytes.len() {
        let (tag, new_offset) = read_protobuf_varint(cert_bytes, offset)?;
        offset = new_offset;
        let field_number = tag >> 3;
        let wire_type = tag & 0x07;

        match wire_type {
            0 => {
                // Varint
                let (value, new_offset) = read_protobuf_varint(cert_bytes, offset)?;
                offset = new_offset;
                // Field 5 in the inner certificate is the expiry -- but it's fixed64 (wire type 1),
                // not varint, in the standard protobuf. Check if this is the expires field.
                if field_number == 5 {
                    return Some(value);
                }
            }
            1 => {
                // Fixed 64-bit
                if offset + 8 > cert_bytes.len() {
                    return None;
                }
                if field_number == 5 {
                    let value = u64::from_le_bytes([
                        cert_bytes[offset],
                        cert_bytes[offset + 1],
                        cert_bytes[offset + 2],
                        cert_bytes[offset + 3],
                        cert_bytes[offset + 4],
                        cert_bytes[offset + 5],
                        cert_bytes[offset + 6],
                        cert_bytes[offset + 7],
                    ]);
                    return Some(value);
                }
                offset += 8;
            }
            2 => {
                // Length-delimited
                let (length, new_offset) = read_protobuf_varint(cert_bytes, offset)?;
                offset = new_offset;
                let length = length as usize;
                if offset + length > cert_bytes.len() {
                    return None;
                }
                // If this is field 1 (certificate), recurse into it
                if field_number == 1
                    && let Some(expiry) = extract_certificate_expiry(&cert_bytes[offset..offset + length]) {
                        return Some(expiry);
                    }
                offset += length;
            }
            5 => {
                // Fixed 32-bit
                offset += 4;
            }
            _ => return None,
        }
    }
    None
}

/// Read a protobuf varint from a byte slice at the given offset.
fn read_protobuf_varint(data: &[u8], mut offset: usize) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if offset >= data.len() {
            return None;
        }
        let byte = data[offset];
        offset += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((result, offset));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_access_key_returns_16_bytes() {
        let helper = UnidentifiedAccessHelper::new();
        let profile_key = [0xAA; 32];
        let key = helper.compute_access_key(&profile_key).unwrap();
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn compute_access_key_deterministic() {
        let helper = UnidentifiedAccessHelper::new();
        let profile_key = [0xBB; 32];
        let k1 = helper.compute_access_key(&profile_key).unwrap();
        let k2 = helper.compute_access_key(&profile_key).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn compute_access_key_differs_for_different_profile_keys() {
        let helper = UnidentifiedAccessHelper::new();
        let k1 = helper.compute_access_key(&[0x11; 32]).unwrap();
        let k2 = helper.compute_access_key(&[0x22; 32]).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn compute_access_key_matches_signal_android_test_vector() {
        // Test vector from Signal-Android UnidentifiedAccessTest.java
        let helper = UnidentifiedAccessHelper::new();
        let profile_key = [0x02u8; 32];
        let key = helper.compute_access_key(&profile_key).unwrap();
        assert_eq!(
            key,
            [0x5a, 0x72, 0x3a, 0xce, 0xe5, 0x2c, 0x5e, 0xa0,
             0x2b, 0x92, 0xa3, 0xa3, 0x60, 0xc0, 0x95, 0x95]
        );
    }

    #[test]
    fn compute_access_key_rejects_wrong_length() {
        let helper = UnidentifiedAccessHelper::new();
        assert!(helper.compute_access_key(&[0xAA; 16]).is_err());
        assert!(helper.compute_access_key(&[0xAA; 64]).is_err());
        assert!(helper.compute_access_key(&[]).is_err());
    }

    #[test]
    fn should_use_sealed_sender_always_true() {
        let helper = UnidentifiedAccessHelper::new();
        let uuid = uuid::Uuid::new_v4();
        assert!(helper.should_use_sealed_sender(&uuid));
    }

    // ---- certificate refresh window constant ----

    #[test]
    fn refresh_window_is_one_hour() {
        assert_eq!(CERTIFICATE_REFRESH_WINDOW_MS, 3_600_000);
    }

    // ---- extract_certificate_expiry ----

    #[test]
    fn extract_expiry_returns_none_for_empty() {
        assert!(extract_certificate_expiry(&[]).is_none());
    }

    #[test]
    fn extract_expiry_returns_none_for_garbage() {
        assert!(extract_certificate_expiry(&[0xFF, 0xFF, 0xFF]).is_none());
    }
}
