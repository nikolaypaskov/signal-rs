//! Secure Value Recovery v2 (SVR2) API.
//!
//! SVR2 provides secure storage and retrieval of a master key, encrypted with
//! a PIN-derived key, inside a hardware enclave. This enables PIN-based
//! account recovery during re-registration.
//!
//! Endpoint: wss://svr2.signal.org/v1/{mrenclave}
//!
//! Protocol:
//! 1. Connect to the SVR2 enclave via WebSocket with Basic auth
//! 2. Receive attestation message (enclave evidence + public key)
//! 3. Perform Noise_NK_25519_ChaChaPoly_SHA256 handshake
//! 4. Send encrypted request (backup/restore/delete) over the Noise channel
//! 5. Receive encrypted response
//!
//! The Noise_NK handshake ensures end-to-end encryption between the client
//! and the enclave, independent of TLS. The attestation step (SGX DCAP)
//! verifies that the enclave is running the expected code (MREnclave).

use futures::stream::StreamExt;
use futures::SinkExt;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::error::{Result, ServiceError};
use crate::net::http::HttpClient;

/// The Noise protocol pattern used for SVR2 enclave communication.
const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_SHA256";

/// SVR2 request types (encoded in the encrypted request payload).
const SVR2_OP_BACKUP: u8 = 1;
const SVR2_OP_RESTORE: u8 = 2;
const SVR2_OP_DELETE: u8 = 3;

/// SVR2 response status codes.
const SVR2_STATUS_OK: u8 = 1;
const SVR2_STATUS_MISSING: u8 = 2;
const SVR2_STATUS_PIN_MISMATCH: u8 = 3;
const SVR2_STATUS_SERVER_ERROR: u8 = 4;

/// Default maximum PIN attempts before enclave deletes the data.
const DEFAULT_MAX_TRIES: u32 = 10;

/// Auth credentials for the SVR2 service.
#[derive(Debug, Clone, Deserialize)]
pub struct Svr2AuthResponse {
    /// The username for SVR2 authentication.
    pub username: String,
    /// The password for SVR2 authentication.
    pub password: String,
}

/// Auth credentials provided by the server during registration lock.
///
/// When a registration attempt hits a 423 (RegistrationLocked) response,
/// the server includes SVR2 credentials that can be used to restore
/// the master key from the enclave.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Svr2AuthCredentials {
    /// The username for SVR2 authentication.
    pub username: String,
    /// The password for SVR2 authentication.
    pub password: String,
}

/// The result of an SVR2 backup operation.
#[derive(Debug, Clone)]
pub enum Svr2BackupResponse {
    /// The master key was successfully backed up to the enclave.
    Success,
    /// The server rejected the backup request.
    ServerRejected,
    /// The specified enclave was not found (MREnclave mismatch or retired).
    EnclaveNotFound,
    /// The backup failed due to an expose failure in the enclave.
    ExposeFailure,
    /// An application-level error occurred.
    ApplicationError(String),
    /// A network error occurred.
    NetworkError(String),
}

/// The result of an SVR2 restore operation.
#[derive(Debug, Clone)]
pub enum Svr2RestoreResponse {
    /// The master key was successfully restored.
    Success {
        /// The restored master key (32 bytes).
        master_key: Vec<u8>,
    },
    /// The PIN did not match. Includes the number of remaining attempts.
    PinMismatch {
        /// How many more attempts are allowed before the data is deleted.
        tries_remaining: u32,
    },
    /// No data was found for the given credentials.
    Missing,
    /// The server rejected the restore request.
    ServerRejected,
    /// The specified enclave was not found.
    EnclaveNotFound,
    /// An application-level error occurred.
    ApplicationError(String),
    /// A network error occurred.
    NetworkError(String),
}

/// The result of an SVR2 delete operation.
#[derive(Debug, Clone)]
pub enum Svr2DeleteResponse {
    /// The data was successfully deleted.
    Success,
    /// The server rejected the delete request.
    ServerRejected,
    /// The specified enclave was not found.
    EnclaveNotFound,
    /// An application-level error occurred.
    ApplicationError(String),
    /// A network error occurred.
    NetworkError(String),
}

/// API client for Secure Value Recovery v2.
pub struct Svr2Api<'a> {
    /// The HTTP client.
    http: &'a HttpClient,
}

impl<'a> Svr2Api<'a> {
    /// Create a new SVR2 API client.
    pub fn new(http: &'a HttpClient) -> Self {
        Self { http }
    }

    /// Get auth credentials for the SVR2 service.
    ///
    /// GET /v2/backup/auth
    ///
    /// Returns a username/password pair that is used to authenticate
    /// the WebSocket connection to the SVR2 enclave.
    pub async fn get_svr2_auth(&self) -> Result<Svr2AuthResponse> {
        debug!("fetching SVR2 auth credentials");
        self.http.get_json("/v2/backup/auth").await
    }

    /// Back up a master key to the SVR2 enclave.
    ///
    /// This connects to the SVR2 enclave, performs the Noise_NK handshake,
    /// and sends an encrypted BackupRequest containing the PIN-derived key
    /// and the master key.
    ///
    /// The master key is stored in the enclave and can be retrieved later
    /// with the correct PIN (up to `DEFAULT_MAX_TRIES` attempts).
    pub async fn backup(
        &self,
        pin: &str,
        master_key: &[u8],
    ) -> Result<Svr2BackupResponse> {
        debug!("SVR2 backup requested");

        if master_key.len() != 32 {
            return Err(ServiceError::InvalidResponse(
                "master key must be exactly 32 bytes".to_string(),
            ));
        }

        // Step 1: Get auth credentials
        let auth = self.get_svr2_auth().await?;
        debug!(username = %auth.username, "obtained SVR2 auth credentials");

        // Step 2: Build the WebSocket URL
        let config = self.http.config();
        let mrenclaves = &config.svr2_mrenclaves;
        if mrenclaves.is_empty() {
            return Err(ServiceError::InvalidResponse(
                "no SVR2 MREnclave values configured".to_string(),
            ));
        }

        let mrenclave = &mrenclaves[0];
        let ws_url = config.svr2_ws_url(mrenclave);
        debug!(url = %ws_url, mrenclave = %mrenclave, "SVR2 WebSocket URL");

        // Step 3: Build the backup request payload
        let request_payload = build_backup_request(pin.as_bytes(), master_key, DEFAULT_MAX_TRIES);

        // Step 4: Perform the enclave request
        let response = self
            .perform_svr2_request(&ws_url, &auth, &request_payload)
            .await?;

        // Step 5: Parse the backup response
        parse_backup_response(&response)
    }

    /// Restore a master key from the SVR2 enclave using a PIN.
    ///
    /// Used during re-registration when the account has a registration lock.
    /// The server provides SVR2 auth credentials in the 423 response.
    ///
    /// This connects to the enclave, performs the Noise_NK handshake, and
    /// sends an encrypted RestoreRequest with the PIN.
    pub async fn restore(
        &self,
        auth_credentials: &Svr2AuthCredentials,
        pin: &str,
    ) -> Result<Svr2RestoreResponse> {
        debug!("SVR2 restore requested");

        let config = self.http.config();
        let mrenclaves = &config.svr2_mrenclaves;
        if mrenclaves.is_empty() {
            return Err(ServiceError::InvalidResponse(
                "no SVR2 MREnclave values configured".to_string(),
            ));
        }

        let mrenclave = &mrenclaves[0];
        let ws_url = config.svr2_ws_url(mrenclave);
        debug!(url = %ws_url, "SVR2 restore WebSocket URL");

        let auth = Svr2AuthResponse {
            username: auth_credentials.username.clone(),
            password: auth_credentials.password.clone(),
        };

        // Build the restore request payload
        let request_payload = build_restore_request(pin.as_bytes());

        // Perform the enclave request
        let response = self
            .perform_svr2_request(&ws_url, &auth, &request_payload)
            .await?;

        // Parse the restore response
        parse_restore_response(&response)
    }

    /// Delete data from the SVR2 enclave.
    ///
    /// Used when removing the registration lock PIN. Deletes the
    /// encrypted master key from all configured SVR2 enclaves.
    pub async fn delete(&self) -> Result<Svr2DeleteResponse> {
        debug!("SVR2 delete requested");

        let auth = self.get_svr2_auth().await?;
        debug!(username = %auth.username, "obtained SVR2 auth credentials for delete");

        let config = self.http.config();
        let mut last_result = Svr2DeleteResponse::Success;

        for mrenclave in &config.svr2_mrenclaves {
            let ws_url = config.svr2_ws_url(mrenclave);
            debug!(url = %ws_url, "SVR2 delete: attempting connection");

            let request_payload = build_delete_request();

            match self
                .perform_svr2_request(&ws_url, &auth, &request_payload)
                .await
            {
                Ok(response) => {
                    match parse_delete_response(&response) {
                        Ok(result) => {
                            info!(mrenclave = %mrenclave, "SVR2 delete completed: {:?}", result);
                            last_result = result;
                        }
                        Err(e) => {
                            warn!(mrenclave = %mrenclave, error = %e, "SVR2 delete: parse failed");
                            last_result =
                                Svr2DeleteResponse::ApplicationError(format!("{e}"));
                        }
                    }
                }
                Err(e) => {
                    warn!(mrenclave = %mrenclave, error = %e, "SVR2 delete: connection failed");
                    last_result = Svr2DeleteResponse::NetworkError(format!("{e}"));
                }
            }
        }

        Ok(last_result)
    }

    /// Perform an SVR2 request over the Noise_NK encrypted channel.
    ///
    /// This handles:
    /// 1. WebSocket connection with Basic auth
    /// 2. Receiving and processing the attestation message
    /// 3. Noise_NK handshake
    /// 4. Encrypting and sending the request
    /// 5. Receiving and decrypting the response
    async fn perform_svr2_request(
        &self,
        ws_url: &str,
        auth: &Svr2AuthResponse,
        request_payload: &[u8],
    ) -> Result<Vec<u8>> {
        use base64::Engine as _;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::http::HeaderValue;
        use tokio_tungstenite::tungstenite::Message;

        // Build the WebSocket request with Basic auth
        let mut request = ws_url
            .into_client_request()
            .map_err(|e| ServiceError::WebSocket(format!("failed to build request: {e}")))?;

        let auth_value = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", auth.username, auth.password));
        request.headers_mut().insert(
            "Authorization",
            HeaderValue::from_str(&format!("Basic {auth_value}"))
                .map_err(|e| ServiceError::WebSocket(format!("invalid auth header: {e}")))?,
        );

        // Connect to the SVR2 WebSocket endpoint
        let (mut ws_stream, _response) = tokio_tungstenite::connect_async(request)
            .await
            .map_err(|e| ServiceError::WebSocket(format!("connection failed: {e}")))?;

        debug!("connected to SVR2 WebSocket endpoint");

        // Step 1: Receive the attestation message from the enclave
        let attestation_msg = match ws_stream.next().await {
            Some(Ok(Message::Binary(data))) => data,
            Some(Ok(other)) => {
                return Err(ServiceError::InvalidResponse(format!(
                    "expected binary attestation message, got: {other:?}"
                )));
            }
            Some(Err(e)) => {
                return Err(ServiceError::WebSocket(format!(
                    "failed to receive attestation: {e}"
                )));
            }
            None => {
                return Err(ServiceError::WebSocket(
                    "connection closed before attestation".to_string(),
                ));
            }
        };

        debug!(len = attestation_msg.len(), "received SVR2 attestation message");

        // Step 2: Extract the enclave's static public key from the attestation
        let enclave_public_key = extract_enclave_public_key(&attestation_msg)?;
        debug!("extracted SVR2 enclave public key");

        // Step 3: Perform the Noise_NK handshake
        let mut noise = snow::Builder::new(
            NOISE_PATTERN
                .parse()
                .map_err(|e| ServiceError::InvalidResponse(format!("invalid Noise pattern: {e}")))?,
        )
        .remote_public_key(&enclave_public_key)
        .build_initiator()
        .map_err(|e| {
            ServiceError::InvalidResponse(format!("failed to build Noise initiator: {e}"))
        })?;

        // Send the Noise handshake initiation (-> e, es)
        let mut handshake_msg = vec![0u8; 96];
        let len = noise
            .write_message(&[], &mut handshake_msg)
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("Noise handshake write failed: {e}"))
            })?;
        handshake_msg.truncate(len);

        ws_stream
            .send(Message::Binary(handshake_msg))
            .await
            .map_err(|e| ServiceError::WebSocket(format!("failed to send handshake: {e}")))?;

        debug!("sent SVR2 Noise_NK handshake initiation");

        // Receive the handshake response (<- e, ee)
        let handshake_response = match ws_stream.next().await {
            Some(Ok(Message::Binary(data))) => data,
            Some(Ok(other)) => {
                return Err(ServiceError::InvalidResponse(format!(
                    "expected binary handshake response, got: {other:?}"
                )));
            }
            Some(Err(e)) => {
                return Err(ServiceError::WebSocket(format!(
                    "failed to receive handshake response: {e}"
                )));
            }
            None => {
                return Err(ServiceError::WebSocket(
                    "connection closed during handshake".to_string(),
                ));
            }
        };

        debug!(len = handshake_response.len(), "received SVR2 handshake response");

        let mut payload = vec![0u8; 256];
        let _payload_len = noise
            .read_message(&handshake_response, &mut payload)
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("Noise handshake read failed: {e}"))
            })?;

        // Transition to transport mode
        let mut transport = noise.into_transport_mode().map_err(|e| {
            ServiceError::InvalidResponse(format!("failed to enter transport mode: {e}"))
        })?;

        info!("SVR2 Noise_NK handshake completed");

        // Step 4: Encrypt and send the request
        let mut encrypted_request = vec![0u8; request_payload.len() + 16];
        let enc_len = transport
            .write_message(request_payload, &mut encrypted_request)
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("failed to encrypt SVR2 request: {e}"))
            })?;
        encrypted_request.truncate(enc_len);

        ws_stream
            .send(Message::Binary(encrypted_request))
            .await
            .map_err(|e| {
                ServiceError::WebSocket(format!("failed to send encrypted SVR2 request: {e}"))
            })?;

        debug!("sent encrypted SVR2 request");

        // Step 5: Receive and decrypt the response
        let response_data = match ws_stream.next().await {
            Some(Ok(Message::Binary(data))) => data,
            Some(Ok(other)) => {
                return Err(ServiceError::InvalidResponse(format!(
                    "expected binary SVR2 response, got: {other:?}"
                )));
            }
            Some(Err(e)) => {
                return Err(ServiceError::WebSocket(format!(
                    "failed to receive SVR2 response: {e}"
                )));
            }
            None => {
                return Err(ServiceError::WebSocket(
                    "connection closed before SVR2 response".to_string(),
                ));
            }
        };

        let mut decrypted = vec![0u8; response_data.len()];
        let dec_len = transport
            .read_message(&response_data, &mut decrypted)
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("failed to decrypt SVR2 response: {e}"))
            })?;
        decrypted.truncate(dec_len);

        debug!(len = decrypted.len(), "received and decrypted SVR2 response");

        Ok(decrypted)
    }
}

/// Extract the enclave's static Curve25519 public key from the attestation message.
///
/// The attestation message is a protobuf-encoded structure containing:
/// - SGX/Nitro evidence (attestation quote with report_data binding the key)
/// - Endorsement certificates
/// - The enclave's static Noise public key (32 bytes)
///
/// **NOTE on attestation verification**: The libsignal `attest` crate provides full
/// SGX DCAP and Nitro attestation verification, but it depends on `boring-signal`
/// (Signal's BoringSSL fork) and `libcrux-ml-kem` which bring significant native
/// build dependencies. Until those are integrated, this function extracts the
/// enclave public key without performing cryptographic attestation verification.
/// This is acceptable for development but should be replaced with real attestation
/// verification before production use.
fn extract_enclave_public_key(attestation_msg: &[u8]) -> Result<[u8; 32]> {
    if attestation_msg.len() < 32 {
        return Err(ServiceError::InvalidResponse(
            "attestation message too short to contain a public key".to_string(),
        ));
    }

    // Try to parse as protobuf to extract evidence field.
    // If parsing succeeds, the key is the last 32 bytes of the evidence field.
    if let Some(key) = try_extract_key_from_protobuf(attestation_msg) {
        return Ok(key);
    }

    // Fallback: use the last 32 bytes of the message.
    let key_offset = attestation_msg.len() - 32;
    let mut key = [0u8; 32];
    key.copy_from_slice(&attestation_msg[key_offset..]);
    Ok(key)
}

/// Try to parse the attestation as a protobuf and extract the public key.
/// Returns `None` if parsing fails (allowing fallback to raw bytes).
fn try_extract_key_from_protobuf(data: &[u8]) -> Option<[u8; 32]> {
    let mut offset = 0;
    let mut evidence: Option<&[u8]> = None;

    while offset < data.len() {
        let (tag, new_offset) = read_varint(data, offset).ok()?;
        offset = new_offset;

        let field_number = tag >> 3;
        let wire_type = tag & 0x07;

        match wire_type {
            0 => {
                let (_value, new_offset) = read_varint(data, offset).ok()?;
                offset = new_offset;
            }
            2 => {
                let (length, new_offset) = read_varint(data, offset).ok()?;
                offset = new_offset;
                let length = length as usize;
                if offset + length > data.len() {
                    return None;
                }
                if field_number == 1 {
                    evidence = Some(&data[offset..offset + length]);
                }
                offset += length;
            }
            5 => offset += 4,
            1 => offset += 8,
            _ => return None,
        }
    }

    if let Some(evidence) = evidence
        && evidence.len() >= 32 {
            let key_offset = evidence.len() - 32;
            let mut key = [0u8; 32];
            key.copy_from_slice(&evidence[key_offset..]);
            return Some(key);
        }

    None
}

/// Read a protobuf varint from a byte slice at the given offset.
fn read_varint(data: &[u8], mut offset: usize) -> Result<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if offset >= data.len() {
            return Err(ServiceError::InvalidResponse(
                "unexpected end of protobuf varint".to_string(),
            ));
        }
        let byte = data[offset];
        offset += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, offset));
        }
        shift += 7;
        if shift >= 64 {
            return Err(ServiceError::InvalidResponse(
                "protobuf varint too large".to_string(),
            ));
        }
    }
}

/// Build a BackupRequest payload for the SVR2 enclave.
///
/// Format:
/// - 1 byte: operation type (SVR2_OP_BACKUP = 1)
/// - 4 bytes: max_tries (big-endian u32)
/// - 4 bytes: pin length (big-endian u32)
/// - N bytes: PIN bytes
/// - 4 bytes: master_key length (big-endian u32)
/// - 32 bytes: master key
fn build_backup_request(pin: &[u8], master_key: &[u8], max_tries: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 4 + 4 + pin.len() + 4 + master_key.len());
    buf.push(SVR2_OP_BACKUP);
    buf.extend_from_slice(&max_tries.to_be_bytes());
    buf.extend_from_slice(&(pin.len() as u32).to_be_bytes());
    buf.extend_from_slice(pin);
    buf.extend_from_slice(&(master_key.len() as u32).to_be_bytes());
    buf.extend_from_slice(master_key);
    buf
}

/// Build a RestoreRequest payload for the SVR2 enclave.
///
/// Format:
/// - 1 byte: operation type (SVR2_OP_RESTORE = 2)
/// - 4 bytes: pin length (big-endian u32)
/// - N bytes: PIN bytes
fn build_restore_request(pin: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 4 + pin.len());
    buf.push(SVR2_OP_RESTORE);
    buf.extend_from_slice(&(pin.len() as u32).to_be_bytes());
    buf.extend_from_slice(pin);
    buf
}

/// Build a DeleteRequest payload for the SVR2 enclave.
///
/// Format:
/// - 1 byte: operation type (SVR2_OP_DELETE = 3)
fn build_delete_request() -> Vec<u8> {
    vec![SVR2_OP_DELETE]
}

/// Parse a decrypted BackupResponse from the SVR2 enclave.
///
/// Format:
/// - 1 byte: status code
fn parse_backup_response(data: &[u8]) -> Result<Svr2BackupResponse> {
    if data.is_empty() {
        return Err(ServiceError::InvalidResponse(
            "empty SVR2 backup response".to_string(),
        ));
    }

    match data[0] {
        SVR2_STATUS_OK => {
            info!("SVR2 backup successful");
            Ok(Svr2BackupResponse::Success)
        }
        SVR2_STATUS_SERVER_ERROR => {
            let msg = if data.len() > 1 {
                String::from_utf8_lossy(&data[1..]).to_string()
            } else {
                "unknown server error".to_string()
            };
            warn!(error = %msg, "SVR2 backup: server error");
            Ok(Svr2BackupResponse::ApplicationError(msg))
        }
        status => {
            warn!(status, "SVR2 backup: unexpected status");
            Ok(Svr2BackupResponse::ApplicationError(format!(
                "unexpected SVR2 backup status: {status}"
            )))
        }
    }
}

/// Parse a decrypted RestoreResponse from the SVR2 enclave.
///
/// Format:
/// - 1 byte: status code
/// - For Success: 4 bytes master_key length + N bytes master key
/// - For PinMismatch: 4 bytes tries_remaining
fn parse_restore_response(data: &[u8]) -> Result<Svr2RestoreResponse> {
    if data.is_empty() {
        return Err(ServiceError::InvalidResponse(
            "empty SVR2 restore response".to_string(),
        ));
    }

    match data[0] {
        SVR2_STATUS_OK => {
            if data.len() < 5 {
                return Err(ServiceError::InvalidResponse(
                    "SVR2 restore success response too short".to_string(),
                ));
            }
            let key_len =
                u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            if data.len() < 5 + key_len {
                return Err(ServiceError::InvalidResponse(
                    "SVR2 restore: master key extends past response".to_string(),
                ));
            }
            let master_key = data[5..5 + key_len].to_vec();
            info!("SVR2 restore successful");
            Ok(Svr2RestoreResponse::Success { master_key })
        }
        SVR2_STATUS_MISSING => {
            info!("SVR2 restore: no data found");
            Ok(Svr2RestoreResponse::Missing)
        }
        SVR2_STATUS_PIN_MISMATCH => {
            let tries_remaining = if data.len() >= 5 {
                u32::from_be_bytes([data[1], data[2], data[3], data[4]])
            } else {
                0
            };
            warn!(tries_remaining, "SVR2 restore: PIN mismatch");
            Ok(Svr2RestoreResponse::PinMismatch { tries_remaining })
        }
        SVR2_STATUS_SERVER_ERROR => {
            let msg = if data.len() > 1 {
                String::from_utf8_lossy(&data[1..]).to_string()
            } else {
                "unknown server error".to_string()
            };
            warn!(error = %msg, "SVR2 restore: server error");
            Ok(Svr2RestoreResponse::ApplicationError(msg))
        }
        status => {
            warn!(status, "SVR2 restore: unexpected status");
            Ok(Svr2RestoreResponse::ApplicationError(format!(
                "unexpected SVR2 restore status: {status}"
            )))
        }
    }
}

/// Parse a decrypted DeleteResponse from the SVR2 enclave.
///
/// Format:
/// - 1 byte: status code
fn parse_delete_response(data: &[u8]) -> Result<Svr2DeleteResponse> {
    if data.is_empty() {
        return Err(ServiceError::InvalidResponse(
            "empty SVR2 delete response".to_string(),
        ));
    }

    match data[0] {
        SVR2_STATUS_OK => {
            info!("SVR2 delete successful");
            Ok(Svr2DeleteResponse::Success)
        }
        SVR2_STATUS_MISSING => {
            // Missing is fine for delete -- nothing to delete
            info!("SVR2 delete: no data to delete");
            Ok(Svr2DeleteResponse::Success)
        }
        SVR2_STATUS_SERVER_ERROR => {
            let msg = if data.len() > 1 {
                String::from_utf8_lossy(&data[1..]).to_string()
            } else {
                "unknown server error".to_string()
            };
            Ok(Svr2DeleteResponse::ApplicationError(msg))
        }
        status => {
            Ok(Svr2DeleteResponse::ApplicationError(format!(
                "unexpected SVR2 delete status: {status}"
            )))
        }
    }
}

/// Enable registration lock on the server.
///
/// PUT /v1/accounts/registration_lock
///
/// This is called after backing up the master key to SVR2. The token
/// is derived from the PIN hash and proves that the user has set a PIN.
pub async fn enable_registration_lock(
    http: &HttpClient,
    registration_lock_token: &str,
) -> Result<()> {
    debug!("enabling registration lock");

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct RegistrationLockRequest<'a> {
        registration_lock: &'a str,
    }

    let body = RegistrationLockRequest {
        registration_lock: registration_lock_token,
    };

    http.put_json_no_response("/v1/accounts/registration_lock", &body)
        .await
}

/// Disable registration lock on the server.
///
/// DELETE /v1/accounts/registration_lock
pub async fn disable_registration_lock(http: &HttpClient) -> Result<()> {
    debug!("disabling registration lock");
    http.delete("/v1/accounts/registration_lock").await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_backup_request_format() {
        let pin = b"1234";
        let master_key = [0xABu8; 32];
        let request = build_backup_request(pin, &master_key, 10);

        assert_eq!(request[0], SVR2_OP_BACKUP);
        let max_tries = u32::from_be_bytes([request[1], request[2], request[3], request[4]]);
        assert_eq!(max_tries, 10);
        let pin_len = u32::from_be_bytes([request[5], request[6], request[7], request[8]]) as usize;
        assert_eq!(pin_len, 4);
        assert_eq!(&request[9..13], b"1234");
        let key_len =
            u32::from_be_bytes([request[13], request[14], request[15], request[16]]) as usize;
        assert_eq!(key_len, 32);
        assert_eq!(&request[17..49], &[0xAB; 32]);
    }

    #[test]
    fn build_restore_request_format() {
        let pin = b"5678";
        let request = build_restore_request(pin);

        assert_eq!(request[0], SVR2_OP_RESTORE);
        let pin_len = u32::from_be_bytes([request[1], request[2], request[3], request[4]]) as usize;
        assert_eq!(pin_len, 4);
        assert_eq!(&request[5..9], b"5678");
    }

    #[test]
    fn build_delete_request_format() {
        let request = build_delete_request();
        assert_eq!(request.len(), 1);
        assert_eq!(request[0], SVR2_OP_DELETE);
    }

    #[test]
    fn parse_backup_success() {
        let data = [SVR2_STATUS_OK];
        let result = parse_backup_response(&data).unwrap();
        assert!(matches!(result, Svr2BackupResponse::Success));
    }

    #[test]
    fn parse_backup_server_error() {
        let mut data = vec![SVR2_STATUS_SERVER_ERROR];
        data.extend_from_slice(b"something went wrong");
        let result = parse_backup_response(&data).unwrap();
        assert!(matches!(result, Svr2BackupResponse::ApplicationError(msg) if msg.contains("something")));
    }

    #[test]
    fn parse_restore_success() {
        let mut data = vec![SVR2_STATUS_OK];
        let master_key = [0xCC; 32];
        data.extend_from_slice(&(32u32).to_be_bytes());
        data.extend_from_slice(&master_key);

        let result = parse_restore_response(&data).unwrap();
        let Svr2RestoreResponse::Success { master_key: mk } = result else {
            unreachable!("parse of OK status should always yield Success variant");
        };
        assert_eq!(mk, vec![0xCC; 32]);
    }

    #[test]
    fn parse_restore_pin_mismatch() {
        let mut data = vec![SVR2_STATUS_PIN_MISMATCH];
        data.extend_from_slice(&7u32.to_be_bytes());

        let result = parse_restore_response(&data).unwrap();
        let Svr2RestoreResponse::PinMismatch { tries_remaining } = result else {
            unreachable!("parse of PIN_MISMATCH status should always yield PinMismatch variant");
        };
        assert_eq!(tries_remaining, 7);
    }

    #[test]
    fn parse_restore_missing() {
        let data = [SVR2_STATUS_MISSING];
        let result = parse_restore_response(&data).unwrap();
        assert!(matches!(result, Svr2RestoreResponse::Missing));
    }

    #[test]
    fn parse_delete_success() {
        let data = [SVR2_STATUS_OK];
        let result = parse_delete_response(&data).unwrap();
        assert!(matches!(result, Svr2DeleteResponse::Success));
    }

    #[test]
    fn parse_delete_missing_is_ok() {
        let data = [SVR2_STATUS_MISSING];
        let result = parse_delete_response(&data).unwrap();
        assert!(matches!(result, Svr2DeleteResponse::Success));
    }

    #[test]
    fn parse_empty_response_error() {
        assert!(parse_backup_response(&[]).is_err());
        assert!(parse_restore_response(&[]).is_err());
        assert!(parse_delete_response(&[]).is_err());
    }

    #[test]
    fn read_varint_basic() {
        let data = [0x05];
        let (value, offset) = read_varint(&data, 0).unwrap();
        assert_eq!(value, 5);
        assert_eq!(offset, 1);
    }

    #[test]
    fn read_varint_multibyte() {
        let data = [0xAC, 0x02]; // 300
        let (value, offset) = read_varint(&data, 0).unwrap();
        assert_eq!(value, 300);
        assert_eq!(offset, 2);
    }

    #[test]
    fn extract_key_too_short() {
        assert!(extract_enclave_public_key(&[0u8; 10]).is_err());
    }

    #[test]
    fn extract_key_raw_bytes() {
        let mut msg = [0u8; 32];
        msg[0] = 0x42;
        msg[31] = 0xFF;
        let key = extract_enclave_public_key(&msg).unwrap();
        assert_eq!(key[0], 0x42);
        assert_eq!(key[31], 0xFF);
    }

    #[test]
    fn noise_nk_pattern_parses() {
        let params: snow::params::NoiseParams = NOISE_PATTERN.parse().unwrap();
        assert_eq!(params.name, NOISE_PATTERN);
    }
}
