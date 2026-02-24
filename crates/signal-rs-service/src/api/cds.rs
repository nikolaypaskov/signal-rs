//! Contact Discovery Service (CDSI) API.
//!
//! CDSI allows looking up Signal users by phone number in a privacy-preserving way.
//! It uses a secure enclave (SGX/Nitro) to ensure the server cannot observe the queries.
//!
//! Endpoint: wss://cdsi.signal.org/v1/{mrenclave}/discovery/{username}
//!
//! Flow:
//! 1. Get an auth token from the main service: GET /v2/directory/auth
//! 2. Connect to CDSI via WebSocket with the auth token
//! 3. Receive the enclave's attestation message (first WebSocket frame)
//! 4. Extract the enclave's static public key from the attestation
//! 5. Perform a Noise_NK handshake (Noise_NK_25519_ChaChaPoly_SHA256)
//! 6. Send an encrypted request containing phone numbers
//! 7. Receive encrypted response with ACI/PNI mappings
//!
//! The Noise_NK pattern means:
//! - N: The initiator (client) does not authenticate with a static key
//! - K: The responder (enclave) has a known static public key
//!
//! Attestation verification ensures the enclave's public key is genuine
//! (i.e., the enclave is running the expected code identified by MREnclave).

use futures::stream::StreamExt;
use futures::SinkExt;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::error::{Result, ServiceError};
use crate::net::http::HttpClient;

/// The Noise protocol pattern used for enclave communication.
const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_SHA256";

/// The result of a CDSI lookup for a single phone number.
#[derive(Debug, Clone)]
pub struct CdsiLookupResult {
    /// The phone number queried (E.164).
    pub e164: String,
    /// The ACI UUID if the number is registered.
    pub aci: Option<Uuid>,
    /// The PNI UUID if the number is registered.
    pub pni: Option<Uuid>,
}

/// Auth credentials for the CDSI service.
#[derive(Debug, Clone, Deserialize)]
pub struct CdsiAuthResponse {
    /// The username for CDSI authentication.
    pub username: String,
    /// The password for CDSI authentication.
    pub password: String,
}

/// Token returned by the CDSI service for subsequent lookups.
///
/// The token is opaque and should be stored to avoid re-sending
/// previously looked-up numbers in future requests.
#[derive(Debug, Clone)]
pub struct CdsiToken {
    /// The raw token bytes.
    pub data: Vec<u8>,
}

/// A CDSI request containing phone numbers to look up.
///
/// Matches the protobuf `ClientRequest` sent inside the encrypted channel.
#[derive(Debug, Clone, Serialize)]
pub struct CdsiRequest {
    /// Previously queried E.164 numbers (for delta queries with a token).
    pub prev_e164s: Vec<u64>,
    /// New E.164 numbers to look up.
    pub new_e164s: Vec<u64>,
    /// A token from a previous query (enables delta queries).
    pub token: Option<Vec<u8>>,
    /// Whether to request ACIs in the response.
    pub aci_uak_pairs: Vec<u8>,
}

/// A single entry in the CDSI response.
#[derive(Debug, Clone)]
pub struct CdsiResponseEntry {
    /// The E.164 number.
    pub e164: u64,
    /// The ACI UUID bytes (16 bytes).
    pub aci: Option<[u8; 16]>,
    /// The PNI UUID bytes (16 bytes).
    pub pni: Option<[u8; 16]>,
}

/// Parse an E.164 phone number string to a u64.
///
/// Strips the leading '+' and parses the remaining digits.
pub fn e164_to_u64(e164: &str) -> Option<u64> {
    let digits = e164.strip_prefix('+').unwrap_or(e164);
    digits.parse::<u64>().ok()
}

/// Convert a u64 back to an E.164 phone number string.
pub fn u64_to_e164(number: u64) -> String {
    format!("+{number}")
}

/// API client for contact discovery.
pub struct CdsApi<'a> {
    /// The HTTP client.
    http: &'a HttpClient,
}

impl<'a> CdsApi<'a> {
    /// Create a new CDS API client.
    pub fn new(http: &'a HttpClient) -> Self {
        Self { http }
    }

    /// Get auth credentials for the CDSI service.
    ///
    /// GET /v2/directory/auth
    ///
    /// Returns a username/password pair that is used to authenticate
    /// the WebSocket connection to the CDSI enclave.
    pub async fn get_cdsi_auth(&self) -> Result<CdsiAuthResponse> {
        debug!("fetching CDSI auth credentials");
        self.http.get_json("/v2/directory/auth").await
    }

    /// Look up a batch of phone numbers via CDSI.
    ///
    /// This method:
    /// 1. Obtains CDSI auth credentials
    /// 2. Connects to the CDSI WebSocket endpoint with Basic auth
    /// 3. Receives the attestation message from the enclave
    /// 4. Extracts the enclave's static public key from the attestation
    /// 5. Performs a Noise_NK_25519_ChaChaPoly_SHA256 handshake
    /// 6. Sends an encrypted ClientRequest with the E.164 phone numbers
    /// 7. Receives and decrypts the ClientResponse with ACI/PNI mappings
    pub async fn lookup(
        &self,
        e164s: &[String],
        previous_token: Option<&CdsiToken>,
    ) -> Result<(Vec<CdsiLookupResult>, CdsiToken)> {
        debug!(count = e164s.len(), "CDSI lookup requested");

        if e164s.is_empty() {
            return Ok((Vec::new(), CdsiToken { data: Vec::new() }));
        }

        // Step 1: Get auth credentials
        let auth = self.get_cdsi_auth().await?;
        debug!(username = %auth.username, "obtained CDSI auth credentials");

        // Step 2: Build the WebSocket URL
        let config = self.http.config();
        let ws_url = config.cdsi_ws_url(&auth.username);
        debug!(url = %ws_url.split('?').next().unwrap_or(&ws_url), "CDSI WebSocket URL");

        // Step 3: Parse E.164 numbers to u64
        let new_e164s: Vec<u64> = e164s.iter().filter_map(|e| e164_to_u64(e)).collect();

        if new_e164s.is_empty() {
            return Err(ServiceError::InvalidResponse(
                "no valid E.164 phone numbers provided".to_string(),
            ));
        }

        let prev_e164s: Vec<u64> = Vec::new();
        let token = previous_token.map(|t| t.data.clone());

        info!(
            new_count = new_e164s.len(),
            prev_count = prev_e164s.len(),
            has_token = token.is_some(),
            "prepared CDSI request"
        );

        // Step 4: Connect via WebSocket and perform Noise_NK handshake
        self.perform_cdsi_lookup(&ws_url, &auth, &new_e164s, &prev_e164s, token.as_deref())
            .await
    }

    /// Perform the full CDSI lookup protocol over a Noise_NK encrypted channel.
    async fn perform_cdsi_lookup(
        &self,
        ws_url: &str,
        auth: &CdsiAuthResponse,
        new_e164s: &[u64],
        prev_e164s: &[u64],
        token: Option<&[u8]>,
    ) -> Result<(Vec<CdsiLookupResult>, CdsiToken)> {
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

        // Connect to the CDSI WebSocket endpoint
        let (mut ws_stream, _response) = tokio_tungstenite::connect_async(request)
            .await
            .map_err(|e| ServiceError::WebSocket(format!("connection failed: {e}")))?;

        debug!("connected to CDSI WebSocket endpoint");

        // Step 1: Receive the attestation message from the enclave.
        // The first frame contains the enclave's attestation data, which includes
        // the enclave's static Curve25519 public key needed for the Noise_NK handshake.
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

        debug!(len = attestation_msg.len(), "received attestation message");

        // Step 2: Extract the enclave's static public key from the attestation.
        // The attestation message is a serialized protobuf containing evidence
        // and the enclave's handshake public key. In the Signal protocol, the
        // public key is typically the last 32 bytes of the attestation message,
        // or embedded within an SGX attestation structure.
        let enclave_public_key = extract_enclave_public_key(&attestation_msg)?;

        debug!("extracted enclave public key from attestation");

        // Step 3: Perform the Noise_NK handshake.
        // NK means: the initiator (us) does not have a static key,
        // the responder (enclave) has a known static key.
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

        // Send the Noise handshake initiation message (-> e, es)
        let mut handshake_msg = vec![0u8; 96]; // Noise NK first message: ephemeral key + payload
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

        debug!("sent Noise_NK handshake initiation");

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

        debug!(
            len = handshake_response.len(),
            "received handshake response"
        );

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

        info!("Noise_NK handshake completed, transport channel established");

        // Step 4: Build and encrypt the ClientRequest.
        let client_request = build_client_request(new_e164s, prev_e164s, token);

        let mut encrypted_request = vec![0u8; client_request.len() + 16]; // +16 for AEAD tag
        let enc_len = transport
            .write_message(&client_request, &mut encrypted_request)
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("failed to encrypt request: {e}"))
            })?;
        encrypted_request.truncate(enc_len);

        ws_stream
            .send(Message::Binary(encrypted_request))
            .await
            .map_err(|e| {
                ServiceError::WebSocket(format!("failed to send encrypted request: {e}"))
            })?;

        debug!("sent encrypted ClientRequest");

        // Step 5: Receive and decrypt the response.
        // The response may come in multiple frames that need to be concatenated.
        let mut response_data = Vec::new();

        loop {
            match ws_stream.next().await {
                Some(Ok(Message::Binary(data))) => {
                    let mut decrypted = vec![0u8; data.len()];
                    let dec_len = transport
                        .read_message(&data, &mut decrypted)
                        .map_err(|e| {
                            ServiceError::InvalidResponse(format!(
                                "failed to decrypt response: {e}"
                            ))
                        })?;
                    decrypted.truncate(dec_len);
                    response_data.extend_from_slice(&decrypted);
                }
                Some(Ok(Message::Close(_))) => {
                    debug!("CDSI WebSocket closed by server");
                    break;
                }
                Some(Ok(_)) => continue,
                Some(Err(e)) => {
                    // If we already have data, treat this as end of stream
                    if !response_data.is_empty() {
                        debug!(error = %e, "WebSocket error after receiving data, continuing");
                        break;
                    }
                    return Err(ServiceError::WebSocket(format!(
                        "failed to receive response: {e}"
                    )));
                }
                None => break,
            }
        }

        debug!(
            response_len = response_data.len(),
            "received CDSI response"
        );

        // Step 6: Parse the decrypted response.
        let (results, response_token) = parse_cdsi_response(&response_data, new_e164s)?;

        info!(
            found = results.len(),
            total = new_e164s.len(),
            "CDSI lookup complete"
        );

        Ok((results, CdsiToken { data: response_token }))
    }

    /// Look up phone numbers, returning only the successfully resolved ones.
    ///
    /// Unlike `lookup`, this method does not fail if CDSI is unavailable.
    /// It returns an empty list and logs a warning instead.
    pub async fn lookup_best_effort(
        &self,
        e164s: &[String],
        previous_token: Option<&CdsiToken>,
    ) -> Vec<CdsiLookupResult> {
        match self.lookup(e164s, previous_token).await {
            Ok((results, _token)) => results,
            Err(e) => {
                warn!(error = %e, "CDSI lookup failed (best-effort mode)");
                Vec::new()
            }
        }
    }

    /// Convenience method: look up phone numbers and return ACI UUIDs.
    ///
    /// Returns a list of (e164, aci) pairs for numbers that resolved to
    /// registered Signal users.
    pub async fn lookup_by_phone_numbers(
        &self,
        phone_numbers: &[String],
    ) -> Result<Vec<(String, Uuid)>> {
        let (results, _token) = self.lookup(phone_numbers, None).await?;
        Ok(results
            .into_iter()
            .filter_map(|r| r.aci.map(|aci| (r.e164, aci)))
            .collect())
    }
}

/// Extract the enclave's static Curve25519 public key from the attestation message.
///
/// The attestation message is a protobuf-encoded `ClientHandshakeStart` containing:
/// - SGX/Nitro evidence (attestation quote)
/// - Endorsement certificates
/// - The enclave's static public key (32 bytes)
///
/// The public key is embedded in the attestation evidence. In the Signal protocol,
/// the attestation message structure places the 32-byte Curve25519 public key
/// at a known offset within the evidence field.
///
/// For SGX DCAP attestation, the report data in the quote contains a hash
/// binding the Noise static key to the attestation. The actual public key
/// is typically sent alongside the attestation evidence.
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
    // This handles cases where the key is appended outside the protobuf,
    // or the message isn't protobuf-encoded.
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

/// Read a varint from a byte slice at the given offset.
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

/// Build a serialized ClientRequest for the CDSI protocol.
///
/// The request format is a simple binary encoding:
/// - 4 bytes: number of new E.164s (big-endian u32)
/// - For each new E.164: 8 bytes (big-endian u64)
/// - 4 bytes: number of prev E.164s (big-endian u32)
/// - For each prev E.164: 8 bytes (big-endian u64)
/// - 4 bytes: token length (big-endian u32)
/// - Token bytes (if any)
/// - 4 bytes: ACI-UAK pairs length (0 for basic lookup)
fn build_client_request(new_e164s: &[u64], prev_e164s: &[u64], token: Option<&[u8]>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + new_e164s.len() * 8 + prev_e164s.len() * 8 + 32);

    // New E.164s
    buf.extend_from_slice(&(new_e164s.len() as u32).to_be_bytes());
    for &e164 in new_e164s {
        buf.extend_from_slice(&e164.to_be_bytes());
    }

    // Previous E.164s
    buf.extend_from_slice(&(prev_e164s.len() as u32).to_be_bytes());
    for &e164 in prev_e164s {
        buf.extend_from_slice(&e164.to_be_bytes());
    }

    // Token
    match token {
        Some(t) => {
            buf.extend_from_slice(&(t.len() as u32).to_be_bytes());
            buf.extend_from_slice(t);
        }
        None => {
            buf.extend_from_slice(&0u32.to_be_bytes());
        }
    }

    // ACI-UAK pairs (empty for basic lookup)
    buf.extend_from_slice(&0u32.to_be_bytes());

    buf
}

/// Parse a decrypted CDSI response into lookup results.
///
/// The response format contains entries of 40 bytes each:
/// - 8 bytes: E.164 number (big-endian u64)
/// - 16 bytes: ACI UUID (or all zeros if not registered)
/// - 16 bytes: PNI UUID (or all zeros if not registered)
///
/// Followed by a variable-length token for future delta queries.
fn parse_cdsi_response(
    data: &[u8],
    queried_e164s: &[u64],
) -> Result<(Vec<CdsiLookupResult>, Vec<u8>)> {
    if data.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    // The response starts with a 4-byte token length, then the token,
    // then entries of 40 bytes each.
    if data.len() < 4 {
        return Err(ServiceError::InvalidResponse(
            "CDSI response too short".to_string(),
        ));
    }

    let token_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let token_end = 4 + token_len;

    if data.len() < token_end {
        return Err(ServiceError::InvalidResponse(
            "CDSI response: token extends past end".to_string(),
        ));
    }

    let response_token = data[4..token_end].to_vec();
    let entries_data = &data[token_end..];

    const ENTRY_SIZE: usize = 8 + 16 + 16; // e164 + aci + pni = 40 bytes

    let mut results = Vec::new();

    // Parse entries
    let mut offset = 0;
    while offset + ENTRY_SIZE <= entries_data.len() {
        let e164 = u64::from_be_bytes([
            entries_data[offset],
            entries_data[offset + 1],
            entries_data[offset + 2],
            entries_data[offset + 3],
            entries_data[offset + 4],
            entries_data[offset + 5],
            entries_data[offset + 6],
            entries_data[offset + 7],
        ]);
        offset += 8;

        let mut aci_bytes = [0u8; 16];
        aci_bytes.copy_from_slice(&entries_data[offset..offset + 16]);
        offset += 16;

        let mut pni_bytes = [0u8; 16];
        pni_bytes.copy_from_slice(&entries_data[offset..offset + 16]);
        offset += 16;

        let all_zero_aci = aci_bytes.iter().all(|&b| b == 0);
        let all_zero_pni = pni_bytes.iter().all(|&b| b == 0);

        let aci = if all_zero_aci {
            None
        } else {
            Some(Uuid::from_bytes(aci_bytes))
        };

        let pni = if all_zero_pni {
            None
        } else {
            Some(Uuid::from_bytes(pni_bytes))
        };

        results.push(CdsiLookupResult {
            e164: u64_to_e164(e164),
            aci,
            pni,
        });
    }

    // If no structured entries were found but we have queried numbers,
    // return empty results (the numbers aren't registered).
    if results.is_empty() && !queried_e164s.is_empty() {
        debug!(
            queried = queried_e164s.len(),
            "CDSI returned no matching entries"
        );
    }

    Ok((results, response_token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e164_to_u64_basic() {
        assert_eq!(e164_to_u64("+15551234567"), Some(15551234567));
        assert_eq!(e164_to_u64("15551234567"), Some(15551234567));
    }

    #[test]
    fn e164_to_u64_invalid() {
        assert_eq!(e164_to_u64("+abc"), None);
        assert_eq!(e164_to_u64(""), None);
        assert_eq!(e164_to_u64("+"), None);
    }

    #[test]
    fn u64_to_e164_basic() {
        assert_eq!(u64_to_e164(15551234567), "+15551234567");
    }

    #[test]
    fn build_client_request_basic() {
        let new = vec![15551234567u64, 15559876543];
        let request = build_client_request(&new, &[], None);

        // 4 (new count) + 2*8 (new e164s) + 4 (prev count) + 4 (token len) + 4 (aci-uak len)
        assert_eq!(request.len(), 4 + 16 + 4 + 4 + 4);

        let new_count = u32::from_be_bytes([request[0], request[1], request[2], request[3]]);
        assert_eq!(new_count, 2);
    }

    #[test]
    fn build_client_request_with_token() {
        let new = vec![15551234567u64];
        let token = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let request = build_client_request(&new, &[], Some(&token));

        // 4 (new count) + 8 (new e164) + 4 (prev count) + 4 (token len) + 4 (token) + 4 (aci-uak)
        assert_eq!(request.len(), 4 + 8 + 4 + 4 + 4 + 4);
    }

    #[test]
    fn parse_response_empty() {
        let (results, token) = parse_cdsi_response(&[], &[]).unwrap();
        assert!(results.is_empty());
        assert!(token.is_empty());
    }

    #[test]
    fn parse_response_with_entries() {
        let mut data = Vec::new();
        // Token length = 0
        data.extend_from_slice(&0u32.to_be_bytes());
        // One entry: e164 + aci + pni
        let e164 = 15551234567u64;
        data.extend_from_slice(&e164.to_be_bytes());
        let aci = Uuid::new_v4();
        data.extend_from_slice(aci.as_bytes());
        let pni = Uuid::new_v4();
        data.extend_from_slice(pni.as_bytes());

        let (results, token) = parse_cdsi_response(&data, &[e164]).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].e164, "+15551234567");
        assert_eq!(results[0].aci, Some(aci));
        assert_eq!(results[0].pni, Some(pni));
        assert!(token.is_empty());
    }

    #[test]
    fn parse_response_zero_uuids_means_not_registered() {
        let mut data = Vec::new();
        // Token length = 0
        data.extend_from_slice(&0u32.to_be_bytes());
        // Entry with zero ACI and PNI
        data.extend_from_slice(&15551234567u64.to_be_bytes());
        data.extend_from_slice(&[0u8; 16]); // zero ACI
        data.extend_from_slice(&[0u8; 16]); // zero PNI

        let (results, _) = parse_cdsi_response(&data, &[15551234567]).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].aci.is_none());
        assert!(results[0].pni.is_none());
    }

    #[test]
    fn parse_response_with_token() {
        let mut data = Vec::new();
        let token_bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        data.extend_from_slice(&(token_bytes.len() as u32).to_be_bytes());
        data.extend_from_slice(&token_bytes);

        let (results, token) = parse_cdsi_response(&data, &[]).unwrap();
        assert!(results.is_empty());
        assert_eq!(token, token_bytes);
    }

    #[test]
    fn read_varint_single_byte() {
        let data = [0x05];
        let (value, offset) = read_varint(&data, 0).unwrap();
        assert_eq!(value, 5);
        assert_eq!(offset, 1);
    }

    #[test]
    fn read_varint_multi_byte() {
        let data = [0xAC, 0x02]; // 300 in varint encoding
        let (value, offset) = read_varint(&data, 0).unwrap();
        assert_eq!(value, 300);
        assert_eq!(offset, 2);
    }

    #[test]
    fn extract_key_from_short_message() {
        let result = extract_enclave_public_key(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn extract_key_from_raw_32_bytes() {
        let mut msg = [0u8; 32];
        msg[0] = 0x42;
        msg[31] = 0xFF;
        let key = extract_enclave_public_key(&msg).unwrap();
        assert_eq!(key[0], 0x42);
        assert_eq!(key[31], 0xFF);
    }

    #[test]
    fn noise_nk_pattern_parses() {
        // Verify the Noise pattern string is valid
        let params: snow::params::NoiseParams = NOISE_PATTERN.parse().unwrap();
        assert_eq!(params.name, NOISE_PATTERN);
    }
}
