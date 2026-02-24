//! Message sending API.
//!
//! Endpoints:
//! - PUT  /v1/messages/{destination}       -- send to a single recipient
//! - PUT  /v1/messages/multi_recipient     -- send to multiple recipients (sealed sender)
//! - GET  /v1/messages                     -- retrieve queued messages (for non-WebSocket clients)

use base64::Engine;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tracing::debug;
use uuid::Uuid;

use crate::error::{Result, ServiceError};
use crate::net::http::HttpClient;

/// An outbound message envelope for a single device.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutgoingMessageEntity {
    /// The message type (e.g., ciphertext, prekey, etc.).
    pub r#type: u32,
    /// The destination device ID.
    pub destination_device_id: u32,
    /// The destination registration ID (for validation).
    pub destination_registration_id: u32,
    /// The base64-encoded ciphertext body.
    pub content: String,
}

/// The request body for sending a message.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageRequest {
    /// The list of message envelopes (one per device).
    pub messages: Vec<OutgoingMessageEntity>,
    /// Whether this message is online-only (no push notification).
    pub online: bool,
    /// Whether this message is urgent.
    pub urgent: bool,
    /// The message timestamp.
    pub timestamp: u64,
}

/// The server's response after sending a message.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendResponse {
    /// Whether the server needed to return stale device info.
    pub needs_sync: bool,
}

/// The 409 Conflict response body, indicating stale devices.
///
/// When the server returns 409, the response contains lists of
/// device IDs that are missing or extra relative to what was sent.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleDevicesResponse {
    /// Device IDs that were expected but not included in the request.
    #[serde(default)]
    pub missing_devices: Vec<u32>,
    /// Device IDs that were included but are no longer valid.
    #[serde(default)]
    pub extra_devices: Vec<u32>,
}

/// The 410 Gone response body, indicating stale sessions.
///
/// When the server returns 410, it means some sessions are outdated
/// and the sender should fetch fresh pre-key bundles.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleSessionsResponse {
    /// Device IDs for which sessions are stale.
    #[serde(default)]
    pub stale_devices: Vec<u32>,
}

/// Response from multi-recipient send.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiRecipientResponse {
    /// The list of UUIDs to which the message could not be delivered (404 recipients).
    #[serde(default)]
    pub uuids404: Vec<Uuid>,
}

/// An incoming envelope entity from the GET /v1/messages response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncomingEnvelopeEntity {
    /// The envelope type (maps to Envelope.Type).
    pub r#type: u32,
    /// The sender's service ID (ACI UUID string).
    #[serde(default)]
    pub source_uuid: Option<String>,
    /// The sender's device ID.
    #[serde(default)]
    pub source_device: Option<u32>,
    /// The destination UUID.
    #[serde(default)]
    pub destination_uuid: Option<String>,
    /// The message timestamp.
    #[serde(default)]
    pub timestamp: Option<u64>,
    /// The base64-encoded content bytes.
    #[serde(default)]
    pub content: Option<String>,
    /// The server-assigned GUID for acknowledging this message.
    #[serde(default)]
    pub server_guid: Option<String>,
    /// The server timestamp.
    #[serde(default)]
    pub server_timestamp: Option<u64>,
    /// Whether this is urgent.
    #[serde(default)]
    pub urgent: Option<bool>,
    /// Whether this is a story.
    #[serde(default)]
    pub story: Option<bool>,
    /// Reporting token (base64).
    #[serde(default)]
    pub reporting_token: Option<String>,
}

impl IncomingEnvelopeEntity {
    /// Decode the base64-encoded content field into raw bytes.
    pub fn content_bytes(&self) -> Option<Vec<u8>> {
        self.content.as_ref().and_then(|c| {
            base64::engine::general_purpose::STANDARD.decode(c).ok()
        })
    }
}

/// The response from GET /v1/messages.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncomingMessagesResponse {
    /// The list of pending envelope entities.
    #[serde(default)]
    pub messages: Vec<IncomingEnvelopeEntity>,
    /// Whether there are more messages to fetch.
    #[serde(default)]
    pub more: bool,
}

/// API client for message sending endpoints.
pub struct MessageApi<'a> {
    /// The HTTP client.
    http: &'a HttpClient,
}

impl<'a> MessageApi<'a> {
    /// Create a new message API client.
    pub fn new(http: &'a HttpClient) -> Self {
        Self { http }
    }

    /// Send a message to a single recipient.
    ///
    /// PUT /v1/messages/{destination}
    ///
    /// On success, returns `SendResponse` indicating whether a sync message is needed.
    /// On 409, the caller should handle `StaleDevicesResponse` (missing/extra devices).
    /// On 410, the caller should handle `StaleSessionsResponse` (stale sessions).
    pub async fn send_message(
        &self,
        destination: &Uuid,
        request: &SendMessageRequest,
    ) -> Result<SendResponse> {
        let path = format!("/v1/messages/{destination}");
        debug!(
            destination = %destination,
            device_count = request.messages.len(),
            "sending message"
        );
        self.http.put_json(&path, request).await
    }

    /// Send a message with an unidentified access key for sealed-sender delivery.
    ///
    /// PUT /v1/messages/{destination} with Unidentified-Access-Key header
    ///
    /// This allows sending messages without revealing the sender's identity
    /// to the server. The access key (derived from the recipient's profile key)
    /// replaces the standard Authorization header.
    pub async fn send_message_unidentified(
        &self,
        destination: &Uuid,
        request: &SendMessageRequest,
        unidentified_access_key: &str,
    ) -> Result<SendResponse> {
        let path = format!("/v1/messages/{destination}");
        debug!(
            destination = %destination,
            device_count = request.messages.len(),
            "sending message (unidentified / sealed sender)"
        );
        self.http
            .put_json_with_unidentified_access(&path, request, unidentified_access_key)
            .await
    }

    /// Send a message to multiple recipients using sealed sender.
    ///
    /// PUT /v1/messages/multi_recipient?ts={timestamp}&online={online}&urgent={urgent}&story={story}
    ///
    /// The payload is a binary-encoded multi-recipient message (not JSON).
    /// Returns information about recipients that could not be reached.
    pub async fn send_multi_recipient(
        &self,
        payload: &[u8],
        timestamp: u64,
        online: bool,
        urgent: bool,
        story: bool,
    ) -> Result<MultiRecipientResponse> {
        let path = format!(
            "/v1/messages/multi_recipient?ts={}&online={}&urgent={}&story={}",
            timestamp, online, urgent, story
        );
        debug!(
            timestamp = timestamp,
            online = online,
            urgent = urgent,
            story = story,
            "sending multi-recipient message"
        );
        let resp_bytes = self
            .http
            .put(&path, Bytes::copy_from_slice(payload))
            .await?;
        // Parse the response for any 404 recipients
        let text = String::from_utf8_lossy(&resp_bytes);
        if text.is_empty() || text == "{}" {
            return Ok(MultiRecipientResponse {
                uuids404: Vec::new(),
            });
        }
        serde_json::from_str(&text).map_err(ServiceError::Json)
    }

    /// Retrieve queued messages from the server.
    ///
    /// GET /v1/messages
    ///
    /// This is an alternative to WebSocket for retrieving pending messages.
    /// Returns the raw bytes of the response body.
    pub async fn get_messages(&self) -> Result<Vec<u8>> {
        debug!("fetching queued messages");
        let bytes = self.http.get("/v1/messages").await?;
        Ok(bytes.to_vec())
    }

    /// Retrieve queued messages from the server as structured entities.
    ///
    /// GET /v1/messages
    ///
    /// The server returns a JSON response with an array of envelope entities.
    /// Each entity includes a `server_guid` for acknowledgment and base64-encoded
    /// content for decryption.
    pub async fn get_messages_structured(&self) -> Result<IncomingMessagesResponse> {
        debug!("fetching queued messages (structured)");
        self.http.get_json("/v1/messages").await
    }

    /// Acknowledge that all messages have been received.
    ///
    /// DELETE /v1/messages/uuid/{server_guid}
    ///
    /// After processing a message, the client should acknowledge it
    /// so the server can remove it from the queue.
    pub async fn acknowledge_message(&self, server_guid: &str) -> Result<()> {
        let path = format!("/v1/messages/uuid/{server_guid}");
        debug!(guid = server_guid, "acknowledging message");
        self.http.delete(&path).await
    }
}
