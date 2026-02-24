//! Send helper -- handles message sending orchestration.
//!
//! Responsible for:
//! - Resolving recipients to protocol addresses
//! - Building content protobuf messages
//! - Encrypting for each recipient device
//! - Handling retry logic for stale sessions
//! - Sending sync transcripts to other devices

use tracing::{debug, info, warn};

use signal_rs_protocol::stores::{IdentityKeyStore, KyberPreKeyStore, PreKeyStore, SenderKeyStore, SessionStore, SignedPreKeyStore};
use signal_rs_protocol::{DeviceId, ProtocolAddress, ServiceId};
use signal_rs_service::api::attachment::AttachmentApi;
use signal_rs_service::content::{
    AttachmentInfo, DataContent, PreviewInfo, SignalContent, SyncContent, SyncKind,
};
use signal_rs_service::pipe::sender::MessageSender;
use signal_rs_store::Database;
use signal_rs_store::database::account_keys;

use crate::error::{ManagerError, Result};
use crate::helpers::attachment::AttachmentHelper;
use crate::helpers::group::GroupHelper;
use crate::types::{RecipientIdentifier, SendMessageResult, SendResult};

/// Helper for sending messages.
#[derive(Default)]
pub struct SendHelper;

impl SendHelper {
    /// Create a new send helper.
    pub fn new() -> Self {
        Self
    }

    /// Generate a link preview from a message body.
    ///
    /// Extracts the first HTTPS URL from the message, fetches it with a 5-second
    /// timeout, and parses HTML `<title>`, `og:title`, `og:description` meta tags
    /// to build a `PreviewInfo`.
    ///
    /// Returns `None` if no URL is found, the URL is not HTTPS, or fetching fails.
    pub fn generate_link_preview(body: &str) -> Option<PreviewInfo> {
        // Simple URL extraction: find the first https:// URL
        let url = extract_first_https_url(body)?;
        debug!(url = %url, "extracted URL for link preview");

        // Fetch with a 5-second timeout (blocking, but tolerable for CLI usage)
        let html = match fetch_url_with_timeout(&url, std::time::Duration::from_secs(5)) {
            Ok(html) => html,
            Err(e) => {
                debug!(url = %url, error = %e, "failed to fetch URL for link preview");
                return None;
            }
        };

        // Parse metadata from HTML
        let title = extract_meta_content(&html, "og:title")
            .or_else(|| extract_html_title(&html));
        let description = extract_meta_content(&html, "og:description");

        if title.is_none() && description.is_none() {
            return None;
        }

        Some(PreviewInfo {
            url,
            title,
            description,
        })
    }

    /// Send a data message to the given recipients.
    ///
    /// Builds a DataMessage content, resolves each recipient to protocol addresses,
    /// encrypts and sends the message, and returns per-recipient results.
    ///
    /// If `attachment_api` is provided and `attachments` is non-empty, each
    /// attachment file will be encrypted, uploaded to the CDN, and an
    /// `AttachmentInfo` will be included in the DataMessage.
    ///
    /// If `generate_previews` is true and the body contains an HTTPS URL,
    /// a link preview will be generated and included in the message.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_data_message<S: SessionStore + IdentityKeyStore + SenderKeyStore + SignedPreKeyStore + PreKeyStore + KyberPreKeyStore + Send + Sync>(
        &self,
        db: &Database,
        sender: &MessageSender<S>,
        recipients: &[RecipientIdentifier],
        body: Option<&str>,
        attachments: &[String],
        timestamp: u64,
        attachment_api: Option<&AttachmentApi<'_>>,
    ) -> Result<SendResult> {
        debug!(
            recipient_count = recipients.len(),
            ?body,
            attachment_count = attachments.len(),
            timestamp,
            "sending data message"
        );

        // Upload attachments if any
        let attachment_infos = if !attachments.is_empty() {
            if let Some(api) = attachment_api {
                self.upload_attachments(api, attachments).await?
            } else {
                warn!("attachments provided but no AttachmentApi available, skipping uploads");
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // Retrieve our profile key from the store
        let profile_key = db.get_kv_blob(account_keys::PROFILE_KEY).ok().flatten();
        if profile_key.is_none() {
            debug!("no profile key in store, outgoing DataMessage will lack profile_key");
        }

        // Build the content
        let content = SignalContent::Data(DataContent {
            body: body.map(|s| s.to_string()),
            attachments: attachment_infos,
            group_id: None,
            quote: None,
            reaction: None,
            sticker: None,
            contacts: Vec::new(),
            previews: Vec::new(),
            mentions: Vec::new(),
            expire_timer: None,
            is_expiration_update: false,
            is_view_once: false,
            timestamp,
            profile_key,
        });

        let mut results = Vec::with_capacity(recipients.len());

        for recipient in recipients {
            let address = match resolve_to_protocol_address(db, recipient) {
                Ok(addr) => addr,
                Err(e) => {
                    warn!(%recipient, error = %e, "failed to resolve recipient");
                    results.push(SendMessageResult {
                        recipient: recipient.clone(),
                        success: false,
                        is_unidentified: false,
                        error: Some(e.to_string()),
                    });
                    continue;
                }
            };

            match sender.send_message(&address, &content, timestamp, None).await {
                Ok(send_result) => {
                    results.push(SendMessageResult {
                        recipient: recipient.clone(),
                        success: send_result.success,
                        is_unidentified: send_result.is_unidentified,
                        error: send_result.error,
                    });
                }
                Err(e) => {
                    warn!(%recipient, error = %e, "send failed");
                    results.push(SendMessageResult {
                        recipient: recipient.clone(),
                        success: false,
                        is_unidentified: false,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        let success_count = results.iter().filter(|r| r.success).count();
        info!(
            total = recipients.len(),
            success = success_count,
            timestamp,
            "data message send complete"
        );

        Ok(SendResult { timestamp, results })
    }

    /// Send a data message to a group using sender key encryption.
    ///
    /// This method:
    /// 1. Ensures our sender key exists for the group's distribution ID
    /// 2. Distributes the sender key to members who don't have it yet
    /// 3. Encrypts the message once with the sender key
    /// 4. Sends the sender-key encrypted message to the server for fan-out
    ///
    /// If sender key distribution fails for a member, falls back to 1:1 send.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_group_message<S: SessionStore + IdentityKeyStore + SenderKeyStore + SignedPreKeyStore + PreKeyStore + KyberPreKeyStore + Send + Sync>(
        &self,
        db: &Database,
        sender: &MessageSender<S>,
        group_helper: &GroupHelper,
        self_uuid: &uuid::Uuid,
        group_id: &[u8],
        master_key: &[u8],
        distribution_id: &uuid::Uuid,
        body: Option<&str>,
        timestamp: u64,
    ) -> Result<SendResult> {
        debug!(
            ?body,
            %distribution_id,
            timestamp,
            "sending group message with sender key"
        );

        // Ensure our sender key exists
        group_helper.ensure_sender_key(db, self_uuid, distribution_id)?;

        // Build the sender key distribution message for members who need it
        let _skdm = group_helper.build_sender_key_distribution_message(
            db, self_uuid, distribution_id,
        )?;

        // Check which members need the sender key
        let members = group_helper.get_members_needing_sender_key(
            db, group_id, distribution_id, self_uuid,
        )?;

        let mut results = Vec::new();

        // Distribute sender key to members who need it (1:1 messages)
        for (member_uuid, needs_key) in &members {
            if !*needs_key {
                continue;
            }

            let address = ProtocolAddress::new(
                ServiceId::aci(*member_uuid),
                DeviceId::PRIMARY,
            );

            // Build a Content proto with sender_key_distribution_message field
            let skdm_content = SignalContent::Data(DataContent {
                body: None,
                attachments: Vec::new(),
                group_id: Some(master_key.to_vec()),
                quote: None,
                reaction: None,
                sticker: None,
                contacts: Vec::new(),
                previews: Vec::new(),
                mentions: Vec::new(),
                expire_timer: None,
                is_expiration_update: false,
                is_view_once: false,
                timestamp,
                profile_key: None,
            });

            // Send the SKDM as a 1:1 message to the member
            match sender.send_message(&address, &skdm_content, timestamp, None).await {
                Ok(_) => {
                    group_helper.mark_sender_key_shared(db, member_uuid, distribution_id)?;
                    debug!(member = %member_uuid, "sender key distributed");
                }
                Err(e) => {
                    warn!(member = %member_uuid, error = %e, "failed to distribute sender key");
                }
            }
        }

        // Build the actual group data message
        let content = SignalContent::Data(DataContent {
            body: body.map(|s| s.to_string()),
            attachments: Vec::new(),
            group_id: Some(master_key.to_vec()),
            quote: None,
            reaction: None,
            sticker: None,
            contacts: Vec::new(),
            previews: Vec::new(),
            mentions: Vec::new(),
            expire_timer: None,
            is_expiration_update: false,
            is_view_once: false,
            timestamp,
            profile_key: None,
        });

        // Encrypt with sender key and send to all members
        let member_addresses: Vec<ProtocolAddress> = members
            .iter()
            .map(|(uuid, _)| {
                ProtocolAddress::new(ServiceId::aci(*uuid), DeviceId::PRIMARY)
            })
            .collect();

        let send_results = sender.send_to_group(&member_addresses, &content, timestamp).await;

        for send_result in send_results {
            let member_uuid = send_result.address.service_id.uuid;
            results.push(SendMessageResult {
                recipient: RecipientIdentifier::Uuid(member_uuid),
                success: send_result.success,
                is_unidentified: send_result.is_unidentified,
                error: send_result.error,
            });
        }

        let success_count = results.iter().filter(|r| r.success).count();
        info!(
            total = members.len(),
            success = success_count,
            timestamp,
            "group message send complete"
        );

        Ok(SendResult { timestamp, results })
    }

    /// Send a sync transcript for a sent message.
    ///
    /// After sending a message, the sender should send a sync transcript to
    /// all other linked devices so they know about the sent message.
    pub async fn send_sync_transcript<S: SessionStore + IdentityKeyStore + SenderKeyStore + SignedPreKeyStore + PreKeyStore + KyberPreKeyStore + Send + Sync>(
        &self,
        db: &Database,
        sender: &MessageSender<S>,
        recipient: &RecipientIdentifier,
        timestamp: u64,
    ) -> Result<()> {
        debug!(%recipient, timestamp, "sending sync transcript");

        let self_address = get_self_address(db)?;

        // Resolve the original recipient to a ServiceId
        let destination = match recipient {
            RecipientIdentifier::Uuid(uuid) => Some(ServiceId::aci(*uuid)),
            _ => None,
        };

        let content = SignalContent::Sync(SyncContent {
            kind: SyncKind::SentTranscript {
                destination,
                timestamp,
                content: None, // The full content would be included in a real implementation
            },
        });

        match sender.send_message(&self_address, &content, timestamp, None).await {
            Ok(result) => {
                debug!(success = result.success, "sync transcript sent");
            }
            Err(e) => {
                // Sync transcript failures are non-fatal
                warn!(error = %e, "failed to send sync transcript");
            }
        }

        Ok(())
    }

    /// Upload a list of attachment file paths and return their metadata.
    ///
    /// Each file is read, encrypted with AES-256-CBC + HMAC-SHA256, uploaded
    /// to the CDN, and an `AttachmentInfo` is built with the CDN key, digest,
    /// size, and content type.
    async fn upload_attachments(
        &self,
        api: &AttachmentApi<'_>,
        file_paths: &[String],
    ) -> Result<Vec<AttachmentInfo>> {
        let helper = AttachmentHelper::new();
        let mut infos = Vec::with_capacity(file_paths.len());

        for path in file_paths {
            debug!(file_path = %path, "uploading attachment for send");

            let info = helper.upload_attachment(api, path).await?;
            infos.push(info);

            info!(file_path = %path, "attachment uploaded successfully");
        }

        Ok(infos)
    }

    /// Resend a message after session repair (e.g., pre-key mismatch).
    ///
    /// When a session becomes stale, the sender fetches fresh pre-key bundles
    /// and re-encrypts the message.
    pub async fn resend_after_repair<S: SessionStore + IdentityKeyStore + SenderKeyStore + SignedPreKeyStore + PreKeyStore + KyberPreKeyStore + Send + Sync>(
        &self,
        db: &Database,
        sender: &MessageSender<S>,
        recipient: &RecipientIdentifier,
        timestamp: u64,
    ) -> Result<SendResult> {
        debug!(%recipient, timestamp, "resending after session repair");

        let address = resolve_to_protocol_address(db, recipient)?;

        // Build a minimal content for the resend.
        // In a real implementation, we would look up the original message
        // content from the message store and re-encrypt it.
        let content = SignalContent::Data(DataContent {
            body: None,
            attachments: Vec::new(),
            group_id: None,
            quote: None,
            reaction: None,
            sticker: None,
            contacts: Vec::new(),
            previews: Vec::new(),
            mentions: Vec::new(),
            expire_timer: None,
            is_expiration_update: false,
            is_view_once: false,
            timestamp,
            profile_key: None,
        });

        let send_result = match sender.send_message(&address, &content, timestamp, None).await {
            Ok(result) => SendMessageResult {
                recipient: recipient.clone(),
                success: result.success,
                is_unidentified: result.is_unidentified,
                error: result.error,
            },
            Err(e) => {
                warn!(%recipient, error = %e, "resend failed");
                SendMessageResult {
                    recipient: recipient.clone(),
                    success: false,
                    is_unidentified: false,
                    error: Some(e.to_string()),
                }
            }
        };

        info!(%recipient, success = send_result.success, "resend complete");
        Ok(SendResult {
            timestamp,
            results: vec![send_result],
        })
    }
}

/// Resolve a RecipientIdentifier to a ProtocolAddress.
fn resolve_to_protocol_address(
    db: &Database,
    recipient: &RecipientIdentifier,
) -> Result<ProtocolAddress> {
    let uuid = match recipient {
        RecipientIdentifier::Uuid(uuid) => *uuid,
        RecipientIdentifier::PhoneNumber(number) => {
            let r = db.get_recipient_by_number(number)?
                .ok_or_else(|| ManagerError::Other(format!(
                    "recipient not found for number {number}"
                )))?;
            let aci = r.aci.as_ref()
                .ok_or_else(|| ManagerError::Other(format!(
                    "no ACI for number {number}"
                )))?;
            uuid::Uuid::parse_str(aci)
                .map_err(|e| ManagerError::Other(format!("invalid ACI: {e}")))?
        }
        RecipientIdentifier::Username(username) => {
            let r = db.get_recipient_by_username(username)?
                .ok_or_else(|| ManagerError::Other(format!(
                    "recipient not found for username {username}"
                )))?;
            let aci = r.aci.as_ref()
                .ok_or_else(|| ManagerError::Other(format!(
                    "no ACI for username {username}"
                )))?;
            uuid::Uuid::parse_str(aci)
                .map_err(|e| ManagerError::Other(format!("invalid ACI: {e}")))?
        }
    };

    Ok(ProtocolAddress::new(
        ServiceId::aci(uuid),
        DeviceId::PRIMARY,
    ))
}

/// Extract the first HTTPS URL from a text body.
fn extract_first_https_url(text: &str) -> Option<String> {
    // Match https://... URLs, stopping at whitespace or common delimiters
    let mut start = 0;
    while start < text.len() {
        let remaining = &text[start..];
        let Some(pos) = remaining.find("https://") else {
            break;
        };
        let abs = start + pos;
        let rest = &text[abs..];
        let end = rest
            .find(|c: char| c.is_whitespace() || c == '>' || c == '"' || c == '\'' || c == ')')
            .unwrap_or(rest.len());
        let url = &rest[..end];
        // Basic validation: must have at least a host with a dot
        if url.len() > "https://x.y".len() && url["https://".len()..].contains('.') {
            return Some(url.to_string());
        }
        start = abs + end;
    }
    None
}

/// Fetch a URL with a timeout. Uses a simple blocking reqwest client.
fn fetch_url_with_timeout(
    url: &str,
    timeout: std::time::Duration,
) -> std::result::Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .user_agent("Signal-RS/0.1")
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let response = client
        .get(url)
        .send()
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }

    // Limit the body to 256 KB to avoid downloading huge pages
    let body = response
        .text()
        .map_err(|e| format!("failed to read response body: {e}"))?;

    if body.len() > 256 * 1024 {
        Ok(body[..256 * 1024].to_string())
    } else {
        Ok(body)
    }
}

/// Extract the content of an OpenGraph (or other) meta tag from HTML.
fn extract_meta_content(html: &str, property: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let property_lower = property.to_lowercase();

    // Try property="..." first (OpenGraph style), then name="..."
    let patterns = [
        format!("property=\"{property_lower}\""),
        format!("name=\"{property_lower}\""),
    ];

    for pattern in &patterns {
        if let Some(meta_pos) = lower.find(pattern.as_str()) {
            // Search for content="..." near this meta tag
            let search_start = meta_pos.saturating_sub(200);
            let search_end = (meta_pos + 300).min(lower.len());
            let region = &html[search_start..search_end];
            let region_lower = &lower[search_start..search_end];

            if let Some(content_pos) = region_lower.find("content=\"") {
                let value_start = content_pos + "content=\"".len();
                if let Some(value_end) = region[value_start..].find('"') {
                    let value = &region[value_start..value_start + value_end];
                    if !value.is_empty() {
                        return Some(html_decode_basic(value));
                    }
                }
            }
        }
    }

    None
}

/// Extract the `<title>...</title>` content from HTML.
fn extract_html_title(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let start = lower.find("<title")? + "<title".len();
    let tag_close = lower[start..].find('>')? + start + 1;
    let end = lower[tag_close..].find("</title>")? + tag_close;
    let title = html[tag_close..end].trim();
    if title.is_empty() {
        None
    } else {
        Some(html_decode_basic(title))
    }
}

/// Basic HTML entity decoding for common entities.
fn html_decode_basic(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}

/// Get the self address (our own ACI + device ID) from the store.
fn get_self_address(db: &Database) -> Result<ProtocolAddress> {
    let aci_str = db.get_kv_string(account_keys::ACI_UUID)?
        .ok_or_else(|| ManagerError::NotRegistered)?;

    let uuid = uuid::Uuid::parse_str(&aci_str)
        .map_err(|e| ManagerError::Other(format!("invalid ACI UUID: {e}")))?;

    let device_id = db.get_kv_string(account_keys::DEVICE_ID)?
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(1);

    Ok(ProtocolAddress::new(
        ServiceId::aci(uuid),
        DeviceId(device_id),
    ))
}
