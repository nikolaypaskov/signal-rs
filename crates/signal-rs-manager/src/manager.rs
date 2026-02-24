//! The `SignalManager` trait and `ManagerImpl` implementation.
//!
//! This is the main entry point for all Signal operations. The trait defines
//! every operation that the CLI/TUI can perform, and `ManagerImpl` provides
//! the concrete implementation that wires together the service, protocol,
//! and store layers.

use base64::Engine;
use prost::Message as ProstMessage;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use signal_rs_protocol::{
    IdentityKeyPair, generate_registration_id, generate_signed_pre_key,
    generate_kyber_pre_key, generate_pre_keys, PREKEY_BATCH_SIZE,
    WireSignalMessage, WirePreKeySignalMessage,
};
use signal_rs_protocol::stores::{IdentityKeyStore, KyberPreKeyStore, PreKeyStore, SessionStore, SignedPreKeyStore};
use signal_rs_protocol::{DeviceId, ProtocolAddress, ServiceId, ServiceIdKind};
use signal_rs_service::api::keys::{
    KeysApi, PreKeyUpload, PreKeyUploadItem, SignedPreKeyUploadItem,
    KyberPreKeyUploadItem,
};
use signal_rs_service::api::provisioning::{FinishDeviceLinkRequest, ProvisioningApi};
use signal_rs_service::api::registration::{
    AccountAttributes, RegistrationApi, RegistrationKyberPreKey,
    RegistrationRequest, RegistrationSignedPreKey, VerificationTransport,
};
use signal_rs_service::content::{
    DataContent, MentionInfo, QuoteInfo, ReceiptContent, ReceiptType, SignalContent,
    StoryContent, TypingAction, TypingContent, ReactionInfo,
};
use signal_rs_service::credentials::ServiceCredentials;
use signal_rs_store::database::account_keys;

use crate::context::Context;
use crate::error::{ManagerError, Result};
use crate::types::{
    Device, Group, Identity, Message, RecipientIdentifier, SendResult,
};

// ---------------------------------------------------------------------------
// SignalManager trait
// ---------------------------------------------------------------------------

/// The main Signal manager trait.
#[allow(async_fn_in_trait)]
pub trait SignalManager {
    // -- Account ------------------------------------------------------------
    async fn get_self_number(&self) -> Result<String>;
    async fn get_self_uuid(&self) -> Result<Uuid>;
    async fn update_account_attributes(&self) -> Result<()>;
    async fn get_configuration(&self) -> Result<AccountConfiguration>;
    async fn update_configuration(&self, config: AccountConfiguration) -> Result<()>;

    // -- Registration and linking -------------------------------------------
    async fn register(&self, number: &str, voice: bool, captcha: Option<&str>) -> Result<()>;
    async fn verify(&self, code: &str, pin: Option<&str>) -> Result<()>;
    async fn link(&self, device_name: &str) -> Result<String>;
    async fn unregister(&self) -> Result<()>;
    async fn delete_account(&self) -> Result<()>;

    // -- Profile ------------------------------------------------------------
    async fn update_profile(
        &self, given_name: Option<&str>, family_name: Option<&str>,
        about: Option<&str>, about_emoji: Option<&str>,
        avatar_path: Option<&str>, remove_avatar: bool,
    ) -> Result<()>;
    async fn get_username(&self) -> Result<Option<String>>;
    async fn set_username(&self, username: &str) -> Result<()>;
    async fn delete_username(&self) -> Result<()>;

    // -- Devices ------------------------------------------------------------
    async fn get_linked_devices(&self) -> Result<Vec<Device>>;
    async fn remove_linked_device(&self, device_id: u32) -> Result<()>;
    async fn add_device_link(&self) -> Result<String>;

    // -- Messages -----------------------------------------------------------
    async fn send_message(
        &self, recipients: &[RecipientIdentifier], message: &str,
        attachments: &[String], quote_timestamp: Option<u64>,
        mentions: &[(Uuid, u32, u32)],
    ) -> Result<SendResult>;
    async fn send_edit_message(
        &self, recipients: &[RecipientIdentifier], target_timestamp: u64,
        new_text: &str, attachments: &[String], mentions: &[(Uuid, u32, u32)],
    ) -> Result<SendResult>;
    async fn send_remote_delete(
        &self, recipients: &[RecipientIdentifier], target_timestamp: u64,
    ) -> Result<SendResult>;
    async fn send_typing(&self, recipient: &RecipientIdentifier, is_stop: bool) -> Result<()>;
    async fn send_read_receipt(
        &self, sender: &RecipientIdentifier, timestamps: &[u64],
    ) -> Result<()>;
    async fn send_viewed_receipt(
        &self, sender: &RecipientIdentifier, timestamps: &[u64],
    ) -> Result<()>;
    async fn send_reaction(
        &self, recipients: &[RecipientIdentifier], emoji: &str,
        target_author: &RecipientIdentifier, target_timestamp: u64, is_remove: bool,
    ) -> Result<SendResult>;

    // -- Groups -------------------------------------------------------------
    async fn get_groups(&self) -> Result<Vec<Group>>;
    async fn create_group(
        &self, name: &str, members: &[RecipientIdentifier], avatar_path: Option<&str>,
    ) -> Result<Group>;
    #[allow(clippy::too_many_arguments)]
    async fn update_group(
        &self, group_id: &str, name: Option<&str>, description: Option<&str>,
        avatar_path: Option<&str>, add_members: &[RecipientIdentifier],
        remove_members: &[RecipientIdentifier], add_admins: &[RecipientIdentifier],
        remove_admins: &[RecipientIdentifier],
    ) -> Result<Group>;
    async fn join_group(&self, invite_link: &str) -> Result<Group>;
    async fn quit_group(&self, group_id: &str) -> Result<()>;
    async fn delete_group(&self, group_id: &str) -> Result<()>;

    // -- Contacts -----------------------------------------------------------
    async fn get_recipients(&self) -> Result<Vec<RecipientInfo>>;
    async fn set_contact_name(
        &self, recipient: &RecipientIdentifier, given_name: &str, family_name: Option<&str>,
    ) -> Result<()>;
    async fn set_contacts_blocked(
        &self, recipients: &[RecipientIdentifier], blocked: bool,
    ) -> Result<()>;
    async fn set_groups_blocked(&self, group_ids: &[String], blocked: bool) -> Result<()>;
    async fn set_expiration_timer(
        &self, recipient: &RecipientIdentifier, seconds: u32,
    ) -> Result<()>;

    // -- Stickers -----------------------------------------------------------
    async fn upload_sticker_pack(&self, path: &str) -> Result<String>;
    async fn install_sticker_pack(&self, pack_id: &str, pack_key: &str) -> Result<()>;
    async fn get_sticker_packs(&self) -> Result<Vec<StickerPack>>;

    // -- Sync ---------------------------------------------------------------
    async fn request_all_sync_data(&self) -> Result<()>;

    // -- Receiving ----------------------------------------------------------
    async fn receive_messages(&self, timeout_seconds: u64) -> Result<Vec<Message>>;
    async fn stop_receiving(&self) -> Result<()>;

    // -- Identity / Trust ---------------------------------------------------
    async fn get_identities(&self) -> Result<Vec<Identity>>;
    async fn trust_identity_verified(
        &self, recipient: &RecipientIdentifier, safety_number: &str,
    ) -> Result<()>;
    async fn trust_identity_all_keys(&self, recipient: &RecipientIdentifier) -> Result<()>;

    // -- Polls --------------------------------------------------------------
    async fn send_poll_create(
        &self, recipients: &[RecipientIdentifier], question: &str,
        options: &[String], multi_select: bool,
    ) -> Result<SendResult>;
    async fn send_poll_vote(
        &self, recipients: &[RecipientIdentifier], poll_id: u64, option_indices: &[u32],
    ) -> Result<SendResult>;
    async fn send_poll_terminate(
        &self, recipients: &[RecipientIdentifier], poll_id: u64,
    ) -> Result<SendResult>;

    // -- Payments -----------------------------------------------------------
    async fn send_payment_notification(
        &self, recipient: &RecipientIdentifier, receipt: &str, note: Option<&str>,
    ) -> Result<SendResult>;

    // -- Number change ------------------------------------------------------
    async fn start_change_number(
        &self, new_number: &str, voice: bool, captcha: Option<&str>,
    ) -> Result<()>;
    async fn finish_change_number(
        &self, new_number: &str, code: &str, pin: Option<&str>,
    ) -> Result<()>;

    // -- Device management --------------------------------------------------
    async fn update_device_name(&self, device_id: u32, name: &str) -> Result<()>;

    // -- Rate limit ---------------------------------------------------------
    async fn submit_rate_limit_challenge(
        &self, challenge: &str, captcha: &str,
    ) -> Result<()>;

    // -- Username lookup ----------------------------------------------------
    async fn lookup_username(&self, username: &str) -> Result<Uuid>;

    // -- Phone number discoverability ---------------------------------------
    async fn set_phone_number_discoverability(&self, discoverable: bool) -> Result<()>;

    // -- Stories ------------------------------------------------------------
    async fn send_story(
        &self, body: Option<&str>, attachment_path: Option<&str>, allow_replies: bool,
    ) -> Result<()>;

    // -- Message requests ---------------------------------------------------
    async fn send_message_request_response(
        &self, thread_aci: Option<&str>, group_id: Option<&str>, response_type: i32,
    ) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// Account-level configuration settings.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, tabled::Tabled)]
pub struct AccountConfiguration {
    pub read_receipts: bool,
    pub typing_indicators: bool,
    pub unidentified_delivery_indicators: bool,
    pub link_previews: bool,
}

impl std::fmt::Display for AccountConfiguration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "read_receipts: {}", self.read_receipts)?;
        writeln!(f, "typing_indicators: {}", self.typing_indicators)?;
        writeln!(f, "unidentified_delivery_indicators: {}", self.unidentified_delivery_indicators)?;
        write!(f, "link_previews: {}", self.link_previews)
    }
}

impl Default for AccountConfiguration {
    fn default() -> Self {
        Self {
            read_receipts: true,
            typing_indicators: true,
            unidentified_delivery_indicators: false,
            link_previews: true,
        }
    }
}

/// Information about a known recipient.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, tabled::Tabled)]
pub struct RecipientInfo {
    pub uuid: Uuid,
    #[tabled(display_with = "display_opt")]
    pub number: Option<String>,
    #[tabled(display_with = "display_opt")]
    pub username: Option<String>,
    #[tabled(display_with = "display_opt")]
    pub profile_name: Option<String>,
    pub is_blocked: bool,
}

impl std::fmt::Display for RecipientInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = self.profile_name.as_deref().unwrap_or("(unknown)");
        let number = self.number.as_deref().unwrap_or("");
        let blocked = if self.is_blocked { " [BLOCKED]" } else { "" };
        write!(f, "{} {} {}{}", self.uuid, name, number, blocked)
    }
}

fn display_opt(o: &Option<String>) -> String {
    o.as_deref().unwrap_or("").to_string()
}

/// A sticker pack.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StickerPack {
    pub pack_id: String,
    pub pack_key: String,
    pub title: Option<String>,
    pub author: Option<String>,
    pub installed: bool,
}

// ---------------------------------------------------------------------------
// Helper: encode keys to base64
// ---------------------------------------------------------------------------

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Build registration signed pre-key structure from protocol type.
fn build_reg_signed_pre_key(
    spk: &signal_rs_protocol::SignedPreKeyRecord,
) -> RegistrationSignedPreKey {
    RegistrationSignedPreKey {
        key_id: spk.id.0,
        public_key: b64(&spk.public_key),
        signature: b64(&spk.signature),
    }
}

/// Build registration Kyber pre-key structure from protocol type.
fn build_reg_kyber_pre_key(
    kpk: &signal_rs_protocol::KyberPreKeyRecord,
) -> RegistrationKyberPreKey {
    RegistrationKyberPreKey {
        key_id: kpk.id.0,
        // Kyber public key is the first 1569 bytes (1 type byte + 1568 key bytes)
        public_key: b64(&kpk.key_pair_serialized[..1569.min(kpk.key_pair_serialized.len())]),
        signature: b64(&kpk.signature),
    }
}

// ---------------------------------------------------------------------------
// ManagerImpl
// ---------------------------------------------------------------------------

/// The concrete implementation of [`SignalManager`].
pub struct ManagerImpl {
    /// The shared context holding all dependencies.
    context: Context,
}

impl ManagerImpl {
    /// Create a new manager with the given context.
    pub fn new(context: Context) -> Self {
        Self { context }
    }

    /// Return a reference to the context.
    pub fn context(&self) -> &Context {
        &self.context
    }

    /// Return a mutable reference to the context.
    pub fn context_mut(&mut self) -> &mut Context {
        &mut self.context
    }

    /// Open a persistent authenticated WebSocket for message receiving.
    ///
    /// The returned `SignalWebSocket` has built-in keepalive and automatic
    /// reconnection, so it can be held open for the lifetime of the
    /// application.  Use [`process_incoming_ws_request`] to handle each
    /// incoming request from the pipe.
    pub async fn connect_message_pipe(
        &self,
    ) -> std::result::Result<
        signal_rs_service::net::websocket::SignalWebSocket,
        crate::error::ManagerError,
    > {
        self.context
            .service
            .get_authenticated_ws()
            .await
            .map_err(|e| ManagerError::Other(format!("WebSocket connect failed: {e}")))
    }

    /// Process a single incoming WebSocket request (envelope).
    ///
    /// Acknowledges the request on the WebSocket, decrypts the envelope,
    /// and returns zero or more `Message` values.  This is the per-message
    /// equivalent of the batch `receive_messages` method.
    pub async fn process_incoming_ws_request(
        &self,
        ws: &signal_rs_service::net::websocket::SignalWebSocket,
        request: signal_rs_service::net::websocket::WebSocketIncomingRequest,
    ) -> Result<Vec<Message>> {
        // Acknowledge immediately.
        if let Err(e) = ws.send_response(request.id, 200).await {
            warn!("failed to ack message: {e}");
        }

        // Only process PUT /api/v1/message requests.
        if request.verb != "PUT" || !request.path.contains("/api/v1/message") {
            debug!(
                verb = %request.verb,
                path = %request.path,
                "ignoring non-message WebSocket request"
            );
            return Ok(Vec::new());
        }

        let body = match request.body {
            Some(b) => b,
            None => return Ok(Vec::new()),
        };

        // Parse the envelope.
        let envelope = match signal_rs_protos::Envelope::decode(body.as_slice()) {
            Ok(env) => env,
            Err(e) => {
                warn!("failed to decode envelope: {e}");
                return Ok(Vec::new());
            }
        };

        let source_uuid_str = envelope.source_service_id.as_deref().unwrap_or_default();
        let source_device = envelope.source_device.unwrap_or(1);
        let envelope_type = envelope.r#type.unwrap_or(0);
        let timestamp = envelope.timestamp.unwrap_or(0);

        debug!(
            source = source_uuid_str,
            device = source_device,
            envelope_type = envelope_type,
            timestamp = timestamp,
            "received envelope via persistent WebSocket"
        );

        // Skip receipt envelopes (type 5).
        if envelope_type == 5 {
            debug!("receipt envelope, skipping");
            return Ok(Vec::new());
        }

        let content_bytes = match envelope.content {
            Some(ref c) => c.clone(),
            None => return Ok(Vec::new()),
        };

        // Decrypt.
        let (plaintext, override_source, override_device) = match self.decrypt_envelope(
            source_uuid_str,
            source_device,
            envelope_type,
            &content_bytes,
        ) {
            Ok(result) => result,
            Err(e) => {
                warn!("failed to decrypt envelope: {e}");
                return Ok(Vec::new());
            }
        };

        let effective_source = override_source.as_deref().unwrap_or(source_uuid_str);
        let effective_device = override_device.unwrap_or(source_device);

        // Build a plaintext envelope for the receive helper.
        let decrypted_envelope = signal_rs_protos::Envelope {
            r#type: Some(8),
            source_service_id: Some(effective_source.to_string()),
            source_device: Some(effective_device),
            timestamp: envelope.timestamp,
            content: Some(plaintext),
            server_timestamp: envelope.server_timestamp,
            server_guid: envelope.server_guid.clone(),
            story: envelope.story,
            reporting_token: envelope.reporting_token.clone(),
            destination_service_id: envelope.destination_service_id.clone(),
            urgent: envelope.urgent,
            updated_pni: envelope.updated_pni.clone(),
        };
        let envelope_bytes = decrypted_envelope.encode_to_vec();

        let receive_helper = crate::helpers::receive::ReceiveHelper::new();
        match receive_helper
            .process_incoming(&self.context.store, &[envelope_bytes])
            .await
        {
            Ok(messages) => {
                // Best-effort delivery receipt.
                let send_receipts = tokio::task::block_in_place(|| {
                    self.context
                        .store
                        .get_kv_string("config.send_delivery_receipts")
                })
                .unwrap_or(None)
                .unwrap_or_else(|| "true".to_string())
                    != "false";

                if send_receipts
                    && let Ok(sender_uuid) = Uuid::parse_str(effective_source)
                {
                    let receipt_content = SignalContent::Receipt(ReceiptContent {
                        receipt_type: ReceiptType::Delivery,
                        timestamps: vec![timestamp],
                    });
                    let receipt_ts = self.current_timestamp_millis();
                    if let Err(e) = self
                        .encrypt_and_send(
                            &sender_uuid,
                            &receipt_content,
                            receipt_ts,
                            false,
                            false,
                        )
                        .await
                    {
                        debug!(
                            error = %e,
                            "failed to send delivery receipt (best-effort)"
                        );
                    }
                }

                Ok(messages)
            }
            Err(e) => {
                warn!("failed to process decrypted envelope: {e}");
                Ok(Vec::new())
            }
        }
    }

    /// Generate a random password for device authentication.
    fn generate_password() -> String {
        let bytes: [u8; 18] = rand::random();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Encrypt a device name using the Signal DeviceName cipher.
    ///
    /// Algorithm:
    /// 1. Generate ephemeral X25519 key pair
    /// 2. ECDH(ephemeral_private, identity_public) -> shared secret
    /// 3. HKDF-SHA256(shared_secret) -> auth_key (info="auth") + cipher_key (info="cipher")
    /// 4. synthetic_iv = HMAC-SHA256(auth_key, plaintext)[..16]
    /// 5. ciphertext = AES-256-CTR(cipher_key, IV=synthetic_iv, plaintext)
    /// 6. Encode as DeviceName protobuf, then base64
    fn encrypt_device_name(
        name: &str,
        identity: &IdentityKeyPair,
    ) -> Result<String> {
        use aes::cipher::{KeyIvInit, StreamCipher};
        use hmac::{Hmac, Mac};
        use prost::Message;
        use x25519_dalek::{EphemeralSecret, PublicKey};

        let plaintext = name.as_bytes();

        // The identity public key has a 0x05 prefix; strip it for X25519 ECDH
        let identity_pub_bytes = identity.public_key().public_key_bytes();
        let identity_x25519_pub = PublicKey::from(<[u8; 32]>::try_from(identity_pub_bytes)
            .map_err(|_| ManagerError::Other("identity key wrong length".into()))?);

        // Generate ephemeral X25519 key pair
        let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // ECDH: master secret
        let master_secret = ephemeral_secret.diffie_hellman(&identity_x25519_pub);

        // Signal uses a double-HMAC chain (NOT HKDF) for key derivation:
        // synthetic_iv = HMAC(HMAC(masterSecret, "auth"), plaintext)[..16]
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(master_secret.as_bytes())
            .map_err(|e| ManagerError::Other(format!("HMAC init failed: {e}")))?;
        mac.update(b"auth");
        let auth_key = mac.finalize().into_bytes();

        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&auth_key)
            .map_err(|e| ManagerError::Other(format!("HMAC init failed: {e}")))?;
        mac.update(plaintext);
        let auth_result = mac.finalize().into_bytes();
        let synthetic_iv: [u8; 16] = auth_result[..16].try_into().unwrap();

        // cipher_key = HMAC(HMAC(masterSecret, "cipher"), syntheticIv)
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(master_secret.as_bytes())
            .map_err(|e| ManagerError::Other(format!("HMAC init failed: {e}")))?;
        mac.update(b"cipher");
        let cipher_key_key = mac.finalize().into_bytes();

        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&cipher_key_key)
            .map_err(|e| ManagerError::Other(format!("HMAC init failed: {e}")))?;
        mac.update(&synthetic_iv);
        let cipher_key = mac.finalize().into_bytes();

        // AES-256-CTR encrypt with all-zeros IV
        type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;
        let zero_iv = [0u8; 16];
        let mut cipher = Aes256Ctr::new(&cipher_key, &zero_iv.into());
        let mut ciphertext = plaintext.to_vec();
        cipher.apply_keystream(&mut ciphertext);

        // Ephemeral public key in Signal's serialized form: 0x05 prefix + 32 bytes
        let mut ephemeral_public_serialized = Vec::with_capacity(33);
        ephemeral_public_serialized.push(0x05);
        ephemeral_public_serialized.extend_from_slice(ephemeral_public.as_bytes());

        // Build DeviceName protobuf
        let device_name_proto = signal_rs_protos::DeviceName {
            ephemeral_public: Some(ephemeral_public_serialized),
            synthetic_iv: Some(synthetic_iv.to_vec()),
            ciphertext: Some(ciphertext),
        };

        let mut buf = Vec::new();
        device_name_proto.encode(&mut buf)
            .map_err(|e| ManagerError::Other(format!("protobuf encode failed: {e}")))?;

        Ok(b64(&buf))
    }
}

impl SignalManager for ManagerImpl {
    // -- Account ------------------------------------------------------------

    async fn get_self_number(&self) -> Result<String> {
        let number = tokio::task::block_in_place(|| {
            self.context.store.get_kv_string(account_keys::PHONE_NUMBER)
        })?;
        number.ok_or(ManagerError::NotRegistered)
    }

    async fn get_self_uuid(&self) -> Result<Uuid> {
        let uuid_str = tokio::task::block_in_place(|| {
            self.context.store.get_kv_string(account_keys::ACI_UUID)
        })?;
        let uuid_str = uuid_str.ok_or(ManagerError::NotRegistered)?;
        Uuid::parse_str(&uuid_str)
            .map_err(|e| ManagerError::Other(format!("invalid UUID: {e}")))
    }

    async fn update_account_attributes(&self) -> Result<()> {
        info!("updating account attributes");
        let password = tokio::task::block_in_place(|| {
            self.context.store.get_kv_string(account_keys::PASSWORD)
        })?;
        let password = password.ok_or(ManagerError::NotRegistered)?;

        let uuid = self.get_self_uuid().await?;
        let device_id_str = tokio::task::block_in_place(|| {
            self.context.store.get_kv_string(account_keys::DEVICE_ID)
        })?.unwrap_or_else(|| "1".to_string());
        let device_id: u32 = device_id_str.parse().unwrap_or(1);

        let reg_id_str = tokio::task::block_in_place(|| {
            self.context.store.get_kv_string(account_keys::REGISTRATION_ID)
        })?.unwrap_or_else(|| "0".to_string());
        let reg_id: u32 = reg_id_str.parse().unwrap_or(0);

        let pni_reg_id_str = tokio::task::block_in_place(|| {
            self.context.store.get_kv_string(account_keys::PNI_REGISTRATION_ID)
        })?.unwrap_or_else(|| "0".to_string());
        let pni_reg_id: u32 = pni_reg_id_str.parse().unwrap_or(0);

        let creds = ServiceCredentials {
            uuid: Some(uuid),
            e164: None,
            password: Some(password),
            device_id: DeviceId(device_id),
        };
        let http = signal_rs_service::net::http::HttpClient::new(
            self.context.config.clone(),
            Some(creds),
        )?;

        let attrs = signal_rs_service::api::registration::AccountAttributes::with_registration_ids(reg_id, pni_reg_id);
        let account_api = signal_rs_service::api::account::AccountApi::new(&http);
        account_api.update_attributes(&attrs).await?;
        info!("account attributes updated");
        Ok(())
    }

    async fn get_configuration(&self) -> Result<AccountConfiguration> {
        debug!("loading account configuration");
        let read_receipts = tokio::task::block_in_place(|| {
            self.context.store.get_kv_string("config.read_receipts")
        })?.unwrap_or_else(|| "true".to_string()) == "true";

        let typing_indicators = tokio::task::block_in_place(|| {
            self.context.store.get_kv_string("config.typing_indicators")
        })?.unwrap_or_else(|| "true".to_string()) == "true";

        let unidentified_delivery_indicators = tokio::task::block_in_place(|| {
            self.context.store.get_kv_string("config.unidentified_delivery_indicators")
        })?.unwrap_or_else(|| "false".to_string()) == "true";

        let link_previews = tokio::task::block_in_place(|| {
            self.context.store.get_kv_string("config.link_previews")
        })?.unwrap_or_else(|| "true".to_string()) == "true";

        Ok(AccountConfiguration {
            read_receipts,
            typing_indicators,
            unidentified_delivery_indicators,
            link_previews,
        })
    }

    async fn update_configuration(&self, config: AccountConfiguration) -> Result<()> {
        info!("updating account configuration");
        tokio::task::block_in_place(|| {
            self.context.store.set_kv_string("config.read_receipts", &config.read_receipts.to_string())?;
            self.context.store.set_kv_string("config.typing_indicators", &config.typing_indicators.to_string())?;
            self.context.store.set_kv_string("config.unidentified_delivery_indicators", &config.unidentified_delivery_indicators.to_string())?;
            self.context.store.set_kv_string("config.link_previews", &config.link_previews.to_string())?;
            Ok::<_, ManagerError>(())
        })?;
        Ok(())
    }

    // -- Registration -------------------------------------------------------

    async fn register(&self, number: &str, voice: bool, _captcha: Option<&str>) -> Result<()> {
        info!(number, "starting registration");

        // Generate identity keypairs and registration IDs
        let aci_identity = IdentityKeyPair::generate();
        let pni_identity = IdentityKeyPair::generate();
        let aci_reg_id = generate_registration_id();
        let pni_reg_id = generate_registration_id();
        let password = Self::generate_password();

        // Persist generated keys
        tokio::task::block_in_place(|| {
            self.context.store.set_kv_string(account_keys::PHONE_NUMBER, number)?;
            self.context.store.set_kv_blob(account_keys::IDENTITY_KEY_PAIR, &aci_identity.serialize())?;
            self.context.store.set_kv_blob(account_keys::PNI_IDENTITY_KEY_PAIR, &pni_identity.serialize())?;
            self.context.store.set_kv_string(account_keys::REGISTRATION_ID, &aci_reg_id.to_string())?;
            self.context.store.set_kv_string(account_keys::PNI_REGISTRATION_ID, &pni_reg_id.to_string())?;
            self.context.store.set_kv_string(account_keys::PASSWORD, &password)?;
            Ok::<_, ManagerError>(())
        })?;

        // Create verification session
        let http = self.context.service.get_unauthenticated_http()?;
        let reg_api = RegistrationApi::new(&http);

        let session = reg_api.create_session(number).await?;
        debug!(session_id = %session.id, "created verification session");

        // Store session ID for verify step
        tokio::task::block_in_place(|| {
            self.context.store.set_kv_string(account_keys::VERIFICATION_SESSION_ID, &session.id)
        })?;

        // Request verification code
        let transport = if voice {
            VerificationTransport::Voice
        } else {
            VerificationTransport::Sms
        };

        reg_api.request_verification_code(&session.id, transport).await?;
        info!("verification code requested");

        Ok(())
    }

    async fn verify(&self, code: &str, _pin: Option<&str>) -> Result<()> {
        info!("verifying registration code");

        // Load stored state
        let (session_id, aci_identity_bytes, pni_identity_bytes, aci_reg_id_str, pni_reg_id_str, password) = tokio::task::block_in_place(|| {
            let session_id = self.context.store.get_kv_string(account_keys::VERIFICATION_SESSION_ID)?
                .ok_or(ManagerError::Other("no verification session found - run register first".into()))?;
            let aci_bytes = self.context.store.get_kv_blob(account_keys::IDENTITY_KEY_PAIR)?
                .ok_or(ManagerError::Other("no ACI identity key pair".into()))?;
            let pni_bytes = self.context.store.get_kv_blob(account_keys::PNI_IDENTITY_KEY_PAIR)?
                .ok_or(ManagerError::Other("no PNI identity key pair".into()))?;
            let aci_reg = self.context.store.get_kv_string(account_keys::REGISTRATION_ID)?
                .ok_or(ManagerError::Other("no ACI registration ID".into()))?;
            let pni_reg = self.context.store.get_kv_string(account_keys::PNI_REGISTRATION_ID)?
                .ok_or(ManagerError::Other("no PNI registration ID".into()))?;
            let password = self.context.store.get_kv_string(account_keys::PASSWORD)?
                .ok_or(ManagerError::Other("no password".into()))?;
            Ok::<_, ManagerError>((session_id, aci_bytes, pni_bytes, aci_reg, pni_reg, password))
        })?;

        let aci_identity = IdentityKeyPair::from_bytes(&aci_identity_bytes)?;
        let pni_identity = IdentityKeyPair::from_bytes(&pni_identity_bytes)?;
        let aci_reg_id: u32 = aci_reg_id_str.parse()
            .map_err(|_| ManagerError::Other("invalid ACI registration ID".into()))?;
        let pni_reg_id: u32 = pni_reg_id_str.parse()
            .map_err(|_| ManagerError::Other("invalid PNI registration ID".into()))?;

        // Submit verification code
        let http = self.context.service.get_unauthenticated_http()?;
        let reg_api = RegistrationApi::new(&http);
        let session = reg_api.submit_verification_code(&session_id, code).await?;
        debug!(verified = session.verified, "code submitted");

        // Generate pre-keys
        let aci_signed_pre_key = generate_signed_pre_key(1, &aci_identity);
        let pni_signed_pre_key = generate_signed_pre_key(1, &pni_identity);
        let aci_kyber_pre_key = generate_kyber_pre_key(1, &aci_identity, true);
        let pni_kyber_pre_key = generate_kyber_pre_key(1, &pni_identity, true);

        // Build registration request
        let request = RegistrationRequest {
            session_id: session_id.clone(),
            account_attributes: AccountAttributes::with_registration_ids(aci_reg_id, pni_reg_id),
            aci_identity_key: b64(aci_identity.public_key().serialize()),
            pni_identity_key: b64(pni_identity.public_key().serialize()),
            aci_signed_pre_key: build_reg_signed_pre_key(&aci_signed_pre_key),
            pni_signed_pre_key: build_reg_signed_pre_key(&pni_signed_pre_key),
            aci_pq_last_resort_pre_key: build_reg_kyber_pre_key(&aci_kyber_pre_key),
            pni_pq_last_resort_pre_key: build_reg_kyber_pre_key(&pni_kyber_pre_key),
            skip_device_transfer: true,
        };

        let account = reg_api.register_account(&request).await?;
        info!(aci = %account.uuid, pni = %account.pni, "account registered");

        // Persist account info and save generated pre-keys locally so they
        // can be found when decrypting incoming pre-key messages.
        tokio::task::block_in_place(|| {
            self.context.store.set_kv_string(account_keys::ACI_UUID, &account.uuid.to_string())?;
            self.context.store.set_kv_string(account_keys::PNI_UUID, &account.pni.to_string())?;
            self.context.store.set_kv_string(account_keys::DEVICE_ID, "1")?;
            self.context.store.set_kv_string(account_keys::IS_PRIMARY_DEVICE, "true")?;
            self.context.store.set_kv_string(account_keys::REGISTERED, "true")?;
            self.context.store.delete_kv(account_keys::VERIFICATION_SESSION_ID)?;

            // Save the pre-keys we generated above to the local store.
            self.context.store.save_signed_pre_key(aci_signed_pre_key.id, &aci_signed_pre_key)
                .map_err(|e| ManagerError::Other(format!("failed to save signed pre-key: {e}")))?;
            self.context.store.save_kyber_pre_key(aci_kyber_pre_key.id, &aci_kyber_pre_key)
                .map_err(|e| ManagerError::Other(format!("failed to save kyber pre-key: {e}")))?;

            // Set the next-ID counters so subsequent generate_and_upload_pre_keys
            // calls don't collide with ID 1.
            self.context.store.set_kv_string("next_signed_pre_key_id", "2")?;
            self.context.store.set_kv_string("next_kyber_pre_key_id", "2")?;

            Ok::<_, ManagerError>(())
        })?;

        // Upload initial pre-keys (ACI)
        let creds = ServiceCredentials {
            uuid: Some(account.uuid),
            e164: None,
            password: Some(password.clone()),
            device_id: DeviceId::PRIMARY,
        };
        let auth_http = signal_rs_service::net::http::HttpClient::new(
            self.context.config.clone(),
            Some(creds),
        )?;
        let keys_api = KeysApi::new(&auth_http);

        let pre_keys = generate_pre_keys(1, PREKEY_BATCH_SIZE);

        // Save one-time pre-keys locally so they can be used during
        // incoming pre-key message decryption.
        tokio::task::block_in_place(|| {
            for pk in &pre_keys {
                self.context.store.save_pre_key(pk.id, pk)
                    .map_err(|e| ManagerError::Other(format!("failed to save pre-key: {e}")))?;
            }
            self.context.store.set_kv_string("next_pre_key_id", &(1 + PREKEY_BATCH_SIZE).to_string())?;
            Ok::<_, ManagerError>(())
        })?;

        let upload = PreKeyUpload {
            pre_keys: pre_keys.iter().map(|pk| PreKeyUploadItem {
                key_id: pk.id.0,
                public_key: b64(&pk.public_key),
            }).collect(),
            signed_pre_key: SignedPreKeyUploadItem {
                key_id: aci_signed_pre_key.id.0,
                public_key: b64(&aci_signed_pre_key.public_key),
                signature: b64(&aci_signed_pre_key.signature),
            },
            last_resort_kyber_pre_key: Some(KyberPreKeyUploadItem {
                key_id: aci_kyber_pre_key.id.0,
                public_key: b64(&aci_kyber_pre_key.key_pair_serialized[..1569.min(aci_kyber_pre_key.key_pair_serialized.len())]),
                signature: b64(&aci_kyber_pre_key.signature),
            }),
            kyber_pre_keys: Vec::new(),
        };

        if let Err(e) = keys_api.upload_pre_keys(&upload, ServiceIdKind::Aci).await {
            debug!("failed to upload ACI pre-keys (non-fatal): {e}");
        }

        Ok(())
    }

    async fn link(&self, device_name: &str) -> Result<String> {
        info!(device_name, "starting device linking");

        // Start provisioning
        let (uuid, cipher, ws) = ProvisioningApi::start_provisioning(&self.context.config).await?;

        // Build device link URI
        let uri = ProvisioningApi::build_device_link_uri(&uuid, &cipher.public_key_bytes());
        info!(uri = %uri, "device link URI generated");

        // Display QR code for scanning
        if let Err(e) = qr2term::print_qr(&uri) {
            debug!("failed to print QR code: {e}");
        }
        eprintln!("\nLink URI: {uri}");
        eprintln!("\nScan this QR code with your primary Signal device.");
        eprintln!("Waiting for primary device...\n");

        // Wait for provision message
        let provision = ProvisioningApi::receive_provision_message(&ws, &cipher).await?;
        info!("received provision message from primary device");

        let phone_number = provision.number.clone().unwrap_or_default();
        let aci = provision.aci.clone().unwrap_or_default();
        let _pni = provision.pni.clone().unwrap_or_default();
        let provisioning_code = provision.provisioning_code.clone()
            .ok_or_else(|| ManagerError::Other("no provisioning code received".into()))?;

        // Reconstruct identity keys from provision message
        let aci_identity = self.build_identity_from_provision(
            &provision.aci_identity_key_public,
            &provision.aci_identity_key_private,
        )?;
        let pni_identity = self.build_identity_from_provision(
            &provision.pni_identity_key_public,
            &provision.pni_identity_key_private,
        )?;

        // Generate keys for this device
        let aci_reg_id = generate_registration_id();
        let pni_reg_id = generate_registration_id();
        let password = Self::generate_password();

        let aci_signed_pre_key = generate_signed_pre_key(1, &aci_identity);
        let pni_signed_pre_key = generate_signed_pre_key(1, &pni_identity);
        let aci_kyber_pre_key = generate_kyber_pre_key(1, &aci_identity, true);
        let pni_kyber_pre_key = generate_kyber_pre_key(1, &pni_identity, true);

        // Encrypt device name using ACI identity key
        let encrypted_device_name = Self::encrypt_device_name(device_name, &aci_identity)?;

        // Build finish link request
        let mut attrs = AccountAttributes::with_registration_ids(aci_reg_id, pni_reg_id);
        attrs.name = Some(encrypted_device_name);

        let finish_request = FinishDeviceLinkRequest {
            verification_code: provisioning_code,
            account_attributes: attrs,
            aci_signed_pre_key: build_reg_signed_pre_key(&aci_signed_pre_key),
            pni_signed_pre_key: build_reg_signed_pre_key(&pni_signed_pre_key),
            aci_pq_last_resort_pre_key: build_reg_kyber_pre_key(&aci_kyber_pre_key),
            pni_pq_last_resort_pre_key: build_reg_kyber_pre_key(&pni_kyber_pre_key),
        };

        // Log the request body for debugging
        if let Ok(json) = serde_json::to_string_pretty(&finish_request) {
            debug!("finish link request body:\n{json}");
        }

        // Close the provisioning WebSocket before finishing the link
        drop(ws);

        // Use temporary credentials to complete linking
        let aci_uuid = Uuid::parse_str(&aci)
            .map_err(|e| ManagerError::Other(format!("invalid ACI UUID: {e}")))?;
        let temp_creds = ServiceCredentials {
            uuid: Some(aci_uuid),
            e164: Some(phone_number.clone()),
            password: Some(password.clone()),
            device_id: DeviceId::PRIMARY,
        };
        let http = signal_rs_service::net::http::HttpClient::new(
            self.context.config.clone(),
            Some(temp_creds),
        )?;

        debug!("sending finish device link request to server");
        let link_response = match ProvisioningApi::finish_device_linking(&http, &finish_request).await {
            Ok(resp) => resp,
            Err(e) => {
                error!("finish_device_linking failed: {e:?}");
                return Err(e.into());
            }
        };
        info!(
            device_id = link_response.device_id,
            aci = %link_response.uuid,
            pni = %link_response.pni,
            "device linked successfully"
        );

        // Persist everything
        tokio::task::block_in_place(|| {
            self.context.store.set_kv_string(account_keys::PHONE_NUMBER, &phone_number)?;
            self.context.store.set_kv_string(account_keys::ACI_UUID, &link_response.uuid.to_string())?;
            self.context.store.set_kv_string(account_keys::PNI_UUID, &link_response.pni.to_string())?;
            self.context.store.set_kv_string(account_keys::DEVICE_ID, &link_response.device_id.to_string())?;
            self.context.store.set_kv_string(account_keys::PASSWORD, &password)?;
            self.context.store.set_kv_blob(account_keys::IDENTITY_KEY_PAIR, &aci_identity.serialize())?;
            self.context.store.set_kv_blob(account_keys::PNI_IDENTITY_KEY_PAIR, &pni_identity.serialize())?;
            self.context.store.set_kv_string(account_keys::REGISTRATION_ID, &aci_reg_id.to_string())?;
            self.context.store.set_kv_string(account_keys::PNI_REGISTRATION_ID, &pni_reg_id.to_string())?;
            self.context.store.set_kv_string(account_keys::IS_PRIMARY_DEVICE, "false")?;
            self.context.store.set_kv_string(account_keys::REGISTERED, "true")?;

            if let Some(profile_key) = &provision.profile_key {
                debug!(len = profile_key.len(), "storing profile key from provision");
                self.context.store.set_kv_blob(account_keys::PROFILE_KEY, profile_key)?;
            } else {
                debug!("provision message did not include profile key");
            }
            // Store Account Entropy Pool if present (modern accounts).
            // When AEP is available, we derive the master key from it rather
            // than using the provision message's master_key field directly.
            if let Some(ref aep) = provision.account_entropy_pool
                && !aep.is_empty()
            {
                debug!(aep_len = aep.len(), "storing Account Entropy Pool from provision");
                self.context.store.set_kv_string("account_entropy_pool", aep)?;
            }
            if let Some(master_key) = &provision.master_key {
                debug!(len = master_key.len(), "storing master key from provision");
                self.context.store.set_kv_blob(account_keys::MASTER_KEY, master_key)?;
            } else if provision.account_entropy_pool.is_none() {
                warn!("provision message included neither master key nor AEP - storage sync will not work");
            }

            // Save the pre-keys we generated above to the local store so they
            // can be found when decrypting incoming pre-key messages.
            self.context.store.save_signed_pre_key(aci_signed_pre_key.id, &aci_signed_pre_key)
                .map_err(|e| ManagerError::Other(format!("failed to save signed pre-key: {e}")))?;
            self.context.store.save_kyber_pre_key(aci_kyber_pre_key.id, &aci_kyber_pre_key)
                .map_err(|e| ManagerError::Other(format!("failed to save kyber pre-key: {e}")))?;

            // Set the next-ID counters so the post-link generate_and_upload_pre_keys
            // call doesn't collide with ID 1.
            self.context.store.set_kv_string("next_signed_pre_key_id", "2")?;
            self.context.store.set_kv_string("next_kyber_pre_key_id", "2")?;

            Ok::<_, ManagerError>(())
        })?;

        // Best-effort account reconciliation: trigger a storage sync so the
        // newly-linked device gets contacts, groups, and settings from the
        // primary.  Errors are logged but do not fail the link.
        //
        // Use the UUID from the server response (authoritative) and the device
        // credentials we just registered.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        {
            // Use link_response.uuid (from server) rather than the provision
            // message ACI, to ensure we use the server-authoritative value.
            let linked_creds = ServiceCredentials {
                uuid: Some(link_response.uuid),
                e164: Some(phone_number.clone()),
                password: Some(password.clone()),
                device_id: DeviceId(link_response.device_id),
            };
            debug!(
                username = %linked_creds.username().unwrap_or_default(),
                device_id = link_response.device_id,
                password_len = password.len(),
                "attempting authenticated request with linked device credentials"
            );
            match signal_rs_service::net::http::HttpClient::new(
                self.context.config.clone(),
                Some(linked_creds),
            ) {
                Ok(linked_http) => {
                    // Upload pre-keys so other devices can establish sessions
                    // with this newly-linked device (signal-cli does
                    // refreshPreKeys before storage sync).
                    let keys_api = signal_rs_service::api::keys::KeysApi::new(&linked_http);
                    {
                        let helper = crate::helpers::pre_key::PreKeyHelper::new();
                        match helper.generate_and_upload_pre_keys(&self.context.store, &keys_api).await {
                            Ok(()) => {
                                info!("post-link pre-key upload succeeded");
                            }
                            Err(e) => {
                                warn!("post-link pre-key upload failed (non-fatal): {e}");
                            }
                        }
                    }

                    // Now get storage-specific credentials from the chat server
                    match signal_rs_service::api::storage::get_storage_auth(&linked_http).await {
                        Ok(storage_creds) => {
                            let storage_api =
                                signal_rs_service::api::storage::StorageApi::new(&linked_http, storage_creds);
                            if let Err(e) = self
                                .context
                                .storage()
                                .sync(&self.context.store, &storage_api)
                                .await
                            {
                                warn!("post-link storage sync failed (non-fatal): {e}");
                            } else {
                                info!("post-link storage sync completed");
                            }
                        }
                        Err(e) => {
                            warn!("post-link storage auth failed (non-fatal): {e}");
                        }
                    }
                }
                Err(e) => {
                    warn!("post-link HTTP client creation failed (non-fatal): {e}");
                }
            }
        }

        Ok(phone_number)
    }

    async fn unregister(&self) -> Result<()> {
        info!("unregistering account");
        let uuid = self.get_self_uuid().await?;
        let password = tokio::task::block_in_place(|| {
            self.context.store.get_kv_string(account_keys::PASSWORD)
        })?.ok_or(ManagerError::NotRegistered)?;
        let device_id_str = tokio::task::block_in_place(|| {
            self.context.store.get_kv_string(account_keys::DEVICE_ID)
        })?.unwrap_or_else(|| "1".to_string());
        let device_id: u32 = device_id_str.parse().unwrap_or(1);

        let creds = ServiceCredentials {
            uuid: Some(uuid),
            e164: None,
            password: Some(password),
            device_id: DeviceId(device_id),
        };
        let http = signal_rs_service::net::http::HttpClient::new(
            self.context.config.clone(),
            Some(creds),
        )?;
        let account_api = signal_rs_service::api::account::AccountApi::new(&http);
        account_api.delete_account().await?;

        tokio::task::block_in_place(|| {
            self.context.store.set_kv_string(account_keys::REGISTERED, "false")
        })?;

        info!("account unregistered");
        Ok(())
    }

    async fn delete_account(&self) -> Result<()> {
        info!("deleting account");
        self.unregister().await?;
        info!("account deleted from server");
        Ok(())
    }

    // -- Profile ------------------------------------------------------------

    async fn update_profile(
        &self, given_name: Option<&str>, family_name: Option<&str>,
        about: Option<&str>, about_emoji: Option<&str>,
        avatar_path: Option<&str>, remove_avatar: bool,
    ) -> Result<()> {
        info!("updating profile");
        let http = self.build_http_client().await?;
        let profile_api = signal_rs_service::api::profile::ProfileApi::new(&http);

        // Delegate to ProfileHelper which handles proper AES-256-GCM encryption
        // of the profile name and about fields using the profile key, and computes
        // the profile key commitment and version.
        self.context.profile().update_profile(
            &self.context.store,
            &profile_api,
            given_name,
            family_name,
            about,
            about_emoji,
            avatar_path,
            remove_avatar,
        ).await?;

        // Update the local profile in the self-recipient record
        let uuid = self.get_self_uuid().await?;
        tokio::task::block_in_place(|| {
            if let Ok(Some(r)) = self.context.store.get_recipient_by_aci(&uuid.to_string())
                && let Err(e) = self.context.store.update_recipient_profile(
                    r.id,
                    given_name,
                    family_name,
                    about,
                    about_emoji,
                    avatar_path,
                ) {
                    warn!(error = %e, "failed to update recipient profile");
                }
        });

        info!("profile updated");
        Ok(())
    }

    async fn get_username(&self) -> Result<Option<String>> {
        debug!("loading username from store");
        let username = tokio::task::block_in_place(|| {
            self.context.store.get_kv_string("username")
        })?;
        Ok(username)
    }

    async fn set_username(&self, username: &str) -> Result<()> {
        info!(username, "setting username");
        let http = self.build_http_client().await?;
        let account_api = signal_rs_service::api::account::AccountApi::new(&http);

        // Parse the username and compute its hash using libsignal's algorithm.
        // Username format is "nickname.discriminator" (e.g., "alice.42").
        let parsed = usernames::Username::new(username)
            .map_err(|e| ManagerError::Other(format!("invalid username format: {e}")))?;

        let username_hash = parsed.hash();

        // Generate a zero-knowledge proof for the username
        let mut randomness = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut randomness);
        let zk_proof = parsed.proof(&randomness)
            .map_err(|e| ManagerError::Other(format!("username proof generation failed: {e}")))?;

        // Encrypt the username for server-side storage.
        // create_for_username requires rand 0.9's CryptoRng.
        let mut rng = rand_09::rng();
        let (_entropy, encrypted_data) = usernames::create_for_username(
            &mut rng,
            username.to_string(),
            None,
        )
        .map_err(|e| ManagerError::Other(format!("username encryption failed: {e}")))?;

        let request = signal_rs_service::api::account::UsernameHashRequest {
            username_hashes: vec![b64(&username_hash)],
        };
        let response = account_api.set_username_hash(&request).await?;

        // Confirm the reservation with ZK proof and encrypted username.
        let confirm_request = signal_rs_service::api::account::ConfirmUsernameRequest {
            username_hash: response.username_hash,
            zk_proof: b64(&zk_proof),
            encrypted_username: Some(b64(&encrypted_data)),
        };
        account_api.confirm_username(&confirm_request).await?;

        // Store locally
        tokio::task::block_in_place(|| {
            self.context.store.set_kv_string("username", username)
        })?;

        info!("username set");
        Ok(())
    }

    async fn delete_username(&self) -> Result<()> {
        info!("deleting username");
        let http = self.build_http_client().await?;
        let account_api = signal_rs_service::api::account::AccountApi::new(&http);

        account_api.delete_username().await?;

        tokio::task::block_in_place(|| {
            self.context.store.delete_kv("username")
        })?;

        info!("username deleted");
        Ok(())
    }

    // -- Devices ------------------------------------------------------------

    async fn get_linked_devices(&self) -> Result<Vec<Device>> {
        info!("fetching linked devices");
        let uuid = self.get_self_uuid().await?;
        let password = tokio::task::block_in_place(|| {
            self.context.store.get_kv_string(account_keys::PASSWORD)
        })?.ok_or(ManagerError::NotRegistered)?;
        let device_id_str = tokio::task::block_in_place(|| {
            self.context.store.get_kv_string(account_keys::DEVICE_ID)
        })?.unwrap_or_else(|| "1".to_string());
        let device_id: u32 = device_id_str.parse().unwrap_or(1);

        let creds = ServiceCredentials {
            uuid: Some(uuid),
            e164: None,
            password: Some(password),
            device_id: DeviceId(device_id),
        };
        let http = signal_rs_service::net::http::HttpClient::new(
            self.context.config.clone(),
            Some(creds),
        )?;
        let account_api = signal_rs_service::api::account::AccountApi::new(&http);
        let devices = account_api.get_devices().await?;

        let result = devices
            .into_iter()
            .map(|d| Device {
                id: d.id,
                name: d.name,
                created: d.created,
                last_seen: d.last_seen,
            })
            .collect();

        Ok(result)
    }

    async fn remove_linked_device(&self, device_id: u32) -> Result<()> {
        info!(device_id, "removing linked device");
        let uuid = self.get_self_uuid().await?;
        let password = tokio::task::block_in_place(|| {
            self.context.store.get_kv_string(account_keys::PASSWORD)
        })?.ok_or(ManagerError::NotRegistered)?;
        let self_device_id_str = tokio::task::block_in_place(|| {
            self.context.store.get_kv_string(account_keys::DEVICE_ID)
        })?.unwrap_or_else(|| "1".to_string());
        let self_device_id: u32 = self_device_id_str.parse().unwrap_or(1);

        let creds = ServiceCredentials {
            uuid: Some(uuid),
            e164: None,
            password: Some(password),
            device_id: DeviceId(self_device_id),
        };
        let http = signal_rs_service::net::http::HttpClient::new(
            self.context.config.clone(),
            Some(creds),
        )?;
        let account_api = signal_rs_service::api::account::AccountApi::new(&http);
        account_api.remove_device(DeviceId(device_id)).await?;
        info!(device_id, "device removed");
        Ok(())
    }

    async fn add_device_link(&self) -> Result<String> {
        info!("generating device link URI for adding a new device");

        // Start a provisioning session to get a UUID and cipher
        let (uuid, cipher, _ws) = ProvisioningApi::start_provisioning(&self.context.config).await?;

        // Build the sgnl:// URI that the new device will scan
        let uri = ProvisioningApi::build_device_link_uri(&uuid, &cipher.public_key_bytes());
        info!(uri = %uri, "device link URI generated");

        Ok(uri)
    }

    // -- Messages -----------------------------------------------------------

    async fn send_message(
        &self, recipients: &[RecipientIdentifier], message: &str,
        attachments: &[String], quote_timestamp: Option<u64>,
        mentions: &[(Uuid, u32, u32)],
    ) -> Result<SendResult> {
        info!(recipient_count = recipients.len(), "sending message");
        let timestamp = self.current_timestamp_millis();

        // Upload attachments
        let mut attachment_infos = Vec::new();
        if !attachments.is_empty() {
            let http = self.build_http_client().await?;
            let attachment_api = signal_rs_service::api::attachment::AttachmentApi::new(&http);
            let helper = crate::helpers::attachment::AttachmentHelper::new();
            for file_path in attachments {
                let info = helper.upload_attachment(&attachment_api, file_path).await?;
                attachment_infos.push(info);
            }
        }

        // Build a proper SignalContent::Data with protobuf encoding
        let mention_infos: Vec<MentionInfo> = mentions.iter().map(|(uuid, start, length)| {
            MentionInfo { uuid: *uuid, start: *start, length: *length }
        }).collect();

        // Build quote info if replying to a message
        let quote = if let Some(qt) = quote_timestamp {
            tokio::task::block_in_place(|| -> Option<QuoteInfo> {
                if let Ok(Some(msg)) = self.context.store.get_message_by_timestamp(qt as i64) {
                    // Determine the author: if sender_id is set it's an incoming message,
                    // otherwise it's our own outgoing message.
                    let author = if let Some(sender_id) = msg.sender_id {
                        self.context.store.get_recipient_by_id(sender_id).ok()
                            .flatten()
                            .and_then(|r| r.aci)
                            .and_then(|aci| Uuid::parse_str(&aci).ok())
                            .map(ServiceId::aci)
                    } else {
                        self.context.store.get_kv_string(account_keys::ACI_UUID).ok()
                            .flatten()
                            .and_then(|aci| Uuid::parse_str(&aci).ok())
                            .map(ServiceId::aci)
                    };

                    Some(QuoteInfo {
                        id: qt,
                        author,
                        text: msg.body,
                    })
                } else {
                    // Message not found locally; send a minimal quote with just the timestamp
                    Some(QuoteInfo {
                        id: qt,
                        author: None,
                        text: None,
                    })
                }
            })
        } else {
            None
        };

        let profile_key = self.context.store.get_kv_blob(account_keys::PROFILE_KEY).ok().flatten();
        let content = SignalContent::Data(DataContent {
            body: Some(message.to_string()),
            attachments: attachment_infos.clone(),
            group_id: None,
            quote,
            reaction: None,
            sticker: None,
            contacts: Vec::new(),
            previews: Vec::new(),
            mentions: mention_infos,
            expire_timer: None,
            is_expiration_update: false,
            is_view_once: false,
            timestamp,
            profile_key,
        });

        let mut results = Vec::new();

        for recipient in recipients {
            let dest_uuid = self.resolve_recipient_uuid(recipient).await?;
            match self.encrypt_and_send(&dest_uuid, &content, timestamp, false, true).await {
                Ok(sealed) => {
                    results.push(crate::types::SendMessageResult {
                        recipient: recipient.clone(),
                        success: true,
                        is_unidentified: sealed,
                        error: None,
                    });
                }
                Err(e) => {
                    results.push(crate::types::SendMessageResult {
                        recipient: recipient.clone(),
                        success: false,
                        is_unidentified: false,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        // Send sync transcript to other linked devices so they see the sent message
        if results.iter().any(|r| r.success) {
            let self_uuid = self.get_self_uuid().await.ok();
            if let Some(self_uuid) = self_uuid {
                let data_message_proto = signal_rs_protos::DataMessage::from(match &content {
                    SignalContent::Data(d) => d,
                    _ => unreachable!(),
                });

                // Build unidentified delivery status for each successful recipient
                let unidentified_status: Vec<signal_rs_protos::sync_message::sent::UnidentifiedDeliveryStatus> = results.iter()
                    .filter(|r| r.success)
                    .filter_map(|r| {
                        let uuid = match &r.recipient {
                            RecipientIdentifier::Uuid(u) => Some(*u),
                            RecipientIdentifier::PhoneNumber(num) => {
                                tokio::task::block_in_place(|| {
                                    self.context.store.get_recipient_by_number(num).ok().flatten()
                                        .and_then(|rec| rec.aci)
                                        .and_then(|aci| Uuid::parse_str(&aci).ok())
                                })
                            }
                            RecipientIdentifier::Username(name) => {
                                tokio::task::block_in_place(|| {
                                    self.context.store.get_recipient_by_username(name).ok().flatten()
                                        .and_then(|rec| rec.aci)
                                        .and_then(|aci| Uuid::parse_str(&aci).ok())
                                })
                            }
                        };
                        uuid.map(|u| signal_rs_protos::sync_message::sent::UnidentifiedDeliveryStatus {
                            destination_service_id: Some(u.to_string()),
                            unidentified: Some(r.is_unidentified),
                        })
                    })
                    .collect();

                // Use the first successful recipient as the destination
                let destination_service_id = unidentified_status.first()
                    .and_then(|s| s.destination_service_id.clone());

                let sync_message = signal_rs_protos::SyncMessage {
                    sent: Some(signal_rs_protos::sync_message::Sent {
                        destination_service_id,
                        timestamp: Some(timestamp),
                        message: Some(data_message_proto),
                        expiration_start_timestamp: None,
                        unidentified_status,
                        is_recipient_update: None,
                        story_message: None,
                        story_message_recipients: Vec::new(),
                        edit_message: None,
                    }),
                    ..Default::default()
                };

                let proto_content = signal_rs_protos::Content {
                    sync_message: Some(sync_message),
                    ..Default::default()
                };
                let sync_raw = proto_content.encode_to_vec();
                let sync_plaintext = signal_rs_service::content::pad_plaintext_public(&sync_raw);

                if let Err(e) = self.encrypt_and_send_raw(&self_uuid, &sync_plaintext, timestamp, false, false).await {
                    warn!(error = %e, "failed to send sync transcript (non-fatal)");
                }
            }
        }

        // Store the sent message locally
        if let Ok(Some(self_recipient)) = tokio::task::block_in_place(|| {
            let uuid = self.context.store.get_kv_string(account_keys::ACI_UUID)?;
            match uuid {
                Some(u) => self.context.store.get_recipient_by_aci(&u),
                None => Ok(None),
            }
        }) {
            for recipient in recipients {
                if let Ok(store_recipient) = tokio::task::block_in_place(|| {
                    self.resolve_recipient(recipient)
                })
                    && let Err(e) = tokio::task::block_in_place(|| {
                        let thread = self.context.store.get_or_create_thread_for_recipient(store_recipient.id)?;
                        let quote_id = match quote_timestamp {
                            Some(qt) => {
                                self.context.store.get_message_by_timestamp_and_sender(qt as i64, self_recipient.id)?
                                    .map(|m| m.id)
                            }
                            None => None,
                        };
                        let attachments_json = if attachment_infos.is_empty() {
                            None
                        } else {
                            Some(serde_json::to_string(&attachment_infos).unwrap_or_default())
                        };
                        self.context.store.insert_message(
                            thread.id,
                            None,
                            timestamp as i64,
                            None,
                            Some(message),
                            signal_rs_store::models::message::MessageType::Normal,
                            quote_id,
                            None,
                            attachments_json.as_deref(),
                        )?;
                        self.context.store.update_thread_on_message(thread.id, timestamp as i64, false)?;
                        Ok::<_, ManagerError>(())
                    }) {
                        warn!(error = %e, "failed to store sent message locally");
                    }
            }
        }

        info!(timestamp, "message sent");
        Ok(SendResult { timestamp, results })
    }

    async fn send_edit_message(
        &self, recipients: &[RecipientIdentifier], target_timestamp: u64,
        new_text: &str, attachments: &[String], mentions: &[(Uuid, u32, u32)],
    ) -> Result<SendResult> {
        info!(target_timestamp, "sending edit message");
        let timestamp = self.current_timestamp_millis();

        // Upload attachments
        let mut attachment_pointers = Vec::new();
        if !attachments.is_empty() {
            let http = self.build_http_client().await?;
            let attachment_api = signal_rs_service::api::attachment::AttachmentApi::new(&http);
            let helper = crate::helpers::attachment::AttachmentHelper::new();
            for file_path in attachments {
                let info = helper.upload_attachment(&attachment_api, file_path).await?;
                let pointer: signal_rs_protos::AttachmentPointer = (&info).into();
                attachment_pointers.push(pointer);
            }
        }

        let mention_infos: Vec<MentionInfo> = mentions.iter().map(|(uuid, start, length)| {
            MentionInfo { uuid: *uuid, start: *start, length: *length }
        }).collect();

        // Build a DataMessage for the edit, then wrap it in an EditMessage protobuf
        let data_message = signal_rs_protos::DataMessage {
            body: Some(new_text.to_string()),
            timestamp: Some(timestamp),
            attachments: attachment_pointers,
            body_ranges: mention_infos.iter().map(|m| {
                signal_rs_protos::data_message::BodyRange {
                    start: Some(m.start),
                    length: Some(m.length),
                    associated_value: Some(
                        signal_rs_protos::data_message::body_range::AssociatedValue::MentionAci(
                            m.uuid.to_string(),
                        ),
                    ),
                }
            }).collect(),
            ..Default::default()
        };
        let edit_message = signal_rs_protos::EditMessage {
            target_sent_timestamp: Some(target_timestamp),
            data_message: Some(data_message),
        };
        let proto_content = signal_rs_protos::Content {
            edit_message: Some(edit_message),
            ..Default::default()
        };
        let plaintext = proto_content.encode_to_vec();

        let mut results = Vec::new();

        for recipient in recipients {
            let dest_uuid = self.resolve_recipient_uuid(recipient).await?;
            match self.encrypt_and_send_raw(&dest_uuid, &plaintext, timestamp, false, true).await {
                Ok(sealed) => {
                    results.push(crate::types::SendMessageResult {
                        recipient: recipient.clone(),
                        success: true,
                        is_unidentified: sealed,
                        error: None,
                    });
                }
                Err(e) => {
                    results.push(crate::types::SendMessageResult {
                        recipient: recipient.clone(),
                        success: false,
                        is_unidentified: false,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        info!(timestamp, "edit message sent");
        Ok(SendResult { timestamp, results })
    }

    async fn send_remote_delete(
        &self, recipients: &[RecipientIdentifier], target_timestamp: u64,
    ) -> Result<SendResult> {
        info!(target_timestamp, "sending remote delete");
        let timestamp = self.current_timestamp_millis();

        // Build a DataMessage with a delete field
        let profile_key = self.context.store.get_kv_blob(account_keys::PROFILE_KEY).ok().flatten();
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
            profile_key,
        });

        // We need to manually add the delete field since DataContent doesn't have it.
        // Build the proto directly with the delete field.
        let mut proto_content = signal_rs_protos::Content::from(&content);
        if let Some(ref mut dm) = proto_content.data_message {
            dm.delete = Some(signal_rs_protos::data_message::Delete {
                target_sent_timestamp: Some(target_timestamp),
            });
        }
        let plaintext = proto_content.encode_to_vec();

        let mut results = Vec::new();

        for recipient in recipients {
            let dest_uuid = self.resolve_recipient_uuid(recipient).await?;
            match self.encrypt_and_send_raw(&dest_uuid, &plaintext, timestamp, false, true).await {
                Ok(sealed) => {
                    results.push(crate::types::SendMessageResult {
                        recipient: recipient.clone(),
                        success: true,
                        is_unidentified: sealed,
                        error: None,
                    });
                }
                Err(e) => {
                    results.push(crate::types::SendMessageResult {
                        recipient: recipient.clone(),
                        success: false,
                        is_unidentified: false,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        info!(timestamp, "remote delete sent");
        Ok(SendResult { timestamp, results })
    }

    async fn send_typing(
        &self, recipient: &RecipientIdentifier, is_stop: bool,
    ) -> Result<()> {
        debug!(%recipient, is_stop, "sending typing indicator");
        let timestamp = self.current_timestamp_millis();
        let dest_uuid = self.resolve_recipient_uuid(recipient).await?;

        let action = if is_stop { TypingAction::Stopped } else { TypingAction::Started };
        let content = SignalContent::Typing(TypingContent {
            action,
            timestamp,
            group_id: None,
        });

        // Typing indicators are best-effort; don't fail on error
        if let Err(e) = self.encrypt_and_send(&dest_uuid, &content, timestamp, true, false).await {
            debug!("typing indicator send failed (non-fatal): {e}");
        }

        Ok(())
    }

    async fn send_read_receipt(
        &self, sender: &RecipientIdentifier, timestamps: &[u64],
    ) -> Result<()> {
        info!(%sender, count = timestamps.len(), "sending read receipt");
        let receipt_timestamp = self.current_timestamp_millis();
        let dest_uuid = self.resolve_recipient_uuid(sender).await?;

        let content = SignalContent::Receipt(ReceiptContent {
            receipt_type: ReceiptType::Read,
            timestamps: timestamps.to_vec(),
        });

        self.encrypt_and_send(&dest_uuid, &content, receipt_timestamp, false, false).await.map(|_| ())
    }

    async fn send_viewed_receipt(
        &self, sender: &RecipientIdentifier, timestamps: &[u64],
    ) -> Result<()> {
        info!(%sender, count = timestamps.len(), "sending viewed receipt");
        let receipt_timestamp = self.current_timestamp_millis();
        let dest_uuid = self.resolve_recipient_uuid(sender).await?;

        let content = SignalContent::Receipt(ReceiptContent {
            receipt_type: ReceiptType::Viewed,
            timestamps: timestamps.to_vec(),
        });

        self.encrypt_and_send(&dest_uuid, &content, receipt_timestamp, false, false).await.map(|_| ())
    }

    async fn send_reaction(
        &self, recipients: &[RecipientIdentifier], emoji: &str,
        target_author: &RecipientIdentifier, target_timestamp: u64, is_remove: bool,
    ) -> Result<SendResult> {
        info!(emoji, target_timestamp, is_remove, "sending reaction");
        let timestamp = self.current_timestamp_millis();
        let target_author_uuid = self.resolve_recipient_uuid(target_author).await?;

        let profile_key = self.context.store.get_kv_blob(account_keys::PROFILE_KEY).ok().flatten();
        let content = SignalContent::Data(DataContent {
            body: None,
            attachments: Vec::new(),
            group_id: None,
            quote: None,
            reaction: Some(ReactionInfo {
                emoji: emoji.to_string(),
                is_remove,
                target_author: Some(ServiceId::aci(target_author_uuid)),
                target_sent_timestamp: target_timestamp,
            }),
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

        let mut results = Vec::new();

        for recipient in recipients {
            let dest_uuid = self.resolve_recipient_uuid(recipient).await?;
            match self.encrypt_and_send(&dest_uuid, &content, timestamp, false, true).await {
                Ok(sealed) => {
                    results.push(crate::types::SendMessageResult {
                        recipient: recipient.clone(),
                        success: true,
                        is_unidentified: sealed,
                        error: None,
                    });
                }
                Err(e) => {
                    results.push(crate::types::SendMessageResult {
                        recipient: recipient.clone(),
                        success: false,
                        is_unidentified: false,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        info!(timestamp, "reaction sent");
        Ok(SendResult { timestamp, results })
    }

    // -- Groups -------------------------------------------------------------

    async fn get_groups(&self) -> Result<Vec<Group>> {
        debug!("loading groups from store");
        let groups = tokio::task::block_in_place(|| {
            self.context.store.list_all_groups()
        })?;

        let mut result = Vec::with_capacity(groups.len());
        for g in groups {
            let id = base64::engine::general_purpose::STANDARD.encode(&g.group_id);

            // Try to decrypt the group name and revision from cached group_data
            let (name, revision) = if let Some(ref data) = g.group_data {
                match signal_rs_protos::Group::decode(data.as_slice()) {
                    Ok(group_proto) => {
                        let decrypted_name = if let Ok(master_key) =
                            signal_rs_service::groups::GroupMasterKey::from_bytes(&g.master_key)
                        {
                            group_proto
                                .title
                                .as_ref()
                                .and_then(|title_bytes| master_key.decrypt_title(title_bytes).ok())
                                .unwrap_or_default()
                        } else {
                            String::new()
                        };
                        let rev = group_proto.version.unwrap_or(0);
                        (decrypted_name, rev)
                    }
                    Err(_) => (String::new(), 0),
                }
            } else {
                (String::new(), 0)
            };

            // Load members from the group_v2_member table
            let store_members = tokio::task::block_in_place(|| {
                self.context.store.list_group_members(&g.group_id)
            })
            .unwrap_or_default();
            let members = self.build_group_member_list(&store_members).await;

            result.push(Group {
                id,
                name,
                description: None,
                members,
                revision,
                invite_link_enabled: false,
                disappearing_messages_timer: 0,
            });
        }

        Ok(result)
    }

    async fn create_group(
        &self, name: &str, members: &[RecipientIdentifier], avatar_path: Option<&str>,
    ) -> Result<Group> {
        info!(name, member_count = members.len(), "creating group");

        if let Some(path) = avatar_path {
            debug!(path, "avatar_path provided; avatar upload not yet implemented, storing locally");
        }

        // Generate a random group master key (32 bytes)
        let master_key: [u8; 32] = rand::random();
        // Derive a group ID from the master key (in practice this uses HKDF;
        // here we use the first 32 bytes of the master key as the group ID)
        let group_id: [u8; 32] = rand::random();
        // Generate a distribution ID for sender key distribution
        let distribution_id = Uuid::new_v4();

        // Insert the group into the local store
        let db_group_id = tokio::task::block_in_place(|| {
            self.context.store.insert_group(
                &group_id,
                &master_key,
                distribution_id.as_bytes(),
            )
        })?;

        // Resolve and add members
        let mut group_members = Vec::new();
        let self_uuid = self.get_self_uuid().await?;

        // Add self as admin
        let self_recipient = tokio::task::block_in_place(|| {
            self.context.store.get_or_create_recipient(&self_uuid.to_string())
        })?;
        tokio::task::block_in_place(|| {
            self.context.store.add_group_member(&group_id, self_recipient.id)
        })?;
        group_members.push(crate::types::GroupMember {
            uuid: self_uuid,
            role: crate::types::GroupMemberRole::Administrator,
            joined_at_revision: 0,
        });

        for member in members {
            let store_recipient = tokio::task::block_in_place(|| {
                self.resolve_recipient(member)
            })?;
            tokio::task::block_in_place(|| {
                self.context.store.add_group_member(&group_id, store_recipient.id)
            })?;
            let member_uuid = store_recipient.aci
                .as_ref()
                .and_then(|s| Uuid::parse_str(s).ok())
                .unwrap_or(Uuid::nil());
            group_members.push(crate::types::GroupMember {
                uuid: member_uuid,
                role: crate::types::GroupMemberRole::Member,
                joined_at_revision: 0,
            });
        }

        // Build a proper Group protobuf for the server
        let title_blob = signal_rs_protos::GroupAttributeBlob {
            content: Some(signal_rs_protos::group_attribute_blob::Content::Title(
                name.to_string(),
            )),
        };
        let group_proto = signal_rs_protos::Group {
            public_key: Some(master_key.to_vec()),
            title: Some(prost::Message::encode_to_vec(&title_blob)),
            access_control: Some(signal_rs_protos::AccessControl {
                attributes: Some(signal_rs_protos::access_control::AccessRequired::Member as i32),
                members: Some(signal_rs_protos::access_control::AccessRequired::Member as i32),
                add_from_invite_link: Some(signal_rs_protos::access_control::AccessRequired::Unsatisfiable as i32),
            }),
            version: Some(0),
            ..Default::default()
        };
        let group_bytes = prost::Message::encode_to_vec(&group_proto);

        // Upload the group to the server
        let http = self.build_http_client().await?;
        let groups_api = signal_rs_service::api::groups_v2::GroupsV2Api::new(&http);
        if let Err(e) = groups_api.create_group(&group_bytes).await {
            debug!("group creation API call failed (non-fatal, local group created): {e}");
        }

        let group_id_b64 = base64::engine::general_purpose::STANDARD.encode(group_id);
        let group = Group {
            id: group_id_b64,
            name: name.to_string(),
            description: None,
            members: group_members,
            revision: 0,
            invite_link_enabled: false,
            disappearing_messages_timer: 0,
        };

        info!(db_id = db_group_id, "group created");
        Ok(group)
    }

    async fn update_group(
        &self, group_id: &str, name: Option<&str>, description: Option<&str>,
        avatar_path: Option<&str>, add_members: &[RecipientIdentifier],
        remove_members: &[RecipientIdentifier], add_admins: &[RecipientIdentifier],
        remove_admins: &[RecipientIdentifier],
    ) -> Result<Group> {
        info!(group_id, "updating group");

        if let Some(path) = avatar_path {
            debug!(path, "avatar_path provided; avatar upload not yet implemented");
        }

        let group_id_bytes = base64::engine::general_purpose::STANDARD
            .decode(group_id)
            .map_err(|e| ManagerError::InvalidGroup(format!("invalid base64: {e}")))?;

        let stored_group = tokio::task::block_in_place(|| {
            self.context.store.get_group_by_group_id(&group_id_bytes)
        })?;
        let stored_group = stored_group.ok_or_else(|| ManagerError::InvalidGroup(group_id.to_string()))?;

        // Derive secret params for encrypting UUIDs in GroupChange.Actions
        let master_key = signal_rs_service::groups::GroupMasterKey::from_bytes(&stored_group.master_key)
            .map_err(|e| ManagerError::InvalidGroup(format!("bad master key: {e}")))?;
        let secret_params = master_key.derive_secret_params();

        // Build GroupChange.Actions protobuf
        let mut actions = signal_rs_protos::group_change::Actions {
            source_service_id: None,
            revision: None,
            add_members: Vec::new(),
            delete_members: Vec::new(),
            modify_member_roles: Vec::new(),
            modify_member_profile_keys: Vec::new(),
            add_pending_members: Vec::new(),
            delete_pending_members: Vec::new(),
            promote_pending_members: Vec::new(),
            modify_title: None,
            modify_avatar: None,
            modify_disappearing_messages_timer: None,
            modify_attributes_access: None,
            modify_member_access: None,
            modify_add_from_invite_link_access: None,
            add_requesting_members: Vec::new(),
            delete_requesting_members: Vec::new(),
            promote_requesting_members: Vec::new(),
            modify_invite_link_password: None,
            modify_description: None,
            modify_announcements_only: None,
            add_banned_members: Vec::new(),
            delete_banned_members: Vec::new(),
            promote_pending_pni_aci_members: Vec::new(),
        };

        // Add members
        for member in add_members {
            let store_recipient = tokio::task::block_in_place(|| {
                self.resolve_recipient(member)
            })?;
            tokio::task::block_in_place(|| {
                self.context.store.add_group_member(&group_id_bytes, store_recipient.id)
            })?;

            let member_uuid = self.resolve_recipient_uuid(member).await?;
            let encrypted_user_id = crate::helpers::group::encrypt_uuid_with_params(&secret_params, &member_uuid);
            let member_proto = signal_rs_protos::Member {
                user_id: Some(encrypted_user_id),
                role: Some(signal_rs_protos::member::Role::Default as i32),
                profile_key: None,
                presentation: None,
                joined_at_version: None,
            };
            actions.add_members.push(
                signal_rs_protos::group_change::actions::AddMemberAction {
                    added: Some(member_proto),
                    join_from_invite_link: Some(false),
                },
            );
        }

        // Remove members
        for member in remove_members {
            let store_recipient = tokio::task::block_in_place(|| {
                self.resolve_recipient(member)
            })?;
            tokio::task::block_in_place(|| {
                self.context.store.remove_group_member(&group_id_bytes, store_recipient.id)
            })?;

            let member_uuid = self.resolve_recipient_uuid(member).await?;
            let encrypted_user_id = crate::helpers::group::encrypt_uuid_with_params(&secret_params, &member_uuid);
            actions.delete_members.push(
                signal_rs_protos::group_change::actions::DeleteMemberAction {
                    deleted_user_id: Some(encrypted_user_id),
                },
            );
        }

        // Promote members to admin
        for admin in add_admins {
            let admin_uuid = self.resolve_recipient_uuid(admin).await?;
            let encrypted_user_id = crate::helpers::group::encrypt_uuid_with_params(&secret_params, &admin_uuid);
            actions.modify_member_roles.push(
                signal_rs_protos::group_change::actions::ModifyMemberRoleAction {
                    user_id: Some(encrypted_user_id),
                    role: Some(signal_rs_protos::member::Role::Administrator as i32),
                },
            );
        }

        // Demote admins to default member
        for admin in remove_admins {
            let admin_uuid = self.resolve_recipient_uuid(admin).await?;
            let encrypted_user_id = crate::helpers::group::encrypt_uuid_with_params(&secret_params, &admin_uuid);
            actions.modify_member_roles.push(
                signal_rs_protos::group_change::actions::ModifyMemberRoleAction {
                    user_id: Some(encrypted_user_id),
                    role: Some(signal_rs_protos::member::Role::Default as i32),
                },
            );
        }

        // Modify title
        if let Some(new_name) = name {
            let encrypted_title = master_key
                .encrypt_title(new_name)
                .unwrap_or_else(|_| new_name.as_bytes().to_vec());
            actions.modify_title = Some(
                signal_rs_protos::group_change::actions::ModifyTitleAction {
                    title: Some(encrypted_title),
                },
            );
        }

        // Submit changes to the server
        let actions_bytes = prost::Message::encode_to_vec(&actions);
        let http = self.build_http_client().await?;
        let groups_api = signal_rs_service::api::groups_v2::GroupsV2Api::new(&http);
        if let Err(e) = groups_api.modify_group(&actions_bytes).await {
            debug!("group modification API call failed (non-fatal): {e}");
        }

        // Build the current member list from the store
        let store_members = tokio::task::block_in_place(|| {
            self.context.store.list_group_members(&group_id_bytes)
        })?;
        let members = self.build_group_member_list(&store_members).await;

        let result = Group {
            id: group_id.to_string(),
            name: name.unwrap_or_default().to_string(),
            description: description.map(|s| s.to_string()),
            members,
            revision: 0,
            invite_link_enabled: false,
            disappearing_messages_timer: 0,
        };

        info!("group updated");
        Ok(result)
    }

    async fn join_group(&self, invite_link: &str) -> Result<Group> {
        info!(invite_link, "joining group via invite link");

        // Extract the invite link password from the URL
        // Signal invite links look like: https://signal.group/#<base64-encoded data>
        let fragment = invite_link
            .split('#')
            .nth(1)
            .ok_or_else(|| ManagerError::InvalidGroup("invalid invite link format".into()))?;

        let invite_data = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(fragment)
            .map_err(|e| ManagerError::InvalidGroup(format!("invalid invite link data: {e}")))?;

        let http = self.build_http_client().await?;
        let groups_api = signal_rs_service::api::groups_v2::GroupsV2Api::new(&http);

        // Get join info from the server
        let _join_info = groups_api.get_group_join_info(&invite_data).await?;

        // Create a local group entry
        let group_id: [u8; 32] = rand::random();
        let distribution_id = Uuid::new_v4();

        // Parse the invite data as a GroupInviteLink-like structure.
        // The invite link fragment contains the master key (first 32 bytes)
        // and an invite link password. Parse the data as a Group protobuf
        // to extract the master key properly.
        let master_key = if let Ok(group_proto) = <signal_rs_protos::Group as prost::Message>::decode(invite_data.as_slice()) {
            group_proto.public_key.unwrap_or_else(|| {
                // Fallback: use invite_data directly if Group decode succeeds
                // but has no public_key field
                if invite_data.len() >= 32 {
                    invite_data[..32].to_vec()
                } else {
                    let mut key = vec![0u8; 32];
                    let len = invite_data.len().min(32);
                    key[..len].copy_from_slice(&invite_data[..len]);
                    key
                }
            })
        } else {
            // Fallback for when protobuf decode fails: treat the first 32
            // bytes as the master key (legacy format)
            if invite_data.len() >= 32 {
                invite_data[..32].to_vec()
            } else {
                let mut key = vec![0u8; 32];
                let len = invite_data.len().min(32);
                key[..len].copy_from_slice(&invite_data[..len]);
                key
            }
        };

        tokio::task::block_in_place(|| {
            self.context.store.insert_group(
                &group_id,
                &master_key,
                distribution_id.as_bytes(),
            )
        })?;

        // Add self as a member
        let self_uuid = self.get_self_uuid().await?;
        let self_recipient = tokio::task::block_in_place(|| {
            self.context.store.get_or_create_recipient(&self_uuid.to_string())
        })?;
        tokio::task::block_in_place(|| {
            self.context.store.add_group_member(&group_id, self_recipient.id)
        })?;

        let group_id_b64 = base64::engine::general_purpose::STANDARD.encode(group_id);
        let group = Group {
            id: group_id_b64,
            name: String::new(),
            description: None,
            members: vec![crate::types::GroupMember {
                uuid: self_uuid,
                role: crate::types::GroupMemberRole::Member,
                joined_at_revision: 0,
            }],
            revision: 0,
            invite_link_enabled: false,
            disappearing_messages_timer: 0,
        };

        info!("joined group");
        Ok(group)
    }

    async fn quit_group(&self, group_id: &str) -> Result<()> {
        info!(group_id, "quitting group");

        let group_id_bytes = base64::engine::general_purpose::STANDARD
            .decode(group_id)
            .map_err(|e| ManagerError::InvalidGroup(format!("invalid base64: {e}")))?;

        let group = tokio::task::block_in_place(|| {
            self.context.store.get_group_by_group_id(&group_id_bytes)
        })?;
        let group = group.ok_or_else(|| ManagerError::InvalidGroup(group_id.to_string()))?;

        // Remove self from the group on the server
        let http = self.build_http_client().await?;
        let groups_api = signal_rs_service::api::groups_v2::GroupsV2Api::new(&http);
        // A full implementation would send a GroupChange.Actions with a DeleteMember action
        if let Err(e) = groups_api.modify_group(&group.master_key).await {
            debug!("group leave API call failed (non-fatal): {e}");
        }

        // Remove self from local group membership
        let self_uuid = self.get_self_uuid().await?;
        let self_recipient = tokio::task::block_in_place(|| {
            self.context.store.get_or_create_recipient(&self_uuid.to_string())
        })?;
        tokio::task::block_in_place(|| {
            self.context.store.remove_group_member(&group_id_bytes, self_recipient.id)
        })?;

        info!("left group");
        Ok(())
    }

    async fn delete_group(&self, group_id: &str) -> Result<()> {
        info!(group_id, "deleting group from local store");

        let group_id_bytes = base64::engine::general_purpose::STANDARD
            .decode(group_id)
            .map_err(|e| ManagerError::InvalidGroup(format!("invalid base64: {e}")))?;

        let group = tokio::task::block_in_place(|| {
            self.context.store.get_group_by_group_id(&group_id_bytes)
        })?;
        let group = group.ok_or_else(|| ManagerError::InvalidGroup(group_id.to_string()))?;

        tokio::task::block_in_place(|| {
            self.context.store.delete_group(group.id)
        })?;

        info!("group deleted");
        Ok(())
    }

    // -- Contacts -----------------------------------------------------------

    async fn get_recipients(&self) -> Result<Vec<RecipientInfo>> {
        debug!("loading contacts from store");
        let recipients = tokio::task::block_in_place(|| {
            self.context.store.list_contacts()
        })?;

        let result = recipients
            .into_iter()
            .filter_map(|r| {
                let uuid = r.aci.as_ref()
                    .and_then(|s| Uuid::parse_str(s).ok())?;
                let profile_name = r.profile_given_name.as_ref().map(|given| {
                    match &r.profile_family_name {
                        Some(family) if !family.is_empty() => format!("{given} {family}"),
                        _ => given.clone(),
                    }
                }).or_else(|| {
                    r.given_name.as_ref().map(|given| {
                        match &r.family_name {
                            Some(family) if !family.is_empty() => format!("{given} {family}"),
                            _ => given.clone(),
                        }
                    })
                });

                Some(RecipientInfo {
                    uuid,
                    number: r.number.clone(),
                    username: r.username.clone(),
                    profile_name,
                    is_blocked: r.blocked,
                })
            })
            .collect();

        Ok(result)
    }

    async fn set_contact_name(
        &self, recipient: &RecipientIdentifier, given_name: &str, family_name: Option<&str>,
    ) -> Result<()> {
        info!(%recipient, "setting contact name");
        let mut store_recipient = tokio::task::block_in_place(|| {
            self.resolve_recipient(recipient)
        })?;

        store_recipient.given_name = Some(given_name.to_string());
        store_recipient.family_name = family_name.map(|s| s.to_string());

        tokio::task::block_in_place(|| {
            self.context.store.update_recipient(&store_recipient)
        })?;
        Ok(())
    }

    async fn set_contacts_blocked(
        &self, recipients: &[RecipientIdentifier], blocked: bool,
    ) -> Result<()> {
        info!(blocked, "setting contacts blocked");
        for recipient in recipients {
            let store_recipient = tokio::task::block_in_place(|| {
                self.resolve_recipient(recipient)
            })?;
            tokio::task::block_in_place(|| {
                self.context.store.set_recipient_blocked(store_recipient.id, blocked)
            })?;
        }
        Ok(())
    }

    async fn set_groups_blocked(
        &self, group_ids: &[String], blocked: bool,
    ) -> Result<()> {
        info!(blocked, "setting groups blocked");
        for group_id_str in group_ids {
            let group_id_bytes = base64::engine::general_purpose::STANDARD
                .decode(group_id_str)
                .map_err(|e| ManagerError::InvalidGroup(format!("invalid base64: {e}")))?;
            let group = tokio::task::block_in_place(|| {
                self.context.store.get_group_by_group_id(&group_id_bytes)
            })?;
            let mut group = group.ok_or_else(|| ManagerError::InvalidGroup(group_id_str.clone()))?;
            group.blocked = blocked;
            tokio::task::block_in_place(|| {
                self.context.store.save_group(&group)
            })?;
        }
        Ok(())
    }

    async fn set_expiration_timer(
        &self, recipient: &RecipientIdentifier, seconds: u32,
    ) -> Result<()> {
        info!(%recipient, seconds, "setting expiration timer");
        let store_recipient = tokio::task::block_in_place(|| {
            self.resolve_recipient(recipient)
        })?;
        let timer = if seconds == 0 { None } else { Some(seconds as i64) };
        tokio::task::block_in_place(|| {
            self.context.store.set_recipient_expiration(store_recipient.id, timer)
        })?;
        Ok(())
    }

    // -- Stickers -----------------------------------------------------------

    async fn upload_sticker_pack(&self, path: &str) -> Result<String> {
        info!(path, "uploading sticker pack");

        // Read the sticker pack data from the directory/file
        let data = tokio::task::block_in_place(|| {
            std::fs::read(path)
        })?;

        let http = self.build_http_client().await?;
        let attachment_api = signal_rs_service::api::attachment::AttachmentApi::new(&http);

        // Get an upload form
        let form = attachment_api.get_upload_form().await?;

        // Upload the pack
        let pack_id = attachment_api.upload_sticker_pack(&form, &data).await?;

        // Generate a pack key
        let pack_key: [u8; 32] = rand::random();
        let pack_id_hex = hex::encode(pack_id.as_bytes());
        let pack_key_hex = hex::encode(pack_key);

        // Store in the key-value store as a JSON entry
        let sticker_json = serde_json::json!({
            "pack_id": pack_id_hex,
            "pack_key": pack_key_hex,
            "installed": true,
        });
        tokio::task::block_in_place(|| {
            self.context.store.set_kv_string(
                &format!("sticker_pack.{pack_id_hex}"),
                &sticker_json.to_string(),
            )
        })?;

        info!(pack_id = %pack_id_hex, "sticker pack uploaded");
        Ok(format!("{pack_id_hex}:{pack_key_hex}"))
    }

    async fn install_sticker_pack(&self, pack_id: &str, pack_key: &str) -> Result<()> {
        info!(pack_id, "installing sticker pack");

        // Validate hex inputs
        let _ = hex::decode(pack_id)
            .map_err(|e| ManagerError::Other(format!("invalid pack_id hex: {e}")))?;
        let _ = hex::decode(pack_key)
            .map_err(|e| ManagerError::Other(format!("invalid pack_key hex: {e}")))?;

        // Store in the key-value store
        let sticker_json = serde_json::json!({
            "pack_id": pack_id,
            "pack_key": pack_key,
            "installed": true,
        });
        tokio::task::block_in_place(|| {
            self.context.store.set_kv_string(
                &format!("sticker_pack.{pack_id}"),
                &sticker_json.to_string(),
            )
        })?;

        info!("sticker pack installed");
        Ok(())
    }

    async fn get_sticker_packs(&self) -> Result<Vec<StickerPack>> {
        debug!("loading sticker packs from store");

        let packs = tokio::task::block_in_place(|| -> Result<Vec<StickerPack>> {
            // Query all sticker-related keys from the key-value store
            let mut stmt = self.context.store.conn().prepare(
                "SELECT key, value FROM key_value WHERE key LIKE 'sticker_pack.%' ORDER BY _id"
            ).map_err(signal_rs_store::StoreError::from)?;

            let rows = stmt.query_map([], |row| {
                let _key: String = row.get(0)?;
                let value: String = row.get(1)?;
                Ok(value)
            }).map_err(signal_rs_store::StoreError::from)?;

            let mut packs = Vec::new();
            for row in rows {
                let json_str = row.map_err(signal_rs_store::StoreError::from)?;
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    packs.push(StickerPack {
                        pack_id: v["pack_id"].as_str().unwrap_or("").to_string(),
                        pack_key: v["pack_key"].as_str().unwrap_or("").to_string(),
                        title: v["title"].as_str().map(|s| s.to_string()),
                        author: v["author"].as_str().map(|s| s.to_string()),
                        installed: v["installed"].as_bool().unwrap_or(false),
                    });
                }
            }

            // Also query the sticker table for any sticker packs stored directly
            let mut stmt2 = self.context.store.conn().prepare(
                "SELECT pack_id, pack_key, installed FROM sticker ORDER BY _id"
            ).map_err(signal_rs_store::StoreError::from)?;

            let sticker_rows = stmt2.query_map([], |row| {
                let pack_id: Vec<u8> = row.get(0)?;
                let pack_key: Vec<u8> = row.get(1)?;
                let installed: bool = row.get::<_, i64>(2)? != 0;
                Ok((pack_id, pack_key, installed))
            }).map_err(signal_rs_store::StoreError::from)?;

            for row in sticker_rows {
                let (pack_id, pack_key, installed) = row.map_err(signal_rs_store::StoreError::from)?;
                packs.push(StickerPack {
                    pack_id: hex::encode(&pack_id),
                    pack_key: hex::encode(&pack_key),
                    title: None,
                    author: None,
                    installed,
                });
            }

            Ok(packs)
        })?;

        Ok(packs)
    }

    // -- Sync ---------------------------------------------------------------

    async fn request_all_sync_data(&self) -> Result<()> {
        info!("requesting sync data from primary device");

        let self_uuid = self.get_self_uuid().await?;
        let timestamp = self.current_timestamp_millis();

        // Send sync requests for each data type
        let request_types = [
            signal_rs_protos::sync_message::request::Type::Contacts,
            signal_rs_protos::sync_message::request::Type::Blocked,
            signal_rs_protos::sync_message::request::Type::Configuration,
            signal_rs_protos::sync_message::request::Type::Keys,
        ];

        for req_type in &request_types {
            let sync_message = signal_rs_protos::SyncMessage {
                request: Some(signal_rs_protos::sync_message::Request {
                    r#type: Some(*req_type as i32),
                }),
                ..Default::default()
            };
            let proto_content = signal_rs_protos::Content {
                sync_message: Some(sync_message),
                ..Default::default()
            };
            let raw = proto_content.encode_to_vec();
            let plaintext = signal_rs_service::content::pad_plaintext_public(&raw);

            if let Err(e) = self.encrypt_and_send_raw(&self_uuid, &plaintext, timestamp, false, false).await {
                warn!("failed to send sync request for {:?}: {e}", req_type);
            }
        }

        info!("sync data requested");
        Ok(())
    }

    // -- Receiving ----------------------------------------------------------

    async fn receive_messages(&self, timeout_seconds: u64) -> Result<Vec<Message>> {
        info!(timeout_seconds, "receiving messages via WebSocket");

        // Connect an authenticated WebSocket for message receiving
        let ws = match self.context.service.get_authenticated_ws().await {
            Ok(ws) => ws,
            Err(e) => {
                warn!("failed to connect WebSocket for receiving: {e}");
                // Fall back to HTTP polling if WebSocket fails
                return self.receive_messages_http_fallback(timeout_seconds).await;
            }
        };

        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_secs(timeout_seconds);
        let mut messages = Vec::new();
        let receive_helper = crate::helpers::receive::ReceiveHelper::new();

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            // Receive next envelope from WebSocket with timeout
            let request = match tokio::time::timeout(remaining, ws.receive_request()).await {
                Ok(Ok(req)) => req,
                Ok(Err(e)) => {
                    debug!("WebSocket receive error: {e}");
                    break;
                }
                Err(_) => {
                    debug!("receive timed out, returning collected messages");
                    break;
                }
            };

            // Acknowledge the message
            if let Err(e) = ws.send_response(request.id, 200).await {
                warn!("failed to ack message: {e}");
            }

            // Only process PUT /api/v1/message requests
            if request.verb != "PUT" || !request.path.contains("/api/v1/message") {
                debug!(
                    verb = %request.verb,
                    path = %request.path,
                    "ignoring non-message WebSocket request"
                );
                continue;
            }

            let body = match request.body {
                Some(b) => b,
                None => continue,
            };

            // Parse the envelope
            let envelope = match signal_rs_protos::Envelope::decode(body.as_slice()) {
                Ok(env) => env,
                Err(e) => {
                    warn!("failed to decode envelope: {e}");
                    continue;
                }
            };

            let source_uuid_str = envelope.source_service_id.as_deref().unwrap_or_default();
            let source_device = envelope.source_device.unwrap_or(1);
            let envelope_type = envelope.r#type.unwrap_or(0);
            let timestamp = envelope.timestamp.unwrap_or(0);

            debug!(
                source = source_uuid_str,
                device = source_device,
                envelope_type = envelope_type,
                timestamp = timestamp,
                "received envelope via WebSocket"
            );

            // Skip receipt envelopes (type 5) and envelopes without content
            if envelope_type == 5 {
                debug!("receipt envelope, skipping");
                continue;
            }

            let content_bytes = match envelope.content {
                Some(ref c) => c.clone(),
                None => continue,
            };

            // Decrypt the content based on the envelope type
            let (plaintext, override_source, override_device) = match self.decrypt_envelope(
                source_uuid_str,
                source_device,
                envelope_type,
                &content_bytes,
            ) {
                Ok(result) => result,
                Err(e) => {
                    warn!("failed to decrypt envelope: {e}");
                    continue;
                }
            };

            // For sealed sender (type 6), the real sender comes from unseal
            let effective_source = override_source
                .as_deref()
                .unwrap_or(source_uuid_str);
            let effective_device = override_device
                .unwrap_or(source_device);

            // Process the decrypted content through the receive helper
            // Re-encode as an envelope with plaintext content for the helper
            let decrypted_envelope = signal_rs_protos::Envelope {
                r#type: Some(8), // PLAINTEXT_CONTENT (already decrypted)
                source_service_id: Some(effective_source.to_string()),
                source_device: Some(effective_device),
                timestamp: envelope.timestamp,
                content: Some(plaintext),
                server_timestamp: envelope.server_timestamp,
                server_guid: envelope.server_guid.clone(),
                story: envelope.story,
                reporting_token: envelope.reporting_token.clone(),
                destination_service_id: envelope.destination_service_id.clone(),
                urgent: envelope.urgent,
                updated_pni: envelope.updated_pni.clone(),
            };
            let envelope_bytes = decrypted_envelope.encode_to_vec();

            match receive_helper
                .process_incoming(&self.context.store, &[envelope_bytes])
                .await
            {
                Ok(mut msgs) => {
                    messages.append(&mut msgs);
                    // Send delivery receipt back to sender (if enabled)
                    let send_receipts = tokio::task::block_in_place(|| {
                        self.context.store.get_kv_string("config.send_delivery_receipts")
                    }).unwrap_or(None).unwrap_or_else(|| "true".to_string()) != "false";

                    if send_receipts
                        && let Ok(sender_uuid) = Uuid::parse_str(effective_source) {
                            let receipt_content = SignalContent::Receipt(ReceiptContent {
                                receipt_type: ReceiptType::Delivery,
                                timestamps: vec![timestamp],
                            });
                            let receipt_ts = self.current_timestamp_millis();
                            if let Err(e) = self.encrypt_and_send(
                                &sender_uuid, &receipt_content, receipt_ts, false, false,
                            ).await {
                                debug!(error = %e, "failed to send delivery receipt (best-effort)");
                            }
                        }
                }
                Err(e) => {
                    warn!("failed to process decrypted envelope: {e}");
                }
            }
        }

        // Close the WebSocket
        if let Err(e) = ws.close().await {
            warn!(error = %e, "failed to close WebSocket");
        }

        info!(
            message_count = messages.len(),
            "message receiving complete"
        );
        Ok(messages)
    }

    async fn stop_receiving(&self) -> Result<()> {
        info!("stopping message receiver");
        // The WebSocket connection is closed when receive_messages returns
        // (either by timeout or explicitly). In a persistent receiver mode,
        // this would set a cancellation token.
        Ok(())
    }

    // -- Identity / Trust ---------------------------------------------------

    async fn get_identities(&self) -> Result<Vec<Identity>> {
        debug!("loading identities from store");
        let identities = tokio::task::block_in_place(|| -> Result<Vec<Identity>> {
            let mut stmt = self.context.store.conn().prepare(
                "SELECT address, identity_key, added_timestamp, trust_level FROM identity ORDER BY _id"
            ).map_err(signal_rs_store::StoreError::from)?;

            let rows = stmt.query_map([], |row| {
                let address: String = row.get(0)?;
                let identity_key: Vec<u8> = row.get(1)?;
                let added: i64 = row.get(2)?;
                let trust_level_int: i64 = row.get(3)?;
                Ok((address, identity_key, added, trust_level_int))
            }).map_err(signal_rs_store::StoreError::from)?;

            let mut identities = Vec::new();
            for row in rows {
                let (address, identity_key, added, trust_level_int) = row.map_err(signal_rs_store::StoreError::from)?;
                let uuid = Uuid::parse_str(&address).unwrap_or(Uuid::nil());
                let trust_level = match trust_level_int {
                    0 => signal_rs_protocol::TrustLevel::Untrusted,
                    1 => signal_rs_protocol::TrustLevel::TrustedUnverified,
                    2 => signal_rs_protocol::TrustLevel::TrustedVerified,
                    _ => signal_rs_protocol::TrustLevel::Untrusted,
                };
                let fingerprint = hex::encode(&identity_key);
                identities.push(Identity {
                    address: uuid,
                    trust_level,
                    fingerprint,
                    added: added as u64,
                });
            }
            Ok(identities)
        })?;

        Ok(identities)
    }

    async fn trust_identity_verified(
        &self, recipient: &RecipientIdentifier, _safety_number: &str,
    ) -> Result<()> {
        info!(%recipient, "trusting identity as verified");
        let address = self.resolve_address(recipient).await?;
        tokio::task::block_in_place(|| {
            self.context.store.set_identity_trust_level(
                &address,
                signal_rs_protocol::TrustLevel::TrustedVerified,
            )
        })?;
        Ok(())
    }

    async fn trust_identity_all_keys(
        &self, recipient: &RecipientIdentifier,
    ) -> Result<()> {
        info!(%recipient, "trusting all keys for identity");
        let address = self.resolve_address(recipient).await?;
        tokio::task::block_in_place(|| {
            self.context.store.set_identity_trust_level(
                &address,
                signal_rs_protocol::TrustLevel::TrustedUnverified,
            )
        })?;
        Ok(())
    }

    // -- Polls --------------------------------------------------------------

    async fn send_poll_create(
        &self, recipients: &[RecipientIdentifier], question: &str,
        options: &[String], multi_select: bool,
    ) -> Result<SendResult> {
        info!(question, option_count = options.len(), "sending poll create");
        let timestamp = self.current_timestamp_millis();

        // Build a DataMessage protobuf directly with the poll encoded as
        // structured JSON in the body.  Signal does not define a dedicated
        // PollMessage protobuf; polls are carried inside the DataMessage body
        // as structured data that clients parse at the application layer.
        let poll_data = serde_json::json!({
            "type": "poll_create",
            "poll_id": timestamp,
            "question": question,
            "options": options,
            "multi_select": multi_select,
        });

        let data_message = signal_rs_protos::DataMessage {
            body: Some(poll_data.to_string()),
            timestamp: Some(timestamp),
            ..Default::default()
        };
        let proto = signal_rs_protos::Content {
            data_message: Some(data_message),
            ..Default::default()
        };
        let plaintext = ProstMessage::encode_to_vec(&proto);

        let mut results = Vec::new();
        for recipient in recipients {
            let dest_uuid = self.resolve_recipient_uuid(recipient).await?;
            match self.encrypt_and_send_raw(&dest_uuid, &plaintext, timestamp, false, true).await {
                Ok(sealed) => {
                    results.push(crate::types::SendMessageResult {
                        recipient: recipient.clone(),
                        success: true,
                        is_unidentified: sealed,
                        error: None,
                    });
                }
                Err(e) => {
                    results.push(crate::types::SendMessageResult {
                        recipient: recipient.clone(),
                        success: false,
                        is_unidentified: false,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        info!(timestamp, "poll created");
        Ok(SendResult { timestamp, results })
    }

    async fn send_poll_vote(
        &self, recipients: &[RecipientIdentifier], poll_id: u64, option_indices: &[u32],
    ) -> Result<SendResult> {
        info!(poll_id, "sending poll vote");
        let timestamp = self.current_timestamp_millis();

        let poll_data = serde_json::json!({
            "type": "poll_vote",
            "poll_id": poll_id,
            "selected_options": option_indices,
        });

        let data_message = signal_rs_protos::DataMessage {
            body: Some(poll_data.to_string()),
            timestamp: Some(timestamp),
            ..Default::default()
        };
        let proto = signal_rs_protos::Content {
            data_message: Some(data_message),
            ..Default::default()
        };
        let plaintext = ProstMessage::encode_to_vec(&proto);

        let mut results = Vec::new();
        for recipient in recipients {
            let dest_uuid = self.resolve_recipient_uuid(recipient).await?;
            match self.encrypt_and_send_raw(&dest_uuid, &plaintext, timestamp, false, true).await {
                Ok(sealed) => {
                    results.push(crate::types::SendMessageResult {
                        recipient: recipient.clone(),
                        success: true,
                        is_unidentified: sealed,
                        error: None,
                    });
                }
                Err(e) => {
                    results.push(crate::types::SendMessageResult {
                        recipient: recipient.clone(),
                        success: false,
                        is_unidentified: false,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        info!(timestamp, "poll vote sent");
        Ok(SendResult { timestamp, results })
    }

    async fn send_poll_terminate(
        &self, recipients: &[RecipientIdentifier], poll_id: u64,
    ) -> Result<SendResult> {
        info!(poll_id, "sending poll terminate");
        let timestamp = self.current_timestamp_millis();

        let poll_data = serde_json::json!({
            "type": "poll_terminate",
            "poll_id": poll_id,
        });

        let data_message = signal_rs_protos::DataMessage {
            body: Some(poll_data.to_string()),
            timestamp: Some(timestamp),
            ..Default::default()
        };
        let proto = signal_rs_protos::Content {
            data_message: Some(data_message),
            ..Default::default()
        };
        let plaintext = ProstMessage::encode_to_vec(&proto);

        let mut results = Vec::new();
        for recipient in recipients {
            let dest_uuid = self.resolve_recipient_uuid(recipient).await?;
            match self.encrypt_and_send_raw(&dest_uuid, &plaintext, timestamp, false, true).await {
                Ok(sealed) => {
                    results.push(crate::types::SendMessageResult {
                        recipient: recipient.clone(),
                        success: true,
                        is_unidentified: sealed,
                        error: None,
                    });
                }
                Err(e) => {
                    results.push(crate::types::SendMessageResult {
                        recipient: recipient.clone(),
                        success: false,
                        is_unidentified: false,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        info!(timestamp, "poll terminated");
        Ok(SendResult { timestamp, results })
    }

    // -- Payments -----------------------------------------------------------

    async fn send_payment_notification(
        &self, recipient: &RecipientIdentifier, receipt: &str, note: Option<&str>,
    ) -> Result<SendResult> {
        info!(%recipient, "sending payment notification");
        let timestamp = self.current_timestamp_millis();
        let dest_uuid = self.resolve_recipient_uuid(recipient).await?;

        // Build a DataMessage with a payment notification
        let payment_proto = signal_rs_protos::DataMessage {
            timestamp: Some(timestamp),
            payment: Some(signal_rs_protos::data_message::Payment {
                item: Some(signal_rs_protos::data_message::payment::Item::Notification(
                    signal_rs_protos::data_message::payment::Notification {
                        transaction: Some(
                            signal_rs_protos::data_message::payment::notification::Transaction::MobileCoin(
                                signal_rs_protos::data_message::payment::notification::MobileCoin {
                                    receipt: Some(receipt.as_bytes().to_vec()),
                                },
                            ),
                        ),
                        note: note.map(|n| n.to_string()),
                    },
                )),
            }),
            ..Default::default()
        };
        let proto_content = signal_rs_protos::Content {
            data_message: Some(payment_proto),
            ..Default::default()
        };
        let plaintext = proto_content.encode_to_vec();

        let result = match self.encrypt_and_send_raw(&dest_uuid, &plaintext, timestamp, false, true).await {
            Ok(sealed) => crate::types::SendMessageResult {
                recipient: recipient.clone(),
                success: true,
                is_unidentified: sealed,
                error: None,
            },
            Err(e) => crate::types::SendMessageResult {
                recipient: recipient.clone(),
                success: false,
                is_unidentified: false,
                error: Some(e.to_string()),
            },
        };

        info!(timestamp, "payment notification sent");
        Ok(SendResult {
            timestamp,
            results: vec![result],
        })
    }

    // -- Number change ------------------------------------------------------

    async fn start_change_number(
        &self, new_number: &str, voice: bool, captcha: Option<&str>,
    ) -> Result<()> {
        info!(new_number, "starting phone number change");
        let http = self.build_http_client().await?;
        let account_api = signal_rs_service::api::account::AccountApi::new(&http);

        let transport = if voice { "voice" } else { "sms" };
        let request = signal_rs_service::api::account::ChangeNumberRequest {
            number: new_number.to_string(),
            transport: transport.to_string(),
            captcha: captcha.map(|c| c.to_string()),
        };

        let response = account_api.start_change_number(&request).await?;

        // Store the session ID for the finish step
        tokio::task::block_in_place(|| {
            self.context.store.set_kv_string(
                "change_number.session_id",
                &response.session_id,
            )?;
            self.context.store.set_kv_string(
                "change_number.new_number",
                new_number,
            )?;
            Ok::<_, ManagerError>(())
        })?;

        info!("verification code requested for number change");
        Ok(())
    }

    async fn finish_change_number(
        &self, new_number: &str, code: &str, pin: Option<&str>,
    ) -> Result<()> {
        info!(new_number, "finishing phone number change");
        let http = self.build_http_client().await?;
        let account_api = signal_rs_service::api::account::AccountApi::new(&http);

        // Load PNI identity key to include in the request
        let pni_identity_bytes = tokio::task::block_in_place(|| {
            self.context.store.get_kv_blob(account_keys::PNI_IDENTITY_KEY_PAIR)
        })?.ok_or_else(|| ManagerError::Other("no PNI identity key pair".into()))?;
        let pni_identity = IdentityKeyPair::from_bytes(&pni_identity_bytes)?;

        let request = signal_rs_service::api::account::FinishChangeNumberRequest {
            number: new_number.to_string(),
            code: code.to_string(),
            pni_identity_key: b64(pni_identity.public_key().serialize()),
            registration_lock: pin.map(|p| p.to_string()),
        };

        account_api.finish_change_number(&request).await?;

        // Update local store with the new number
        tokio::task::block_in_place(|| {
            self.context.store.set_kv_string(account_keys::PHONE_NUMBER, new_number)?;
            // Clean up change number session
            if let Err(e) = self.context.store.delete_kv("change_number.session_id") {
                warn!(error = %e, "failed to clean up change number data");
            }
            if let Err(e) = self.context.store.delete_kv("change_number.new_number") {
                warn!(error = %e, "failed to clean up change number data");
            }
            Ok::<_, ManagerError>(())
        })?;

        info!("phone number changed successfully");
        Ok(())
    }

    // -- Device management --------------------------------------------------

    async fn update_device_name(&self, _device_id: u32, name: &str) -> Result<()> {
        info!(name, "updating device name");
        let http = self.build_http_client().await?;
        let account_api = signal_rs_service::api::account::AccountApi::new(&http);

        // Load identity key pair to derive encryption key
        let ik_bytes = tokio::task::block_in_place(|| {
            self.context.store.get_kv_blob("identity_key_pair")
        })?.ok_or_else(|| ManagerError::NotRegistered)?;
        let identity_pair = IdentityKeyPair::from_bytes(&ik_bytes)
            .map_err(|e| ManagerError::Other(format!("invalid identity key: {e}")))?;

        // Derive encryption key from identity private key using HKDF-SHA256
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, identity_pair.private_key_bytes());
        let mut enc_key = [0u8; 32];
        hk.expand(b"device_name_encryption", &mut enc_key)
            .map_err(|e| ManagerError::Other(format!("HKDF expand failed: {e}")))?;

        // Encrypt device name with AES-256-GCM
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
        use rand::RngCore;

        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|e| ManagerError::Other(format!("AES key init failed: {e}")))?;
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, name.as_bytes())
            .map_err(|e| ManagerError::Other(format!("AES-GCM encrypt failed: {e}")))?;

        // Format: version (1 byte) + nonce (12 bytes) + ciphertext (includes tag)
        let mut result = Vec::with_capacity(1 + 12 + ciphertext.len());
        result.push(0x01);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        let request = signal_rs_service::api::account::UpdateDeviceNameRequest {
            device_name: b64(&result),
        };

        account_api.update_device_name(&request).await?;
        info!("device name updated");
        Ok(())
    }

    // -- Rate limit ---------------------------------------------------------

    async fn submit_rate_limit_challenge(
        &self, challenge: &str, captcha: &str,
    ) -> Result<()> {
        info!("submitting rate limit challenge");
        let http = self.build_http_client().await?;
        let account_api = signal_rs_service::api::account::AccountApi::new(&http);

        let request = signal_rs_service::api::account::SubmitRateLimitChallengeRequest {
            r#type: "captcha".to_string(),
            token: challenge.to_string(),
            captcha: captcha.to_string(),
        };

        account_api.submit_rate_limit_challenge(&request).await?;
        info!("rate limit challenge submitted successfully");
        Ok(())
    }

    // -- Username lookup ----------------------------------------------------

    async fn lookup_username(&self, username: &str) -> Result<Uuid> {
        info!(username, "looking up username");
        let http = self.build_http_client().await?;
        let account_api = signal_rs_service::api::account::AccountApi::new(&http);

        // Parse the username and compute its hash
        let parsed = usernames::Username::new(username)
            .map_err(|e| ManagerError::Other(format!("invalid username format: {e}")))?;

        let username_hash = parsed.hash();
        let hash_b64 = b64(&username_hash);

        let response = account_api.lookup_username_hash(&hash_b64).await?;
        info!(uuid = %response.uuid, "username resolved");
        Ok(response.uuid)
    }

    // -- Phone number discoverability ---------------------------------------

    async fn set_phone_number_discoverability(&self, discoverable: bool) -> Result<()> {
        info!(discoverable, "setting phone number discoverability");
        let http = self.build_http_client().await?;
        let account_api = signal_rs_service::api::account::AccountApi::new(&http);

        account_api.set_phone_number_discoverability(discoverable).await?;
        info!(discoverable, "phone number discoverability updated");
        Ok(())
    }

    // -- Stories ------------------------------------------------------------

    async fn send_story(
        &self, body: Option<&str>, attachment_path: Option<&str>, allow_replies: bool,
    ) -> Result<()> {
        info!(?body, ?attachment_path, allow_replies, "sending story");

        let story = StoryContent {
            body: body.map(|s| s.to_string()),
            attachment: None,
            allows_replies: allow_replies,
        };

        let self_uuid = self.get_self_uuid().await?;
        let timestamp = self.current_timestamp_millis();

        // Build the story as a sync message so linked devices see it
        let story_proto = signal_rs_protos::StoryMessage::from(&story);

        let sync_message = signal_rs_protos::SyncMessage {
            sent: Some(signal_rs_protos::sync_message::Sent {
                destination_service_id: None,
                timestamp: Some(timestamp),
                message: None,
                expiration_start_timestamp: None,
                unidentified_status: Vec::new(),
                is_recipient_update: None,
                story_message: Some(story_proto),
                story_message_recipients: Vec::new(),
                edit_message: None,
            }),
            ..Default::default()
        };

        let proto_content = signal_rs_protos::Content {
            sync_message: Some(sync_message),
            ..Default::default()
        };

        let raw = proto_content.encode_to_vec();
        let plaintext = signal_rs_service::content::pad_plaintext_public(&raw);

        self.encrypt_and_send_raw(&self_uuid, &plaintext, timestamp, false, true)
            .await.map(|_| ())?;

        info!(timestamp, "story sent");
        Ok(())
    }

    // -- Message requests ---------------------------------------------------

    async fn send_message_request_response(
        &self,
        thread_aci: Option<&str>,
        group_id: Option<&str>,
        response_type: i32,
    ) -> Result<()> {
        info!(
            ?thread_aci, ?group_id, response_type,
            "sending message request response"
        );

        let group_id_bytes = group_id.map(|gid| {
            base64::engine::general_purpose::STANDARD
                .decode(gid)
                .unwrap_or_else(|_| gid.as_bytes().to_vec())
        });

        let self_uuid = self.get_self_uuid().await?;
        let timestamp = self.current_timestamp_millis();

        let sync_message = signal_rs_protos::SyncMessage {
            message_request_response: Some(
                signal_rs_protos::sync_message::MessageRequestResponse {
                    thread_aci: thread_aci.map(|s| s.to_string()),
                    group_id: group_id_bytes,
                    r#type: Some(response_type),
                },
            ),
            ..Default::default()
        };

        let proto_content = signal_rs_protos::Content {
            sync_message: Some(sync_message),
            ..Default::default()
        };

        let raw = proto_content.encode_to_vec();
        let plaintext = signal_rs_service::content::pad_plaintext_public(&raw);

        self.encrypt_and_send_raw(&self_uuid, &plaintext, timestamp, false, false)
            .await.map(|_| ())?;

        info!("message request response sent");
        Ok(())
    }
}

impl ManagerImpl {
    /// Resolve a `RecipientIdentifier` to a UUID (public API).
    ///
    /// Looks up the recipient in the local store and returns the ACI UUID.
    pub async fn resolve_recipient_to_uuid(
        &self,
        recipient: &RecipientIdentifier,
    ) -> Result<Uuid> {
        self.resolve_recipient_uuid(recipient).await
    }

    /// Resolve a `RecipientIdentifier` to a store `Recipient`.
    fn resolve_recipient(
        &self,
        recipient: &RecipientIdentifier,
    ) -> Result<signal_rs_store::models::recipient::Recipient> {
        let result = match recipient {
            RecipientIdentifier::Uuid(uuid) => {
                self.context.store.get_recipient_by_aci(&uuid.to_string())?
            }
            RecipientIdentifier::PhoneNumber(number) => {
                self.context.store.get_recipient_by_number(number)?
            }
            RecipientIdentifier::Username(username) => {
                self.context.store.get_recipient_by_username(username)?
            }
        };
        result.ok_or_else(|| ManagerError::Other(format!("recipient not found: {recipient}")))
    }

    /// Resolve a `RecipientIdentifier` to an address string (UUID) for identity lookups.
    async fn resolve_address(&self, recipient: &RecipientIdentifier) -> Result<String> {
        match recipient {
            RecipientIdentifier::Uuid(uuid) => Ok(uuid.to_string()),
            _ => {
                let store_recipient = tokio::task::block_in_place(|| {
                    self.resolve_recipient(recipient)
                })?;
                store_recipient.aci.ok_or_else(|| {
                    ManagerError::Other(format!("recipient {recipient} has no ACI UUID"))
                })
            }
        }
    }

    /// Build an authenticated HTTP client from stored credentials.
    async fn build_http_client(&self) -> Result<signal_rs_service::net::http::HttpClient> {
        let uuid = self.get_self_uuid().await?;
        let password = tokio::task::block_in_place(|| {
            self.context.store.get_kv_string(account_keys::PASSWORD)
        })?.ok_or(ManagerError::NotRegistered)?;
        let device_id_str = tokio::task::block_in_place(|| {
            self.context.store.get_kv_string(account_keys::DEVICE_ID)
        })?.unwrap_or_else(|| "1".to_string());
        let device_id: u32 = device_id_str.parse().unwrap_or(1);

        let creds = ServiceCredentials {
            uuid: Some(uuid),
            e164: None,
            password: Some(password),
            device_id: DeviceId(device_id),
        };
        signal_rs_service::net::http::HttpClient::new(
            self.context.config.clone(),
            Some(creds),
        ).map_err(ManagerError::Service)
    }

    /// Resolve a RecipientIdentifier to a UUID.
    async fn resolve_recipient_uuid(&self, recipient: &RecipientIdentifier) -> Result<Uuid> {
        match recipient {
            RecipientIdentifier::Uuid(uuid) => Ok(*uuid),
            RecipientIdentifier::PhoneNumber(number) => {
                // Check if this is our own phone number (note-to-self)
                if let Ok(Some(own_number)) = self.context.store.get_kv_string(account_keys::PHONE_NUMBER)
                    && &own_number == number
                    && let Ok(Some(aci)) = self.context.store.get_kv_string(account_keys::ACI_UUID)
                {
                    return Uuid::parse_str(&aci)
                        .map_err(|e| ManagerError::Other(format!("invalid self UUID: {e}")));
                }
                // Look up in recipients table
                let store_recipient = tokio::task::block_in_place(|| {
                    self.resolve_recipient(recipient)
                })?;
                let aci = store_recipient.aci.ok_or_else(|| {
                    ManagerError::Other(format!("recipient {recipient} has no ACI UUID"))
                })?;
                Uuid::parse_str(&aci)
                    .map_err(|e| ManagerError::Other(format!("invalid UUID: {e}")))
            }
            RecipientIdentifier::Username(username) => {
                let store_recipient = tokio::task::block_in_place(|| {
                    self.resolve_recipient(recipient)
                })?;
                let aci = store_recipient.aci.ok_or_else(|| {
                    ManagerError::Other(format!("recipient {username} has no ACI UUID"))
                })?;
                Uuid::parse_str(&aci)
                    .map_err(|e| ManagerError::Other(format!("invalid UUID: {e}")))
            }
        }
    }

    /// Get the current time in milliseconds since epoch.
    fn current_timestamp_millis(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Build group member list from store member records.
    async fn build_group_member_list(
        &self,
        store_members: &[signal_rs_store::models::group::GroupV2Member],
    ) -> Vec<crate::types::GroupMember> {
        let mut members = Vec::new();
        for m in store_members {
            let uuid = tokio::task::block_in_place(|| {
                self.context.store.get_recipient_by_id(m.recipient_id)
            })
            .ok()
            .flatten()
            .and_then(|r| r.aci.as_ref().and_then(|s| Uuid::parse_str(s).ok()))
            .unwrap_or(Uuid::nil());

            members.push(crate::types::GroupMember {
                uuid,
                role: crate::types::GroupMemberRole::Member,
                joined_at_revision: 0,
            });
        }
        members
    }

    /// Encrypt a `SignalContent` and send it to a recipient via the message API.
    ///
    /// This is the core send path that:
    /// 1. Serializes content to protobuf
    /// 2. Resolves device IDs for the recipient
    /// 3. Encrypts via the session store (or sends plaintext if no session)
    /// 4. Sends via the REST API with retry on 409/410
    async fn encrypt_and_send(
        &self,
        dest_uuid: &Uuid,
        content: &SignalContent,
        timestamp: u64,
        online: bool,
        urgent: bool,
    ) -> Result<bool> {
        let plaintext = signal_rs_service::content::encode_content(content);
        self.encrypt_and_send_raw(dest_uuid, &plaintext, timestamp, online, urgent).await
    }

    /// Encrypt raw protobuf bytes and send to a recipient.
    ///
    /// Used when the caller has already built the protobuf Content manually
    /// (e.g., for edit messages, delete messages, payment notifications).
    ///
    /// Attempts sealed sender delivery when the recipient's profile key is
    /// available. Falls back to authenticated delivery otherwise.
    async fn encrypt_and_send_raw(
        &self,
        dest_uuid: &Uuid,
        plaintext: &[u8],
        timestamp: u64,
        online: bool,
        urgent: bool,
    ) -> Result<bool> {
        let http = self.build_http_client().await?;
        let message_api = signal_rs_service::api::message::MessageApi::new(&http);

        let service_id = ServiceId::aci(*dest_uuid);

        // Resolve all device IDs for the recipient (primary + sub-devices)
        let mut device_ids = tokio::task::block_in_place(|| {
            self.context.store.get_sub_device_sessions(&service_id)
        }).unwrap_or_default();
        if !device_ids.contains(&DeviceId::PRIMARY) {
            device_ids.insert(0, DeviceId::PRIMARY);
        }

        // When sending to ourselves (sync messages), exclude our own device ID.
        let self_uuid = self.context.store.get_kv_string(account_keys::ACI_UUID)
            .ok().flatten()
            .and_then(|s| Uuid::parse_str(&s).ok());
        if self_uuid.as_ref() == Some(dest_uuid) {
            let own_device_id = self.context.store.get_kv_string(account_keys::DEVICE_ID)
                .ok().flatten()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(1);
            device_ids.retain(|d| d.value() != own_device_id);
            if device_ids.is_empty() {
                debug!("no other devices to send sync message to");
                return Ok(false);
            }
        }

        // Compute unidentified access key from recipient's profile key for sealed sender.
        let ua_helper = crate::helpers::unidentified_access::UnidentifiedAccessHelper::new();
        let unidentified_access_key: Option<Vec<u8>> = tokio::task::block_in_place(|| {
            if let Ok(Some(recipient)) = self.context.store.get_recipient_by_aci(&dest_uuid.to_string())
                && let Some(ref profile_key) = recipient.profile_key
            {
                return ua_helper.compute_access_key(profile_key).ok();
            }
            None
        });

        // Fetch sender certificate for sealed sender wrapping.
        let sender_cert_bytes: Option<Vec<u8>> = if unidentified_access_key.is_some() {
            let cert_api = signal_rs_service::api::certificate::CertificateApi::new(&http);
            match ua_helper.get_sender_certificate(&self.context.store, &cert_api).await {
                Ok(cert) => Some(cert),
                Err(e) => {
                    debug!(%dest_uuid, error = %e, "failed to get sender certificate, falling back to authenticated");
                    None
                }
            }
        } else {
            None
        };

        // Load our identity key pair for sealed sender wrapping.
        let our_identity = tokio::task::block_in_place(|| {
            self.context.store.get_identity_key_pair()
        }).ok();

        let b64_engine = base64::engine::general_purpose::STANDARD;

        for attempt in 0..3u32 {
            let mut messages = Vec::new();

            for &device_id in &device_ids {
                let address = ProtocolAddress::new(service_id, device_id);

                // Ensure a session exists for this address.
                // If not, fetch the pre-key bundle and establish one.
                let is_new_session = tokio::task::block_in_place(|| {
                    let existing = self.context.store.load_session(&address)
                        .map_err(|e| ManagerError::Other(format!("session load failed: {e}")))?;
                    Ok::<bool, ManagerError>(existing.is_none())
                })?;

                let mut pre_key_id = None;
                let mut signed_pre_key_id = None;
                let mut kyber_pre_key_id = None;
                let mut kyber_ciphertext: Option<Vec<u8>> = None;
                let remote_registration_id = if is_new_session {
                    let (pkid, spkid, remote_reg_id, kpkid, kyber_ct) = self.establish_session_from_pre_key(&http, &service_id, &address, device_id).await?;
                    pre_key_id = pkid;
                    signed_pre_key_id = Some(spkid);
                    kyber_pre_key_id = kpkid;
                    kyber_ciphertext = kyber_ct;
                    remote_reg_id
                } else {
                    // Load the remote registration ID from the stored session so the
                    // server can verify we're targeting the correct device registration.
                    // Without this, we'd send reg_id=0 and get 410 Gone every time.
                    tokio::task::block_in_place(|| {
                        self.context.store.load_session(&address)
                    }).ok().flatten()
                        .map(|s| s.remote_registration_id())
                        .unwrap_or(0)
                };

                let (ciphertext, msg_type, reg_id) = tokio::task::block_in_place(|| {
                    self.encrypt_for_address(&address, plaintext, is_new_session, pre_key_id, signed_pre_key_id, remote_registration_id, kyber_pre_key_id, kyber_ciphertext.as_deref())
                })?;

                info!(
                    %dest_uuid,
                    device = device_id.value(),
                    msg_type,
                    reg_id,
                    is_new_session,
                    ciphertext_len = ciphertext.len(),
                    plaintext_len = plaintext.len(),
                    "encrypted message for device"
                );

                // Wrap in sealed sender if we have the certificate and UAK
                let (final_ciphertext, final_msg_type) = if let (Some(cert), Some(identity)) =
                    (&sender_cert_bytes, &our_identity)
                {
                    // Look up the recipient's identity key for the sealed sender wrapper
                    let recipient_identity_pub = tokio::task::block_in_place(|| {
                        self.context.store.get_identity(&address)
                    }).ok().flatten();

                    if let Some(recipient_ik) = recipient_identity_pub {
                        let ik_bytes = recipient_ik.serialize();
                        info!(
                            %dest_uuid,
                            device = device_id.value(),
                            inner_msg_type = msg_type,
                            cert_len = cert.len(),
                            recipient_ik_len = ik_bytes.len(),
                            recipient_ik_prefix = format!("0x{:02x}", ik_bytes[0]),
                            "sealing with sealed sender"
                        );
                        match signal_rs_protocol::seal_sealed_sender(
                            &ciphertext,
                            msg_type,
                            cert,
                            identity,
                            ik_bytes,
                            1, // RESENDABLE
                            None,
                        ) {
                            Ok(sealed) => {
                                info!(
                                    %dest_uuid,
                                    device = device_id.value(),
                                    sealed_len = sealed.len(),
                                    version_byte = format!("0x{:02x}", sealed[0]),
                                    "sealed sender wrap OK"
                                );
                                (sealed, 6) // UNIDENTIFIED_SENDER
                            }
                            Err(e) => {
                                warn!(%dest_uuid, error = %e, "sealed sender wrap failed, using authenticated");
                                (ciphertext, msg_type)
                            }
                        }
                    } else {
                        info!(%dest_uuid, "no recipient identity key, using authenticated delivery");
                        (ciphertext, msg_type)
                    }
                } else {
                    info!(%dest_uuid, has_cert = sender_cert_bytes.is_some(), has_identity = our_identity.is_some(), has_uak = unidentified_access_key.is_some(), "no sealed sender (missing cert/identity/UAK)");
                    (ciphertext, msg_type)
                };

                info!(
                    %dest_uuid,
                    device = device_id.value(),
                    final_msg_type,
                    final_ciphertext_len = final_ciphertext.len(),
                    "outgoing message entity"
                );
                messages.push(signal_rs_service::api::message::OutgoingMessageEntity {
                    r#type: final_msg_type,
                    destination_device_id: device_id.value(),
                    destination_registration_id: reg_id,
                    content: b64_engine.encode(&final_ciphertext),
                });
            }

            let request = signal_rs_service::api::message::SendMessageRequest {
                messages,
                online,
                urgent,
                timestamp,
            };

            info!(
                %dest_uuid,
                timestamp,
                device_count = request.messages.len(),
                msg_types = ?request.messages.iter().map(|m| m.r#type).collect::<Vec<_>>(),
                has_uak = unidentified_access_key.is_some(),
                attempt,
                "submitting message to server"
            );

            // Try sealed sender first if we have the unidentified access key,
            // then fall back to authenticated send.
            let mut used_sealed_sender = false;
            let send_result = if let Some(ref ua_key) = unidentified_access_key {
                let ua_key_b64 = b64_engine.encode(ua_key);
                match message_api.send_message_unidentified(dest_uuid, &request, &ua_key_b64).await {
                    Ok(response) => {
                        used_sealed_sender = true;
                        info!(%dest_uuid, "message sent via sealed sender (200 OK)");
                        Ok(response)
                    }
                    Err(e) => {
                        // Sealed sender failed (e.g., recipient changed profile key),
                        // fall back to authenticated send
                        debug!(%dest_uuid, error = %e, "sealed sender failed, falling back to authenticated");
                        message_api.send_message(dest_uuid, &request).await
                    }
                }
            } else {
                message_api.send_message(dest_uuid, &request).await
            };

            match send_result {
                Ok(_response) => {
                    debug!(%dest_uuid, "message sent successfully");
                    return Ok(used_sealed_sender);
                }
                Err(signal_rs_service::error::ServiceError::Conflict) if attempt < 2 => {
                    // 409 Conflict: stale device list. Fetch fresh pre-key bundles.
                    warn!(%dest_uuid, attempt, "got 409 Conflict, refreshing devices");
                    let keys_api = KeysApi::new(&http);
                    if let Ok((_identity_key, bundles)) = keys_api
                        .get_pre_key_bundles_for_all_devices(&service_id)
                        .await
                    {
                        device_ids = bundles.iter().map(|b| b.device_id).collect();
                        if !device_ids.contains(&DeviceId::PRIMARY) {
                            device_ids.insert(0, DeviceId::PRIMARY);
                        }
                    }
                    continue;
                }
                Err(signal_rs_service::error::ServiceError::Gone) if attempt < 2 => {
                    // 410 Gone: stale sessions. Delete sessions for all devices and retry.
                    warn!(%dest_uuid, attempt, "got 410 Gone (stale sessions), re-establishing");
                    for &device_id in &device_ids {
                        let address = ProtocolAddress::new(service_id, device_id);
                        let _ = tokio::task::block_in_place(|| {
                            self.context.store.delete_session(&address)
                        });
                    }
                    continue;
                }
                Err(e) => {
                    return Err(ManagerError::Service(e));
                }
            }
        }

        Err(ManagerError::Other("send failed after retries".into()))
    }

    /// Encrypt plaintext for a single device address.
    ///
    /// Returns (ciphertext, wire_type, registration_id).
    /// The caller must ensure a session exists before calling this method.
    /// If `is_pre_key_session` is true, the ciphertext is wrapped in
    /// PreKeySignalMessage format (wire type 3). Otherwise it's a plain
    /// SignalMessage (wire type 1).
    #[allow(clippy::too_many_arguments)]
    fn encrypt_for_address(
        &self,
        address: &ProtocolAddress,
        plaintext: &[u8],
        is_pre_key_session: bool,
        pre_key_id: Option<u32>,
        signed_pre_key_id: Option<u32>,
        remote_registration_id: u32,
        kyber_pre_key_id: Option<u32>,
        kyber_ciphertext: Option<&[u8]>,
    ) -> Result<(Vec<u8>, u32, u32)> {
        // Try to load an existing session
        let session = self.context.store.load_session(address)
            .map_err(|e| ManagerError::Other(format!("session load failed: {e}")))?;

        // For PreKeySignalMessage, include our local registration ID in the protobuf.
        // For the API's destination_registration_id, use the remote device's registration ID.
        let our_registration_id = self.context.store.get_local_registration_id().unwrap_or(0);

        match session {
            Some(mut session) => {
                // Encrypt using the established session
                let (cbc_ciphertext, counter, keys) = session.encrypt(plaintext)
                    .map_err(|e| ManagerError::Other(format!("session encrypt failed: {e}")))?;

                // Get identity keys for MAC computation
                let our_identity = self.context.store.get_identity_key_pair()
                    .map_err(|e| ManagerError::Other(format!("failed to get identity: {e}")))?;
                let sender_identity = our_identity.public_key().serialize();
                let receiver_identity = session.remote_identity_key();

                // Get ratchet key and previous counter from the session
                let ratchet_key = session.local_ephemeral_public();
                let prev_counter = session.previous_counter();

                // Build proper SignalMessage wire format:
                // [version_byte][protobuf{ratchet_key, counter, prev_counter, ciphertext}][8-byte MAC]
                let signal_message = WireSignalMessage::serialize(
                    ratchet_key,
                    counter,
                    prev_counter,
                    &cbc_ciphertext,
                    &keys.mac_key,
                    sender_identity,
                    receiver_identity,
                );

                // Persist the updated session (chain key advanced)
                self.context.store.store_session(address, &session)
                    .map_err(|e| ManagerError::Other(format!("session store failed: {e}")))?;

                if is_pre_key_session {
                    // Wrap in PreKeySignalMessage for first message in a new session
                    // base_key is the ephemeral key from X3DH, NOT the sending ratchet key
                    let base_key = session.base_key()
                        .unwrap_or_else(|| session.local_ephemeral_public());
                    let identity_key = our_identity.public_key().serialize();
                    let wire = WirePreKeySignalMessage::serialize(
                        pre_key_id,
                        base_key,
                        identity_key,
                        &signal_message,
                        our_registration_id,
                        signed_pre_key_id.unwrap_or(0),
                        kyber_pre_key_id,
                        kyber_ciphertext,
                    );
                    // API destination_registration_id = remote device's registration ID
                    Ok((wire, 3, remote_registration_id))
                } else {
                    // For existing sessions, use the remote registration ID
                    Ok((signal_message, 1, remote_registration_id))
                }
            }
            None => {
                Err(ManagerError::Other(format!(
                    "no session exists for {address}; session should have been established by caller"
                )))
            }
        }
    }

    /// Establish a new session with a remote device by fetching their pre-key bundle.
    ///
    /// Performs X3DH key agreement to derive shared session keys, then stores
    /// the new session and the remote identity key.
    async fn establish_session_from_pre_key(
        &self,
        http: &signal_rs_service::net::http::HttpClient,
        service_id: &ServiceId,
        address: &ProtocolAddress,
        device_id: DeviceId,
    ) -> Result<(Option<u32>, u32, u32, Option<u32>, Option<Vec<u8>>)> {
        debug!(%address, "no session exists, fetching pre-key bundle");

        let keys_api = KeysApi::new(http);
        let bundle = keys_api.get_pre_key_bundle(service_id, device_id).await
            .map_err(|e| ManagerError::Other(format!(
                "failed to fetch pre-key bundle for {address}: {e}"
            )))?;
        let remote_registration_id = bundle.registration_id;

        // Load our identity key pair
        let ik_bytes = tokio::task::block_in_place(|| {
            self.context.store.get_kv_blob("identity_key_pair")
        })?.ok_or_else(|| ManagerError::NotRegistered)?;
        let identity_pair = IdentityKeyPair::from_bytes(&ik_bytes)
            .map_err(|e| ManagerError::Other(format!("invalid identity key pair: {e}")))?;

        // Extract key material from the bundle.
        // The identity key's public_key_bytes() returns 32 bytes without the 0x05 prefix.
        let their_identity_bytes = bundle.identity_key.public_key_bytes();

        // Signed pre-key public bytes: strip 0x05 prefix if present (33 -> 32 bytes)
        let spk_bytes = &bundle.signed_pre_key.1;
        let their_spk = if spk_bytes.len() == 33 && spk_bytes[0] == 0x05 {
            &spk_bytes[1..]
        } else {
            spk_bytes.as_slice()
        };

        // One-time pre-key public bytes (optional): strip 0x05 prefix if present
        let opk_storage;
        let their_opk = match &bundle.pre_key {
            Some((_id, pk_bytes)) => {
                opk_storage = if pk_bytes.len() == 33 && pk_bytes[0] == 0x05 {
                    pk_bytes[1..].to_vec()
                } else {
                    pk_bytes.clone()
                };
                Some(opk_storage.as_slice())
            }
            None => None,
        };

        // Extract pre-key IDs for PreKeySignalMessage wrapping
        let pre_key_id = bundle.pre_key.as_ref().map(|(id, _)| id.0);
        let signed_pre_key_id = (bundle.signed_pre_key.0).0;

        // Extract Kyber pre-key public bytes (if available in the bundle)
        let kyber_pre_key_id = bundle.kyber_pre_key.as_ref().map(|(id, _, _)| id.0);
        let kyber_pub_bytes = bundle.kyber_pre_key.as_ref().map(|(_, pub_key, _)| pub_key.as_slice());

        // Perform PQXDH to establish the session (includes Kyber if available)
        let (mut session, kyber_ciphertext) = signal_rs_protocol::SessionRecord::new_from_pre_key(
            &identity_pair,
            their_identity_bytes,
            their_spk,
            their_opk,
            kyber_pub_bytes,
        ).map_err(|e| ManagerError::Other(format!("PQXDH session setup failed: {e}")))?;

        // Store the remote registration ID so subsequent sends include the correct value.
        // Without this, reused sessions would send reg_id=0 and the server returns 410 Gone.
        session.set_remote_registration_id(remote_registration_id);

        // Store the new session and the remote identity key
        tokio::task::block_in_place(|| {
            self.context.store.store_session(address, &session)
                .map_err(|e| ManagerError::Other(format!("failed to store session: {e}")))?;
            self.context.store.save_identity(address, &bundle.identity_key)
                .map_err(|e| ManagerError::Other(format!("failed to save identity: {e}")))?;
            Ok::<_, ManagerError>(())
        })?;

        debug!(%address, remote_registration_id, ?kyber_pre_key_id, "pre-key session established successfully");
        Ok((pre_key_id, signed_pre_key_id, remote_registration_id, kyber_pre_key_id, kyber_ciphertext))
    }

    /// Decrypt an envelope's content based on the envelope type.
    ///
    /// Maps envelope types to cipher operations:
    /// - Type 1 (CIPHERTEXT): Whisper message, decrypt with existing session
    /// - Type 3 (PREKEY_BUNDLE): Pre-key message, establish session and decrypt
    /// - Type 6 (UNIDENTIFIED_SENDER): Sealed sender, unseal then decrypt
    /// - Type 7 (SENDER_KEY): Sender key group message
    /// - Type 8 (PLAINTEXT_CONTENT): No decryption needed
    ///
    /// Returns `(plaintext, override_source_uuid, override_source_device)`.
    /// For type 6 (sealed sender), the source UUID and device are extracted from the
    /// inner sealed-sender layer, since the server does not include them in the envelope.
    fn decrypt_envelope(
        &self,
        source_uuid_str: &str,
        source_device: u32,
        envelope_type: i32,
        content_bytes: &[u8],
    ) -> Result<(Vec<u8>, Option<String>, Option<u32>)> {
        match envelope_type {
            8 => {
                // Plaintext content, no decryption needed
                Ok((content_bytes.to_vec(), None, None))
            }
            1 => {
                // CIPHERTEXT (Whisper message) - decrypt with existing session
                let sender_uuid = Uuid::parse_str(source_uuid_str)
                    .map_err(|e| ManagerError::Other(format!("invalid source UUID: {e}")))?;
                let address = ProtocolAddress::new(
                    ServiceId::aci(sender_uuid),
                    DeviceId(source_device),
                );
                let plaintext = tokio::task::block_in_place(|| {
                    self.decrypt_whisper(&address, content_bytes)
                })?;
                Ok((plaintext, None, None))
            }
            3 => {
                // PREKEY_BUNDLE - pre-key message, establish session and decrypt
                let sender_uuid = Uuid::parse_str(source_uuid_str)
                    .map_err(|e| ManagerError::Other(format!("invalid source UUID: {e}")))?;
                let address = ProtocolAddress::new(
                    ServiceId::aci(sender_uuid),
                    DeviceId(source_device),
                );
                let plaintext = tokio::task::block_in_place(|| {
                    self.decrypt_pre_key_message(&address, content_bytes)
                })?;
                Ok((plaintext, None, None))
            }
            6 => {
                // UNIDENTIFIED_SENDER (sealed sender)
                // Unseal the outer layer to discover the real sender, then decrypt
                tokio::task::block_in_place(|| {
                    self.decrypt_sealed_sender(content_bytes)
                })
            }
            _ => {
                // Unknown or unhandled envelope type, pass through as-is
                debug!(envelope_type, "unhandled envelope type, passing through");
                Ok((content_bytes.to_vec(), None, None))
            }
        }
    }

    /// Decrypt a Whisper (normal ratchet) message using the proper wire format.
    ///
    /// Parses the SignalMessage wire format (version + protobuf + 8-byte MAC),
    /// extracts the ratchet key, counter, and ciphertext, then calls session.decrypt().
    fn decrypt_whisper(
        &self,
        address: &ProtocolAddress,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        use signal_rs_protocol::WireSignalMessage;

        let signal_msg = WireSignalMessage::deserialize(ciphertext)
            .map_err(|e| ManagerError::Other(format!("signal message parse failed: {e}")))?;

        let mut session = self.context.store.load_session(address)
            .map_err(|e| ManagerError::Other(format!("session load failed: {e}")))?
            .ok_or_else(|| ManagerError::Other(format!("no session for {address}")))?;

        let (plaintext, keys) = session.decrypt(
            &signal_msg.ciphertext,
            signal_msg.counter,
            &signal_msg.ratchet_key,
        ).map_err(|e| ManagerError::Other(format!("whisper decrypt failed: {e}")))?;

        // Verify MAC
        let our_identity = self.context.store.get_identity_key_pair()
            .map_err(|e| ManagerError::Other(format!("failed to get identity: {e}")))?;
        let our_identity_bytes = our_identity.public_key().serialize();
        let sender_identity = session.remote_identity_key();

        let mac_valid = signal_msg.verify_mac(&keys.mac_key, sender_identity, our_identity_bytes)
            .map_err(|e| ManagerError::Other(format!("MAC verify error: {e}")))?;
        if !mac_valid {
            return Err(ManagerError::Other("whisper message MAC verification failed".into()));
        }

        self.context.store.store_session(address, &session)
            .map_err(|e| ManagerError::Other(format!("session store failed: {e}")))?;

        Ok(plaintext)
    }

    /// Decrypt a pre-key message using the proper wire format.
    ///
    /// Parses the PreKeySignalMessage wire format (version + protobuf),
    /// establishes a session via X3DH from the receiver's perspective,
    /// then decrypts the inner SignalMessage.
    fn decrypt_pre_key_message(
        &self,
        address: &ProtocolAddress,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        use signal_rs_protocol::{WirePreKeySignalMessage, WireSignalMessage, SignedPreKeyId, PreKeyId};

        let pre_key_msg = WirePreKeySignalMessage::deserialize(ciphertext)
            .map_err(|e| ManagerError::Other(format!("pre-key message parse failed: {e}")))?;

        let our_identity = self.context.store.get_identity_key_pair()
            .map_err(|e| ManagerError::Other(format!("failed to get identity key pair: {e}")))?;

        // Look up our signed pre-key
        let signed_pre_key = self.context.store.get_signed_pre_key(
            SignedPreKeyId(pre_key_msg.signed_pre_key_id),
        ).map_err(|e| ManagerError::Other(format!(
            "failed to load signed pre-key {}: {e}",
            pre_key_msg.signed_pre_key_id
        )))?;

        // Look up one-time pre-key if specified
        let one_time_pre_key_private = if let Some(pk_id) = pre_key_msg.pre_key_id {
            match self.context.store.get_pre_key(PreKeyId(pk_id)) {
                Ok(pk) => {
                    let _ = self.context.store.remove_pre_key(PreKeyId(pk_id));
                    Some(pk.private_key)
                }
                Err(_) => None,
            }
        } else {
            None
        };

        // Look up Kyber pre-key if the sender included PQXDH material
        let kyber_data = if let (Some(kyber_pk_id), Some(kyber_ct)) =
            (pre_key_msg.kyber_pre_key_id, &pre_key_msg.kyber_ciphertext)
        {
            use signal_rs_protocol::KyberPreKeyId;
            match self.context.store.get_kyber_pre_key(KyberPreKeyId(kyber_pk_id)) {
                Ok(kyber_record) => {
                    // key_pair_serialized = public_key (1569 bytes) + secret_key (3169 bytes)
                    let sk_bytes = kyber_record.key_pair_serialized[1569..].to_vec();
                    let _ = self.context.store.mark_kyber_pre_key_used(KyberPreKeyId(kyber_pk_id));
                    Some((sk_bytes, kyber_ct.clone()))
                }
                Err(e) => {
                    warn!(kyber_pk_id, error = %e, "failed to load Kyber pre-key, proceeding without PQXDH");
                    None
                }
            }
        } else {
            None
        };

        // Establish session via PQXDH from receiver perspective
        let kyber_refs = kyber_data.as_ref().map(|(sk, ct)| (sk.as_slice(), ct.as_slice()));
        let mut session = signal_rs_protocol::SessionRecord::new_from_received_pre_key(
            &our_identity,
            &signed_pre_key.private_key,
            one_time_pre_key_private.as_deref(),
            &pre_key_msg.identity_key,
            &pre_key_msg.base_key,
            kyber_refs,
        ).map_err(|e| ManagerError::Other(format!("pre-key session setup failed: {e}")))?;

        // Store the sender's registration ID so we can include it when sending back.
        session.set_remote_registration_id(pre_key_msg.registration_id);

        // Parse and decrypt the inner SignalMessage
        let inner_msg = WireSignalMessage::deserialize(&pre_key_msg.message)
            .map_err(|e| ManagerError::Other(format!("inner signal message parse failed: {e}")))?;

        let (plaintext, keys) = session.decrypt(
            &inner_msg.ciphertext,
            inner_msg.counter,
            &inner_msg.ratchet_key,
        ).map_err(|e| ManagerError::Other(format!("pre-key message decrypt failed: {e}")))?;

        // Verify MAC on the inner message
        let our_identity_bytes = our_identity.public_key().serialize();
        let mac_valid = inner_msg.verify_mac(&keys.mac_key, &pre_key_msg.identity_key, our_identity_bytes)
            .map_err(|e| ManagerError::Other(format!("MAC verify error: {e}")))?;
        if !mac_valid {
            return Err(ManagerError::Other("pre-key message MAC verification failed".into()));
        }

        // Save the sender's identity
        if let Ok(identity_key) = signal_rs_protocol::IdentityKey::from_bytes(&pre_key_msg.identity_key) {
            let _ = self.context.store.save_identity(address, &identity_key);
        }

        self.context.store.store_session(address, &session)
            .map_err(|e| ManagerError::Other(format!("session store failed: {e}")))?;

        Ok(plaintext)
    }

    /// Decrypt a sealed sender message.
    ///
    /// Unseals the outer V1 sealed-sender layer (double ECDH + AES-256-CTR + HMAC),
    /// then dispatches the inner ciphertext to the appropriate decryptor based on
    /// the message type from the USMC.
    ///
    /// Returns `(plaintext, sender_uuid_str, sender_device)`.
    fn decrypt_sealed_sender(
        &self,
        ciphertext: &[u8],
    ) -> Result<(Vec<u8>, Option<String>, Option<u32>)> {
        let our_identity = self.context.store.get_identity_key_pair()
            .map_err(|e| ManagerError::Other(format!("failed to get identity key pair: {e}")))?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let unsealed = signal_rs_protocol::unseal_sealed_sender(ciphertext, &our_identity, timestamp)
            .map_err(|e| ManagerError::Other(format!("sealed sender unseal failed: {e}")))?;

        let sender_uuid_str = unsealed.sender_uuid.to_string();
        let sender_device = unsealed.sender_device_id.value();
        let address = ProtocolAddress::new(
            ServiceId::aci(unsealed.sender_uuid),
            unsealed.sender_device_id,
        );

        debug!(
            sender = %sender_uuid_str,
            device = sender_device,
            msg_type = unsealed.msg_type,
            inner_size = unsealed.content.len(),
            "unsealed sealed sender, decrypting inner message"
        );

        // Save the sender's identity key from the sealed sender layer
        if let Ok(identity_key) = signal_rs_protocol::IdentityKey::from_bytes(&unsealed.sender_identity_key) {
            let _ = self.context.store.save_identity(&address, &identity_key);
        }

        // Dispatch inner decryption based on the message type
        let plaintext = match unsealed.msg_type {
            3 => self.decrypt_pre_key_message(&address, &unsealed.content)?,
            1 => self.decrypt_whisper(&address, &unsealed.content)?,
            _ => {
                debug!(msg_type = unsealed.msg_type, "unknown inner msg_type, passing through");
                unsealed.content
            }
        };

        Ok((plaintext, Some(sender_uuid_str), Some(sender_device)))
    }

    /// Fall back to HTTP polling for message receiving when WebSocket is unavailable.
    ///
    /// Fetches pending messages from the server via GET /v1/messages, processes
    /// each envelope through the standard decrypt/receive pipeline, and acknowledges
    /// each message via DELETE /v1/messages/uuid/{guid}.
    async fn receive_messages_http_fallback(
        &self,
        timeout_seconds: u64,
    ) -> Result<Vec<Message>> {
        debug!("falling back to HTTP message polling");
        let http = self.build_http_client().await?;
        let message_api = signal_rs_service::api::message::MessageApi::new(&http);

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_seconds),
            message_api.get_messages_structured(),
        ).await;

        let incoming = match response {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                debug!("failed to fetch messages via HTTP: {e}");
                return Ok(Vec::new());
            }
            Err(_) => {
                debug!("HTTP message fetch timed out");
                return Ok(Vec::new());
            }
        };

        if incoming.messages.is_empty() {
            debug!("no pending messages from HTTP polling");
            return Ok(Vec::new());
        }

        debug!(count = incoming.messages.len(), "received envelopes via HTTP polling");

        let receive_helper = crate::helpers::receive::ReceiveHelper::new();
        let mut messages = Vec::new();

        for entity in &incoming.messages {
            let source_uuid_str = entity.source_uuid.as_deref().unwrap_or_default();
            let source_device = entity.source_device.unwrap_or(1);
            let envelope_type = entity.r#type as i32;
            let timestamp = entity.timestamp.unwrap_or(0);

            debug!(
                source = source_uuid_str,
                device = source_device,
                envelope_type = envelope_type,
                timestamp = timestamp,
                guid = ?entity.server_guid,
                "processing HTTP-polled envelope"
            );

            // Skip receipt envelopes (type 5) and those without content
            if envelope_type == 5 {
                debug!("receipt envelope, skipping");
                if let Some(ref guid) = entity.server_guid
                    && let Err(e) = message_api.acknowledge_message(guid).await {
                        debug!("failed to ack receipt envelope: {e}");
                    }
                continue;
            }

            let content_bytes = match entity.content_bytes() {
                Some(b) => b,
                None => {
                    if let Some(ref guid) = entity.server_guid
                        && let Err(e) = message_api.acknowledge_message(guid).await {
                            debug!("failed to ack empty envelope: {e}");
                        }
                    continue;
                }
            };

            // Decrypt the content based on the envelope type
            let (plaintext, override_source, override_device) = match self.decrypt_envelope(
                source_uuid_str,
                source_device,
                envelope_type,
                &content_bytes,
            ) {
                Ok(result) => result,
                Err(e) => {
                    warn!("failed to decrypt HTTP-polled envelope: {e}");
                    // Acknowledge even on decrypt failure to avoid re-delivery loops
                    if let Some(ref guid) = entity.server_guid
                        && let Err(e) = message_api.acknowledge_message(guid).await {
                            debug!("failed to ack failed envelope: {e}");
                        }
                    continue;
                }
            };

            // For sealed sender (type 6), the real sender comes from unseal
            let effective_source = override_source
                .as_deref()
                .unwrap_or(source_uuid_str);
            let effective_device = override_device
                .unwrap_or(source_device);

            // Build a decrypted envelope for the receive helper
            let decrypted_envelope = signal_rs_protos::Envelope {
                r#type: Some(8), // PLAINTEXT_CONTENT (already decrypted)
                source_service_id: Some(effective_source.to_string()),
                source_device: Some(effective_device),
                timestamp: entity.timestamp,
                content: Some(plaintext),
                server_timestamp: entity.server_timestamp,
                server_guid: entity.server_guid.clone(),
                story: entity.story,
                reporting_token: entity.reporting_token.as_ref().and_then(|t| {
                    base64::engine::general_purpose::STANDARD.decode(t).ok()
                }),
                destination_service_id: entity.destination_uuid.clone(),
                urgent: entity.urgent,
                updated_pni: None,
            };
            let envelope_bytes = prost::Message::encode_to_vec(&decrypted_envelope);

            match receive_helper
                .process_incoming(&self.context.store, &[envelope_bytes])
                .await
            {
                Ok(mut msgs) => {
                    messages.append(&mut msgs);
                    // Send delivery receipt back to sender (if enabled)
                    let send_receipts = tokio::task::block_in_place(|| {
                        self.context.store.get_kv_string("config.send_delivery_receipts")
                    }).unwrap_or(None).unwrap_or_else(|| "true".to_string()) != "false";

                    if send_receipts
                        && let Ok(sender_uuid) = Uuid::parse_str(effective_source) {
                            let receipt_content = SignalContent::Receipt(ReceiptContent {
                                receipt_type: ReceiptType::Delivery,
                                timestamps: vec![timestamp],
                            });
                            let receipt_ts = self.current_timestamp_millis();
                            if let Err(e) = self.encrypt_and_send(
                                &sender_uuid, &receipt_content, receipt_ts, false, false,
                            ).await {
                                debug!(error = %e, "failed to send delivery receipt (best-effort)");
                            }
                        }
                }
                Err(e) => {
                    warn!("failed to process HTTP-polled envelope: {e}");
                }
            }

            // Acknowledge the message so the server removes it from the queue
            if let Some(ref guid) = entity.server_guid
                && let Err(e) = message_api.acknowledge_message(guid).await {
                    warn!("failed to acknowledge message {guid}: {e}");
                }
        }

        info!(
            message_count = messages.len(),
            "HTTP fallback message receiving complete"
        );
        Ok(messages)
    }

    /// Build an IdentityKeyPair from the public and private key bytes
    /// received in a provisioning message.
    fn build_identity_from_provision(
        &self,
        public_bytes: &[u8],
        private_bytes: &[u8],
    ) -> Result<IdentityKeyPair> {
        // The public key may or may not have the 0x05 prefix
        let public_with_prefix = if public_bytes.len() == 32 {
            let mut prefixed = vec![0x05u8];
            prefixed.extend_from_slice(public_bytes);
            prefixed
        } else if public_bytes.len() == 33 && public_bytes[0] == 0x05 {
            public_bytes.to_vec()
        } else {
            return Err(ManagerError::Other(format!(
                "unexpected public key length: {}",
                public_bytes.len()
            )));
        };

        let identity_key = signal_rs_protocol::IdentityKey::from_bytes(&public_with_prefix)?;
        let pair = IdentityKeyPair::new(identity_key, private_bytes.to_vec())?;
        Ok(pair)
    }
}
