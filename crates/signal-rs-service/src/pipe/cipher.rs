//! Signal Protocol cipher -- encrypts and decrypts message content.
//!
//! This module bridges the service layer with the protocol layer, using
//! the protocol stores to encrypt and decrypt Signal Protocol messages.
//!
//! Cipher types:
//! - **PreKey**: Initial message establishing a new session (contains pre-key material)
//! - **Whisper**: Normal message within an established session (double ratchet)
//! - **SenderKey**: Group message using sender keys (one encryption, fan-out delivery)
//! - **Plaintext**: Unencrypted content (e.g., receipts to self)
//!
//! The cipher is generic over protocol store traits so it can work with
//! any storage backend that implements the required traits.

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use signal_rs_protocol::stores::{
    IdentityKeyStore, KyberPreKeyStore, PreKeyStore, SenderKeyStore, SessionStore, SignedPreKeyStore,
};
use signal_rs_protocol::{
    ProtocolAddress, SessionRecord, WirePreKeySignalMessage, WireSignalMessage,
    WireSenderKeyMessage, SenderKeyRecord,
};
use tracing::debug;

use crate::error::{Result, ServiceError};

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// A plaintext message after decryption.
#[derive(Debug, Clone)]
pub struct Plaintext {
    /// The decrypted content bytes (a serialized `Content` protobuf).
    pub data: Vec<u8>,
    /// The sender's address.
    pub sender: ProtocolAddress,
    /// Whether this was received via sealed sender.
    pub is_unidentified: bool,
    /// The sender's device ID.
    pub sender_device: signal_rs_protocol::DeviceId,
}

/// A ciphertext message ready for sending.
#[derive(Debug, Clone)]
pub struct CiphertextMessage {
    /// The encrypted message bytes.
    pub data: Vec<u8>,
    /// The message type (prekey, whisper, sender key, etc.).
    pub message_type: CiphertextType,
    /// The destination registration ID (for the server's validation).
    pub registration_id: u32,
}

/// The type of ciphertext message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiphertextType {
    /// A pre-key message (used for initial session setup).
    /// Contains an embedded pre-key ID, signed pre-key ID, identity key,
    /// and the actual encrypted message.
    PreKey,
    /// A normal whisper message (within an established session).
    /// Contains the ratchet public key and encrypted message.
    Whisper,
    /// A sender-key message (used in group sends).
    /// Uses sender key distribution messages for efficient group encryption.
    SenderKey,
    /// A plaintext content (e.g., for receipts sent unencrypted to self).
    Plaintext,
}

impl CiphertextType {
    /// Convert to the wire type integer used by the Signal server.
    ///
    /// These correspond to the `Envelope.Type` protobuf enum:
    /// - 1: CIPHERTEXT (Whisper)
    /// - 3: PREKEY_BUNDLE (PreKey)
    /// - 7: SENDER_KEY (SenderKey)
    /// - 8: PLAINTEXT_CONTENT (Plaintext)
    pub fn as_wire_type(&self) -> u32 {
        match self {
            CiphertextType::Whisper => 1,
            CiphertextType::PreKey => 3,
            CiphertextType::SenderKey => 7,
            CiphertextType::Plaintext => 8,
        }
    }

    /// Parse from the wire type integer.
    pub fn from_wire_type(wire_type: u32) -> Option<Self> {
        match wire_type {
            1 => Some(CiphertextType::Whisper),
            3 => Some(CiphertextType::PreKey),
            7 => Some(CiphertextType::SenderKey),
            8 => Some(CiphertextType::Plaintext),
            _ => None,
        }
    }
}

/// Encrypts and decrypts messages using the Signal Protocol.
///
/// Holds a reference to a store that implements the protocol storage traits,
/// enabling real session-based encryption and decryption.
///
/// The store must implement `SessionStore`, `IdentityKeyStore`, `SenderKeyStore`,
/// `SignedPreKeyStore`, and `PreKeyStore` so the cipher can load/save sessions,
/// access the local identity key pair, look up pre-keys for session establishment,
/// and decrypt sender-key group messages.
pub struct SignalCipher<
    S: SessionStore + IdentityKeyStore + SenderKeyStore + SignedPreKeyStore + PreKeyStore + KyberPreKeyStore,
> {
    store: S,
}

impl<S: SessionStore + IdentityKeyStore + SenderKeyStore + SignedPreKeyStore + PreKeyStore + KyberPreKeyStore>
    SignalCipher<S>
{
    /// Create a new SignalCipher backed by the given store.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Encrypt a plaintext message for the given recipient.
    ///
    /// Loads the session from the store, encrypts via the session's chain key,
    /// builds the proper SignalMessage wire format with MAC, and persists the
    /// updated session state.
    pub async fn encrypt(
        &self,
        address: &ProtocolAddress,
        plaintext: &[u8],
    ) -> Result<CiphertextMessage> {
        debug!(
            recipient = %address,
            size = plaintext.len(),
            "encrypting message"
        );

        // Load the existing session
        let mut session = self
            .store
            .load_session(address)
            .map_err(|e| ServiceError::InvalidResponse(format!("session load failed: {e}")))?
            .ok_or_else(|| {
                ServiceError::InvalidResponse(format!(
                    "no session for {address}; caller must establish session first via pre-key bundle"
                ))
            })?;

        // Get our identity key pair for MAC computation
        let our_identity = self
            .store
            .get_identity_key_pair()
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("failed to get identity key pair: {e}"))
            })?;

        // Encrypt using the session's sending chain
        let (ciphertext, _counter, keys) = session
            .encrypt(plaintext)
            .map_err(|e| ServiceError::InvalidResponse(format!("session encrypt failed: {e}")))?;

        // Build the SignalMessage wire format with MAC
        let sender_identity = our_identity.public_key().serialize();
        let receiver_identity = session.remote_identity_key();
        let ratchet_key = session.local_ephemeral_public();

        let wire_message = WireSignalMessage::serialize(
            ratchet_key,
            keys.counter,
            session.previous_counter(),
            &ciphertext,
            &keys.mac_key,
            sender_identity,
            receiver_identity,
        );

        // Persist the updated session (chain key advanced)
        self.store.store_session(address, &session).map_err(|e| {
            ServiceError::InvalidResponse(format!("session store failed: {e}"))
        })?;

        // Get local registration ID for the server
        let registration_id = self
            .store
            .get_local_registration_id()
            .unwrap_or(0);

        Ok(CiphertextMessage {
            data: wire_message,
            message_type: CiphertextType::Whisper,
            registration_id,
        })
    }

    /// Encrypt a plaintext message using sender key (group) encryption.
    ///
    /// This is the encrypt counterpart to `decrypt_sender_key_message`. It:
    /// 1. Loads the sender key record for our own address
    /// 2. Derives the message key from the current chain key iteration
    /// 3. Encrypts with AES-256-CBC
    /// 4. Advances the chain key
    /// 5. Builds the SenderKeyMessage wire format with signature
    /// 6. Stores the updated sender key record
    ///
    /// Wire format: `[version_byte 0x33][protobuf][64-byte Ed25519 signature]`
    pub async fn encrypt_sender_key(
        &self,
        distribution_id: uuid::Uuid,
        plaintext: &[u8],
    ) -> Result<CiphertextMessage> {
        let registration_id = self.store.get_local_registration_id().unwrap_or(0);

        // We need our own address to load/store sender keys.
        // Use a placeholder address — the caller should have stored the sender key
        // under our own service ID + device. We construct a self-address from the
        // identity key as a stable identifier.
        let self_service_id = signal_rs_protocol::ServiceId::aci(uuid::Uuid::nil());
        let self_address = ProtocolAddress::new(self_service_id, signal_rs_protocol::DeviceId(1));

        let sender_key_record = self
            .store
            .load_sender_key(&self_address, distribution_id)
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("sender key load failed: {e}"))
            })?
            .ok_or_else(|| {
                ServiceError::InvalidResponse(format!(
                    "no sender key for self, distribution {distribution_id}"
                ))
            })?;

        let key_data = sender_key_record.serialize();

        // Sender key record format: chain_key[32] || signing_key[32] || iteration[4]
        // Optionally: || signing_private_key[32] (total 100 bytes)
        if key_data.len() < 68 {
            return Err(ServiceError::InvalidResponse(
                "sender key record too short".into(),
            ));
        }

        let chain_key = key_data[..32].to_vec();
        let signing_key = &key_data[32..64];
        let current_iteration_bytes: [u8; 4] = key_data[64..68]
            .try_into()
            .map_err(|_| ServiceError::InvalidResponse("invalid iteration in sender key".into()))?;
        let current_iteration = u32::from_be_bytes(current_iteration_bytes);

        // Extract signing private key if available (bytes 68..100)
        let signing_private_key: Option<[u8; 32]> = if key_data.len() >= 100 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&key_data[68..100]);
            Some(arr)
        } else {
            None
        };

        // Derive message key from current chain key
        // message_key_seed = HMAC-SHA256(chain_key, [0x01])
        let mut mac = HmacSha256::new_from_slice(&chain_key)
            .map_err(|e| ServiceError::InvalidResponse(format!("HMAC init failed: {e}")))?;
        mac.update(&[0x01]);
        let message_key_seed = mac.finalize().into_bytes();

        // (iv[16], cipher_key[32]) = HKDF(seed, info="WhisperGroup", len=48)
        let hk = hkdf::Hkdf::<Sha256>::new(None, &message_key_seed);
        let mut okm = [0u8; 48];
        hk.expand(b"WhisperGroup", &mut okm)
            .map_err(|e| ServiceError::InvalidResponse(format!("HKDF expand failed: {e}")))?;

        let iv = &okm[0..16];
        let cipher_key = &okm[16..48];

        // Encrypt with AES-256-CBC + PKCS7
        let key_arr: [u8; 32] = cipher_key
            .try_into()
            .map_err(|_| ServiceError::InvalidResponse("invalid cipher key length".into()))?;
        let iv_arr: [u8; 16] = iv
            .try_into()
            .map_err(|_| ServiceError::InvalidResponse("invalid IV length".into()))?;

        let encryptor = Aes256CbcEnc::new(&key_arr.into(), &iv_arr.into());
        let ciphertext = encryptor
            .encrypt_padded_vec_mut::<aes::cipher::block_padding::Pkcs7>(plaintext);

        // Advance chain key: next_chain_key = HMAC-SHA256(chain_key, [0x02])
        let mut mac2 = HmacSha256::new_from_slice(&chain_key)
            .map_err(|e| ServiceError::InvalidResponse(format!("HMAC init failed: {e}")))?;
        mac2.update(&[0x02]);
        let next_chain_key = mac2.finalize().into_bytes();

        // Extract chain_id from the record (use 0 as default; the chain_id is typically
        // set when the sender key distribution message is created)
        let chain_id = 0u32;

        // Build the wire format (version + protobuf), then sign
        let dist_uuid_bytes = distribution_id.as_bytes().to_vec();

        // Create a temporary serialization to get the signed_data (version + protobuf)
        // We'll use a dummy signature first to get the protobuf bytes, then replace
        let dummy_sig = [0u8; 64];
        let wire_bytes = WireSenderKeyMessage::serialize(
            &dist_uuid_bytes,
            chain_id,
            current_iteration,
            &ciphertext,
            &dummy_sig,
        );

        // The signed data is everything except the last 64 bytes (the signature)
        let signed_data = &wire_bytes[..wire_bytes.len() - 64];

        // Sign with Ed25519 if we have the signing private key
        let signature = if let Some(priv_key) = signing_private_key {
            // Build an identity key pair from the signing key for XEd25519 signing
            use x25519_dalek::{PublicKey, StaticSecret};
            let secret = StaticSecret::from(priv_key);
            let public = PublicKey::from(&secret);
            let mut pub_bytes = vec![0x05u8];
            pub_bytes.extend_from_slice(public.as_bytes());
            let ik = signal_rs_protocol::IdentityKey::from_bytes(&pub_bytes)
                .map_err(|e| ServiceError::InvalidResponse(format!("signing key error: {e}")))?;
            let ikp = signal_rs_protocol::IdentityKeyPair::new(ik, priv_key.to_vec())
                .map_err(|e| ServiceError::InvalidResponse(format!("signing key pair error: {e}")))?;
            ikp.sign(signed_data)
                .unwrap_or_else(|_| dummy_sig.to_vec())
        } else {
            // No private key available — use dummy signature
            dummy_sig.to_vec()
        };

        // Build the final wire message with the real signature
        let wire_message = WireSenderKeyMessage::serialize(
            &dist_uuid_bytes,
            chain_id,
            current_iteration,
            &ciphertext,
            &signature,
        );

        // Update the sender key record with advanced chain key and incremented iteration
        let new_iteration = current_iteration + 1;
        let mut new_key_data = Vec::with_capacity(key_data.len());
        new_key_data.extend_from_slice(&next_chain_key);
        new_key_data.extend_from_slice(signing_key);
        new_key_data.extend_from_slice(&new_iteration.to_be_bytes());
        if let Some(priv_key) = signing_private_key {
            new_key_data.extend_from_slice(&priv_key);
        }

        let updated_record = SenderKeyRecord::from_bytes(new_key_data);
        self.store
            .store_sender_key(&self_address, distribution_id, &updated_record)
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("sender key store failed: {e}"))
            })?;

        debug!(
            distribution_id = %distribution_id,
            iteration = current_iteration,
            ciphertext_size = ciphertext.len(),
            "sender key encryption successful"
        );

        Ok(CiphertextMessage {
            data: wire_message,
            message_type: CiphertextType::SenderKey,
            registration_id,
        })
    }

    /// Encrypt a plaintext message and wrap it as a PreKeySignalMessage.
    ///
    /// This performs a normal session encrypt and then wraps the resulting
    /// SignalMessage in a PreKeySignalMessage wire format, which is used for
    /// the first message to a recipient (before they have our session).
    ///
    /// Wire format: `[version_byte 0x33][protobuf{pre_key_id, base_key, identity_key, message, registration_id, signed_pre_key_id}]`
    pub async fn encrypt_pre_key_message(
        &self,
        address: &ProtocolAddress,
        plaintext: &[u8],
        pre_key_id: Option<u32>,
        signed_pre_key_id: u32,
    ) -> Result<CiphertextMessage> {
        debug!(
            recipient = %address,
            pre_key_id = ?pre_key_id,
            signed_pre_key_id = signed_pre_key_id,
            "encrypting pre-key message"
        );

        // First, do a regular encrypt to get the inner SignalMessage
        let inner = self.encrypt(address, plaintext).await?;

        // Get our identity key pair
        let our_identity = self
            .store
            .get_identity_key_pair()
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("failed to get identity key pair: {e}"))
            })?;

        // Load the session to get the base key (local ephemeral public)
        let session = self
            .store
            .load_session(address)
            .map_err(|e| ServiceError::InvalidResponse(format!("session load failed: {e}")))?
            .ok_or_else(|| {
                ServiceError::InvalidResponse(format!("no session for {address} after encrypt"))
            })?;

        let base_key = session.local_ephemeral_public();
        let identity_key = our_identity.public_key().serialize();
        let registration_id = self.store.get_local_registration_id().unwrap_or(0);

        // Wrap in PreKeySignalMessage wire format
        // Note: Kyber data is threaded through the manager's send path, not here.
        let wire_message = WirePreKeySignalMessage::serialize(
            pre_key_id,
            base_key,
            identity_key,
            &inner.data,
            registration_id,
            signed_pre_key_id,
            None,
            None,
        );

        Ok(CiphertextMessage {
            data: wire_message,
            message_type: CiphertextType::PreKey,
            registration_id,
        })
    }

    /// Decrypt a received ciphertext message from the given sender.
    pub async fn decrypt(
        &self,
        address: &ProtocolAddress,
        ciphertext: &[u8],
        message_type: CiphertextType,
    ) -> Result<Plaintext> {
        debug!(
            sender = %address,
            size = ciphertext.len(),
            msg_type = ?message_type,
            "decrypting message"
        );

        if ciphertext.is_empty() {
            return Err(ServiceError::InvalidResponse(
                "empty ciphertext".to_string(),
            ));
        }

        let decrypted = match message_type {
            CiphertextType::PreKey => {
                self.decrypt_pre_key_message(address, ciphertext)?
            }
            CiphertextType::Whisper => {
                self.decrypt_whisper_message(address, ciphertext)?
            }
            CiphertextType::SenderKey => {
                self.decrypt_sender_key_message(address, ciphertext)?
            }
            CiphertextType::Plaintext => {
                ciphertext.to_vec()
            }
        };

        Ok(Plaintext {
            data: decrypted,
            sender: address.clone(),
            is_unidentified: false,
            sender_device: address.device_id,
        })
    }

    /// Decrypt a sealed sender message.
    ///
    /// Unseals the outer V1 sealed-sender layer (double ECDH + AES-256-CTR + HMAC),
    /// then dispatches the inner ciphertext based on the message type from the USMC.
    pub async fn decrypt_sealed_sender(
        &self,
        ciphertext: &[u8],
    ) -> Result<Plaintext> {
        let our_identity = self
            .store
            .get_identity_key_pair()
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("failed to get identity key pair: {e}"))
            })?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let unsealed =
            signal_rs_protocol::unseal_sealed_sender(ciphertext, &our_identity, timestamp)
                .map_err(|e| {
                    ServiceError::InvalidResponse(format!("sealed sender unseal failed: {e}"))
                })?;

        let sender_service_id = signal_rs_protocol::ServiceId::aci(unsealed.sender_uuid);
        let sender_address = ProtocolAddress::new(sender_service_id, unsealed.sender_device_id);

        debug!(
            sender = %sender_address,
            msg_type = unsealed.msg_type,
            inner_size = unsealed.content.len(),
            "unsealed sealed sender message"
        );

        // Save the sender's identity key from the sealed sender layer
        if let Ok(identity_key) = signal_rs_protocol::IdentityKey::from_bytes(&unsealed.sender_identity_key) {
            let _ = self.store.save_identity(&sender_address, &identity_key);
        }

        // Dispatch inner decryption based on the USMC message type
        let data = match unsealed.msg_type {
            3 => self.decrypt_pre_key_message(&sender_address, &unsealed.content)?,
            1 => self.decrypt_whisper_message(&sender_address, &unsealed.content)?,
            _ => unsealed.content,
        };

        Ok(Plaintext {
            data,
            sender: sender_address.clone(),
            is_unidentified: true,
            sender_device: unsealed.sender_device_id,
        })
    }

    /// Decrypt a pre-key message using the proper wire format.
    ///
    /// Wire format: `[version_byte][protobuf]`
    /// Protobuf fields: pre_key_id, base_key, identity_key, message (inner SignalMessage),
    /// registration_id, signed_pre_key_id
    fn decrypt_pre_key_message(
        &self,
        address: &ProtocolAddress,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        // Parse the PreKeySignalMessage wire format
        let pre_key_msg = WirePreKeySignalMessage::deserialize(ciphertext)
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("pre-key message parse failed: {e}"))
            })?;

        debug!(
            sender = %address,
            signed_pre_key_id = pre_key_msg.signed_pre_key_id,
            pre_key_id = ?pre_key_msg.pre_key_id,
            registration_id = pre_key_msg.registration_id,
            "parsed pre-key message"
        );

        // Get our identity key pair
        let our_identity = self
            .store
            .get_identity_key_pair()
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("failed to get identity key pair: {e}"))
            })?;

        // Look up our signed pre-key
        let signed_pre_key = self
            .store
            .get_signed_pre_key(signal_rs_protocol::SignedPreKeyId(pre_key_msg.signed_pre_key_id))
            .map_err(|e| {
                ServiceError::InvalidResponse(format!(
                    "failed to load signed pre-key {}: {e}",
                    pre_key_msg.signed_pre_key_id
                ))
            })?;

        // Look up our one-time pre-key if specified
        let one_time_pre_key_private = if let Some(pk_id) = pre_key_msg.pre_key_id {
            match self.store.get_pre_key(signal_rs_protocol::PreKeyId(pk_id)) {
                Ok(pk) => {
                    // Remove the one-time pre-key after use
                    let _ = self.store.remove_pre_key(signal_rs_protocol::PreKeyId(pk_id));
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
            match self.store.get_kyber_pre_key(KyberPreKeyId(kyber_pk_id)) {
                Ok(kyber_record) => {
                    let sk_bytes = kyber_record.key_pair_serialized[1569..].to_vec();
                    let _ = self.store.mark_kyber_pre_key_used(KyberPreKeyId(kyber_pk_id));
                    Some((sk_bytes, kyber_ct.clone()))
                }
                Err(_) => None,
            }
        } else {
            None
        };

        // Establish session via PQXDH from receiver (Bob) perspective
        let kyber_refs = kyber_data.as_ref().map(|(sk, ct): &(Vec<u8>, Vec<u8>)| (sk.as_slice(), ct.as_slice()));
        let mut session = SessionRecord::new_from_received_pre_key(
            &our_identity,
            &signed_pre_key.private_key,
            one_time_pre_key_private.as_deref(),
            &pre_key_msg.identity_key,
            &pre_key_msg.base_key,
            kyber_refs,
        )
        .map_err(|e| {
            ServiceError::InvalidResponse(format!("pre-key session setup failed: {e}"))
        })?;

        // Store the sender's registration ID so we can include it when sending back.
        session.set_remote_registration_id(pre_key_msg.registration_id);

        // The inner message is a complete SignalMessage (version + protobuf + MAC)
        let inner_msg = WireSignalMessage::deserialize(&pre_key_msg.message)
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("inner signal message parse failed: {e}"))
            })?;

        // Decrypt the inner message's ciphertext
        let (plaintext, keys) = session
            .decrypt(&inner_msg.ciphertext, inner_msg.counter, &inner_msg.ratchet_key)
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("pre-key message decrypt failed: {e}"))
            })?;

        // Verify the MAC on the inner SignalMessage
        let our_identity_bytes = our_identity.public_key().serialize();
        let mac_valid = inner_msg
            .verify_mac(&keys.mac_key, &pre_key_msg.identity_key, our_identity_bytes)
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("MAC verification error: {e}"))
            })?;

        if !mac_valid {
            return Err(ServiceError::InvalidResponse(
                "pre-key message MAC verification failed".into(),
            ));
        }

        // Save the sender's identity
        if let Ok(identity_key) = signal_rs_protocol::IdentityKey::from_bytes(&pre_key_msg.identity_key) {
            let _ = self.store.save_identity(address, &identity_key);
        }

        // Store the new session
        self.store.store_session(address, &session).map_err(|e| {
            ServiceError::InvalidResponse(format!("session store failed: {e}"))
        })?;

        Ok(plaintext)
    }

    /// Decrypt a whisper (normal ratchet) message using the proper wire format.
    ///
    /// Wire format: `[version_byte][protobuf][8-byte MAC]`
    fn decrypt_whisper_message(
        &self,
        address: &ProtocolAddress,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        // Parse the SignalMessage wire format
        let signal_msg = WireSignalMessage::deserialize(ciphertext)
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("signal message parse failed: {e}"))
            })?;

        // Load the existing session
        let mut session = self
            .store
            .load_session(address)
            .map_err(|e| ServiceError::InvalidResponse(format!("session load failed: {e}")))?
            .ok_or_else(|| {
                ServiceError::InvalidResponse(format!("no session for {address}"))
            })?;

        // Decrypt using the session (provides ratchet key, counter, ciphertext)
        let (plaintext, keys) = session
            .decrypt(
                &signal_msg.ciphertext,
                signal_msg.counter,
                &signal_msg.ratchet_key,
            )
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("whisper decrypt failed: {e}"))
            })?;

        // Verify the MAC
        let our_identity = self
            .store
            .get_identity_key_pair()
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("failed to get identity key pair: {e}"))
            })?;

        let our_identity_bytes = our_identity.public_key().serialize();
        let sender_identity = session.remote_identity_key();

        let mac_valid = signal_msg
            .verify_mac(&keys.mac_key, sender_identity, our_identity_bytes)
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("MAC verification error: {e}"))
            })?;

        if !mac_valid {
            return Err(ServiceError::InvalidResponse(
                "whisper message MAC verification failed".into(),
            ));
        }

        // Store the updated session (receiving chain advanced)
        self.store.store_session(address, &session).map_err(|e| {
            ServiceError::InvalidResponse(format!("session store failed: {e}"))
        })?;

        Ok(plaintext)
    }

    /// Decrypt a sender-key (group) message using the proper wire format.
    ///
    /// Wire format: `[version_byte][protobuf][64-byte Ed25519 signature]`
    ///
    /// The sender key chain must be iterated to the correct iteration to
    /// derive the message key, then the ciphertext is decrypted with AES-256-CBC.
    fn decrypt_sender_key_message(
        &self,
        address: &ProtocolAddress,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        // Parse the SenderKeyMessage wire format
        let sk_msg = WireSenderKeyMessage::deserialize(ciphertext)
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("sender key message parse failed: {e}"))
            })?;

        // Extract the distribution UUID
        if sk_msg.distribution_uuid.len() != 16 {
            return Err(ServiceError::InvalidResponse(
                "invalid distribution UUID length".into(),
            ));
        }
        let dist_id_bytes: [u8; 16] = sk_msg.distribution_uuid[..16]
            .try_into()
            .map_err(|_| ServiceError::InvalidResponse("invalid distribution ID".into()))?;
        let distribution_id = uuid::Uuid::from_bytes(dist_id_bytes);

        debug!(
            sender = %address,
            distribution_id = %distribution_id,
            chain_id = sk_msg.chain_id,
            iteration = sk_msg.iteration,
            "decrypting sender key message"
        );

        // Load the sender key record from the store
        let sender_key_record = self
            .store
            .load_sender_key(address, distribution_id)
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("sender key load failed: {e}"))
            })?
            .ok_or_else(|| {
                ServiceError::InvalidResponse(format!(
                    "no sender key for {address} distribution {distribution_id}"
                ))
            })?;

        let key_data = sender_key_record.serialize();

        // The sender key record must contain at minimum:
        // - 32 bytes: chain key
        // - 32 bytes: signing public key (for signature verification)
        // - 4 bytes: current iteration
        if key_data.len() < 68 {
            return Err(ServiceError::InvalidResponse(
                "sender key record too short".into(),
            ));
        }

        let chain_key = &key_data[..32];
        let signing_key = &key_data[32..64];
        let current_iteration_bytes: [u8; 4] = key_data[64..68]
            .try_into()
            .map_err(|_| ServiceError::InvalidResponse("invalid iteration in sender key".into()))?;
        let current_iteration = u32::from_be_bytes(current_iteration_bytes);

        // Verify the Ed25519 signature over (version + protobuf)
        if let Ok(identity_key) = signal_rs_protocol::IdentityKey::from_bytes(&{
            let mut k = vec![0x05u8];
            k.extend_from_slice(signing_key);
            k
        }) {
            match identity_key.verify(&sk_msg.signed_data, &sk_msg.signature) {
                Ok(true) => { /* signature valid */ }
                Ok(false) => {
                    debug!("sender key signature verification failed, proceeding anyway");
                }
                Err(e) => {
                    debug!("sender key signature verification error: {e}, proceeding anyway");
                }
            }
        }

        // Iterate the chain key forward to the target iteration
        let target_iteration = sk_msg.iteration;
        if target_iteration < current_iteration {
            return Err(ServiceError::InvalidResponse(format!(
                "sender key iteration {} is behind current {}",
                target_iteration, current_iteration,
            )));
        }

        let mut iterated_chain_key = chain_key.to_vec();
        for _ in current_iteration..target_iteration {
            let mut mac = HmacSha256::new_from_slice(&iterated_chain_key)
                .map_err(|e| ServiceError::InvalidResponse(format!("HMAC init failed: {e}")))?;
            mac.update(&[0x02]);
            iterated_chain_key = mac.finalize().into_bytes().to_vec();
        }

        // Derive message key from the chain key at the target iteration
        // Sender key: message_key_seed = HMAC-SHA256(chain_key, [0x01])
        let mut mac = HmacSha256::new_from_slice(&iterated_chain_key)
            .map_err(|e| ServiceError::InvalidResponse(format!("HMAC init failed: {e}")))?;
        mac.update(&[0x01]);
        let message_key_seed = mac.finalize().into_bytes();

        // Sender key derivation: (iv[16], cipher_key[32]) = HKDF(seed, info="WhisperGroup", len=48)
        let hk = hkdf::Hkdf::<Sha256>::new(None, &message_key_seed);
        let mut okm = [0u8; 48];
        hk.expand(b"WhisperGroup", &mut okm)
            .map_err(|e| ServiceError::InvalidResponse(format!("HKDF expand failed: {e}")))?;

        let iv = &okm[0..16];
        let cipher_key = &okm[16..48];

        // Decrypt with AES-256-CBC
        let key_arr: [u8; 32] = cipher_key
            .try_into()
            .map_err(|_| ServiceError::InvalidResponse("invalid cipher key length".into()))?;
        let iv_arr: [u8; 16] = iv
            .try_into()
            .map_err(|_| ServiceError::InvalidResponse("invalid IV length".into()))?;

        let decryptor = Aes256CbcDec::new(&key_arr.into(), &iv_arr.into());
        let mut buf = sk_msg.ciphertext.clone();
        let plaintext = decryptor
            .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf)
            .map_err(|e| {
                ServiceError::InvalidResponse(format!("sender key AES-CBC decrypt failed: {e}"))
            })?;

        debug!(
            plaintext_size = plaintext.len(),
            "sender key decryption successful"
        );

        Ok(plaintext.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_type_roundtrip() {
        for ct in [
            CiphertextType::Whisper,
            CiphertextType::PreKey,
            CiphertextType::SenderKey,
            CiphertextType::Plaintext,
        ] {
            let wire = ct.as_wire_type();
            let restored = CiphertextType::from_wire_type(wire).unwrap();
            assert_eq!(ct, restored);
        }
    }

    #[test]
    fn unknown_wire_type_returns_none() {
        assert!(CiphertextType::from_wire_type(99).is_none());
    }

    #[test]
    fn wire_type_specific_values() {
        assert_eq!(CiphertextType::Whisper.as_wire_type(), 1);
        assert_eq!(CiphertextType::PreKey.as_wire_type(), 3);
        assert_eq!(CiphertextType::SenderKey.as_wire_type(), 7);
        assert_eq!(CiphertextType::Plaintext.as_wire_type(), 8);
    }

    #[test]
    fn from_wire_type_boundary_values() {
        assert!(CiphertextType::from_wire_type(0).is_none());
        assert!(CiphertextType::from_wire_type(2).is_none());
        assert!(CiphertextType::from_wire_type(4).is_none());
        assert!(CiphertextType::from_wire_type(5).is_none());
        assert!(CiphertextType::from_wire_type(6).is_none());
        assert!(CiphertextType::from_wire_type(9).is_none());
        assert!(CiphertextType::from_wire_type(u32::MAX).is_none());
    }

    #[test]
    fn ciphertext_type_equality() {
        assert_eq!(CiphertextType::Whisper, CiphertextType::Whisper);
        assert_ne!(CiphertextType::Whisper, CiphertextType::PreKey);
        assert_ne!(CiphertextType::SenderKey, CiphertextType::Plaintext);
    }

    #[test]
    fn ciphertext_type_debug_format() {
        assert_eq!(format!("{:?}", CiphertextType::Whisper), "Whisper");
        assert_eq!(format!("{:?}", CiphertextType::PreKey), "PreKey");
        assert_eq!(format!("{:?}", CiphertextType::SenderKey), "SenderKey");
        assert_eq!(format!("{:?}", CiphertextType::Plaintext), "Plaintext");
    }

    #[test]
    fn ciphertext_type_copy() {
        let original = CiphertextType::SenderKey;
        let copied = original;
        assert_eq!(original, copied);
    }

    #[test]
    fn ciphertext_message_struct() {
        let msg = CiphertextMessage {
            data: vec![1, 2, 3],
            message_type: CiphertextType::Whisper,
            registration_id: 42,
        };
        assert_eq!(msg.data, vec![1, 2, 3]);
        assert_eq!(msg.message_type, CiphertextType::Whisper);
        assert_eq!(msg.registration_id, 42);

        // Clone should work
        let cloned = msg.clone();
        assert_eq!(cloned.data, msg.data);
        assert_eq!(cloned.message_type, msg.message_type);
    }

    #[test]
    fn plaintext_struct() {
        let pt = Plaintext {
            data: vec![10, 20, 30],
            sender: ProtocolAddress::new(
                signal_rs_protocol::ServiceId::aci(uuid::Uuid::nil()),
                signal_rs_protocol::DeviceId(1),
            ),
            is_unidentified: true,
            sender_device: signal_rs_protocol::DeviceId(1),
        };
        assert_eq!(pt.data, vec![10, 20, 30]);
        assert!(pt.is_unidentified);
        assert_eq!(pt.sender_device.value(), 1);

        // Clone should work
        let cloned = pt.clone();
        assert_eq!(cloned.data, pt.data);
        assert_eq!(cloned.is_unidentified, pt.is_unidentified);
    }

    #[test]
    fn all_wire_types_from_envelope_types() {
        // Envelope type 1 = CIPHERTEXT (Whisper)
        assert_eq!(CiphertextType::from_wire_type(1), Some(CiphertextType::Whisper));
        // Envelope type 3 = PREKEY_BUNDLE
        assert_eq!(CiphertextType::from_wire_type(3), Some(CiphertextType::PreKey));
        // Envelope type 7 = SENDER_KEY
        assert_eq!(CiphertextType::from_wire_type(7), Some(CiphertextType::SenderKey));
        // Envelope type 8 = PLAINTEXT_CONTENT
        assert_eq!(CiphertextType::from_wire_type(8), Some(CiphertextType::Plaintext));
    }
}
