//! Session record types with double-ratchet session state.
//!
//! Implements X3DH key agreement for session establishment and the
//! Signal Protocol double-ratchet using HMAC-SHA256 chain key derivation
//! and AES-256-CBC encryption.

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::ProtocolError;
use crate::identity::IdentityKeyPair;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// The HKDF info string used when deriving the root key from X3DH.
/// Must match libsignal: "WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024"
const X3DH_INFO: &[u8] = b"WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024";

/// The HKDF info string used for ratchet step key derivation.
const WHISPER_RATCHET_INFO: &[u8] = b"WhisperRatchet";

/// The HKDF info string used for deriving message keys from seed.
const WHISPER_MESSAGE_KEYS_INFO: &[u8] = b"WhisperMessageKeys";

/// Maximum number of receiver chains to keep.
const MAX_RECEIVER_CHAINS: usize = 5;

/// Maximum number of skipped message keys to keep.
const MAX_SKIPPED_KEYS: usize = 1000;

/// Maximum gap in message counters we will skip ahead.
const MAX_MESSAGE_GAP: u32 = 2000;

/// Derived message keys for encryption/decryption and MAC computation.
#[derive(Debug, Clone)]
pub struct MessageKeys {
    /// 32-byte AES-256 cipher key.
    pub cipher_key: Vec<u8>,
    /// 32-byte HMAC-SHA256 MAC key.
    pub mac_key: Vec<u8>,
    /// 16-byte AES-CBC initialization vector.
    pub iv: Vec<u8>,
    /// The message counter for this set of keys.
    pub counter: u32,
}

/// A receiver chain entry tracking a remote ratchet key and its chain state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiverChain {
    /// The remote ratchet public key (33 bytes with 0x05 prefix).
    pub ratchet_key: Vec<u8>,
    /// The current chain key (32 bytes).
    pub chain_key: Vec<u8>,
    /// The current chain index (next expected message number).
    pub chain_index: u32,
}

/// A skipped message key for out-of-order delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedKey {
    /// The ratchet key this message was under (33 bytes with 0x05 prefix).
    pub ratchet_key: Vec<u8>,
    /// The message counter.
    pub counter: u32,
    /// The 32-byte cipher key.
    pub cipher_key: Vec<u8>,
    /// The 32-byte MAC key.
    pub mac_key: Vec<u8>,
    /// The 16-byte IV.
    pub iv: Vec<u8>,
}

/// A session record containing the double-ratchet state for communicating
/// with a specific remote device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    /// The remote identity public key bytes (33 bytes with 0x05 prefix).
    remote_identity_key: Vec<u8>,
    /// The root key (32 bytes).
    root_key: Vec<u8>,
    /// The sender chain key (32 bytes).
    sender_chain_key: Vec<u8>,
    /// The next sending message counter.
    sender_counter: u32,
    /// Our local ephemeral private key bytes (32 bytes).
    local_ephemeral_private: Vec<u8>,
    /// Our local ephemeral public key bytes (33 bytes with 0x05 prefix for wire format).
    local_ephemeral_public: Vec<u8>,
    /// Receiver chains (up to MAX_RECEIVER_CHAINS).
    receiver_chains: Vec<ReceiverChain>,
    /// The previous sending counter (before last ratchet step).
    previous_counter: u32,
    /// Skipped message keys for out-of-order delivery.
    skipped_keys: Vec<SkippedKey>,
    /// The base key (Alice's ephemeral) for PreKeySignalMessage.
    /// Only set during initial session creation, cleared after first message.
    #[serde(default)]
    base_key: Option<Vec<u8>>,
    /// The remote device's registration ID (from pre-key bundle or PreKeySignalMessage).
    /// Used in the API's `destination_registration_id` field so the server can verify
    /// we're targeting the correct device registration.
    #[serde(default)]
    remote_registration_id: u32,
}

impl SessionRecord {
    /// Create a new session record from serialized bytes (for store compatibility).
    pub fn from_bytes(data: Vec<u8>) -> Self {
        if let Ok(record) = serde_json::from_slice::<SessionRecord>(&data) {
            return record;
        }
        // Fallback: create a minimal record wrapping the raw data.
        Self {
            remote_identity_key: Vec::new(),
            root_key: data,
            sender_chain_key: vec![0u8; 32],
            sender_counter: 0,
            local_ephemeral_private: vec![0u8; 32],
            local_ephemeral_public: vec![0u8; 33],
            receiver_chains: Vec::new(),
            previous_counter: 0,
            skipped_keys: Vec::new(),
            base_key: None,
            remote_registration_id: 0,
        }
    }

    /// Return the serialized session data (backward compat: returns root_key).
    pub fn serialize(&self) -> &[u8] {
        &self.root_key
    }

    /// Serialize the full session state to a byte vector.
    pub fn serialize_to_vec(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Consume the record and return the serialized bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.serialize_to_vec()
    }

    /// Perform PQXDH key agreement from Alice's (initiator) perspective.
    ///
    /// # Arguments
    /// - `our_identity` - Our local identity key pair
    /// - `their_identity` - Their public identity key bytes (32 bytes, no prefix)
    /// - `their_signed_pre_key` - Their signed pre-key public bytes (32 bytes)
    /// - `their_one_time_pre_key` - Their optional one-time pre-key public bytes
    /// - `their_kyber_public_key` - Their optional Kyber1024 public key (1569 bytes with type prefix)
    ///
    /// Returns `(session, kyber_ciphertext)` where kyber_ciphertext is the KEM
    /// ciphertext to include in the PreKeySignalMessage (if Kyber key was provided).
    pub fn new_from_pre_key(
        our_identity: &IdentityKeyPair,
        their_identity: &[u8],
        their_signed_pre_key: &[u8],
        their_one_time_pre_key: Option<&[u8]>,
        their_kyber_public_key: Option<&[u8]>,
    ) -> Result<(Self, Option<Vec<u8>>), ProtocolError> {
        if their_identity.len() != 32 {
            return Err(ProtocolError::InvalidKey(format!(
                "their identity key must be 32 bytes, got {}",
                their_identity.len()
            )));
        }
        if their_signed_pre_key.len() != 32 {
            return Err(ProtocolError::InvalidKey(format!(
                "their signed pre-key must be 32 bytes, got {}",
                their_signed_pre_key.len()
            )));
        }

        let our_private_bytes: [u8; 32] = our_identity
            .private_key_bytes()
            .try_into()
            .map_err(|_| ProtocolError::InvalidKey("invalid private key length".into()))?;
        let our_ik_secret = StaticSecret::from(our_private_bytes);

        let their_ik_bytes: [u8; 32] = their_identity
            .try_into()
            .map_err(|_| ProtocolError::InvalidKey("invalid their identity key length".into()))?;
        let their_ik_public = PublicKey::from(their_ik_bytes);

        let their_spk_bytes: [u8; 32] = their_signed_pre_key
            .try_into()
            .map_err(|_| ProtocolError::InvalidKey("invalid their signed pre-key length".into()))?;
        let their_spk_public = PublicKey::from(their_spk_bytes);

        // Generate our ephemeral key pair (base key)
        let our_ephemeral_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let our_ephemeral_public = PublicKey::from(&our_ephemeral_secret);

        // X3DH shared secrets (must match libsignal exactly)
        let dh1 = our_ik_secret.diffie_hellman(&their_spk_public);
        let dh2 = our_ephemeral_secret.diffie_hellman(&their_ik_public);
        let dh3 = our_ephemeral_secret.diffie_hellman(&their_spk_public);

        // Prepend 32 bytes of 0xFF "discontinuity bytes" as required by the protocol
        let mut secrets = Vec::with_capacity(32 * 5);
        secrets.extend_from_slice(&[0xFFu8; 32]);
        secrets.extend_from_slice(dh1.as_bytes());
        secrets.extend_from_slice(dh2.as_bytes());
        secrets.extend_from_slice(dh3.as_bytes());

        if let Some(opk_bytes) = their_one_time_pre_key {
            if opk_bytes.len() != 32 {
                return Err(ProtocolError::InvalidKey(format!(
                    "their one-time pre-key must be 32 bytes, got {}",
                    opk_bytes.len()
                )));
            }
            let opk_arr: [u8; 32] = opk_bytes
                .try_into()
                .map_err(|_| ProtocolError::InvalidKey("invalid OPK length".into()))?;
            let their_opk_public = PublicKey::from(opk_arr);
            let dh4 = our_ephemeral_secret.diffie_hellman(&their_opk_public);
            secrets.extend_from_slice(dh4.as_bytes());
        }

        // PQXDH: Kyber KEM encapsulation (if Kyber public key provided)
        let kyber_ciphertext = if let Some(kyber_pub_bytes) = their_kyber_public_key {
            use libsignal_protocol::kem;
            let kyber_pub = kem::PublicKey::deserialize(kyber_pub_bytes)
                .map_err(|e| ProtocolError::InvalidKey(format!("invalid Kyber public key: {e}")))?;
            let (shared_secret, ciphertext) = kyber_pub.encapsulate(&mut rand_09::rng())
                .map_err(|e| ProtocolError::InvalidKey(format!("Kyber encapsulate failed: {e}")))?;
            secrets.extend_from_slice(&shared_secret);
            Some(ciphertext.to_vec())
        } else {
            None
        };

        // Derive root key and initial chain key (salt=None per libsignal)
        let hk = Hkdf::<Sha256>::new(None, &secrets);
        let mut okm = [0u8; 96];
        hk.expand(X3DH_INFO, &mut okm)
            .map_err(|e| ProtocolError::InvalidKey(format!("HKDF expand failed: {e}")))?;

        let initial_root_key = okm[0..32].to_vec();
        let initial_chain_key = okm[32..64].to_vec();
        // okm[64..96] is the PQR key (unused without Kyber support)

        // Build wire format keys
        let mut their_ik_wire = Vec::with_capacity(33);
        their_ik_wire.push(0x05);
        their_ik_wire.extend_from_slice(their_identity);

        let mut their_spk_wire = Vec::with_capacity(33);
        their_spk_wire.push(0x05);
        their_spk_wire.extend_from_slice(their_signed_pre_key);

        // The initial receiver chain uses their signed pre-key (ratchet key) + initial chain key
        let receiver_chain = ReceiverChain {
            ratchet_key: their_spk_wire,
            chain_key: initial_chain_key,
            chain_index: 0,
        };

        // Per libsignal: after X3DH, generate a NEW sending ratchet key pair
        // and perform a ratchet step to derive the sending chain.
        // This is critical: the base_key is NOT the sending ratchet key.
        let sending_ratchet_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let sending_ratchet_public = PublicKey::from(&sending_ratchet_secret);

        // DH ratchet: DH(new_sending_key, their_signed_pre_key) to get sending chain
        let sending_shared = sending_ratchet_secret.diffie_hellman(&their_spk_public);
        let (sending_root_key, sending_chain_key) =
            ratchet_derive(&initial_root_key, sending_shared.as_bytes())?;

        // Build wire format for our sending ratchet public key
        let mut sending_ratchet_pub_wire = Vec::with_capacity(33);
        sending_ratchet_pub_wire.push(0x05);
        sending_ratchet_pub_wire.extend_from_slice(sending_ratchet_public.as_bytes());

        // Store the base key (ephemeral) for PreKeySignalMessage
        let mut base_key_wire = Vec::with_capacity(33);
        base_key_wire.push(0x05);
        base_key_wire.extend_from_slice(our_ephemeral_public.as_bytes());

        Ok((Self {
            remote_identity_key: their_ik_wire,
            root_key: sending_root_key,
            sender_chain_key: sending_chain_key,
            sender_counter: 0,
            local_ephemeral_private: sending_ratchet_secret.to_bytes().to_vec(),
            local_ephemeral_public: sending_ratchet_pub_wire,
            receiver_chains: vec![receiver_chain],
            previous_counter: 0,
            skipped_keys: Vec::new(),
            base_key: Some(base_key_wire),
            remote_registration_id: 0,
        }, kyber_ciphertext))
    }

    /// Perform PQXDH from Bob's (receiver) perspective.
    ///
    /// This is used when receiving a PreKeySignalMessage: Bob uses his own
    /// signed pre-key (and optional one-time pre-key) with Alice's base key
    /// and identity key.
    ///
    /// `kyber_data` is `Some((our_kyber_secret_key_bytes, their_kyber_ciphertext))`
    /// when the sender included Kyber KEM material (PQXDH).
    pub fn new_from_received_pre_key(
        our_identity: &IdentityKeyPair,
        our_signed_pre_key_private: &[u8],
        our_one_time_pre_key_private: Option<&[u8]>,
        their_identity: &[u8],
        their_base_key: &[u8],
        kyber_data: Option<(&[u8], &[u8])>,
    ) -> Result<Self, ProtocolError> {
        // their_identity and their_base_key may be 32 or 33 bytes (with 0x05 prefix)
        let their_ik_raw = strip_key_prefix(their_identity)?;
        let their_base_raw = strip_key_prefix(their_base_key)?;

        if our_signed_pre_key_private.len() != 32 {
            return Err(ProtocolError::InvalidKey(format!(
                "signed pre-key private must be 32 bytes, got {}",
                our_signed_pre_key_private.len()
            )));
        }

        let our_private_bytes: [u8; 32] = our_identity
            .private_key_bytes()
            .try_into()
            .map_err(|_| ProtocolError::InvalidKey("invalid private key length".into()))?;
        let our_ik_secret = StaticSecret::from(our_private_bytes);

        let spk_private_bytes: [u8; 32] = our_signed_pre_key_private
            .try_into()
            .map_err(|_| ProtocolError::InvalidKey("invalid spk private length".into()))?;
        let our_spk_secret = StaticSecret::from(spk_private_bytes);

        let their_ik_bytes: [u8; 32] = their_ik_raw
            .try_into()
            .map_err(|_| ProtocolError::InvalidKey("invalid their identity key".into()))?;
        let their_ik_public = PublicKey::from(their_ik_bytes);

        let their_base_bytes: [u8; 32] = their_base_raw
            .try_into()
            .map_err(|_| ProtocolError::InvalidKey("invalid their base key".into()))?;
        let their_base_public = PublicKey::from(their_base_bytes);

        // X3DH from Bob's side (reverse DH order from Alice):
        // DH1 = DH(SPK_B, IK_A)
        let dh1 = our_spk_secret.diffie_hellman(&their_ik_public);
        // DH2 = DH(IK_B, EK_A)
        let dh2 = our_ik_secret.diffie_hellman(&their_base_public);
        // DH3 = DH(SPK_B, EK_A)
        let dh3 = our_spk_secret.diffie_hellman(&their_base_public);

        // Prepend 32 bytes of 0xFF "discontinuity bytes" as required by the protocol
        let mut secrets = Vec::with_capacity(32 * 5);
        secrets.extend_from_slice(&[0xFFu8; 32]);
        secrets.extend_from_slice(dh1.as_bytes());
        secrets.extend_from_slice(dh2.as_bytes());
        secrets.extend_from_slice(dh3.as_bytes());

        // DH4 = DH(OPK_B, EK_A) if available
        if let Some(opk_private) = our_one_time_pre_key_private {
            if opk_private.len() != 32 {
                return Err(ProtocolError::InvalidKey(format!(
                    "one-time pre-key private must be 32 bytes, got {}",
                    opk_private.len()
                )));
            }
            let opk_bytes: [u8; 32] = opk_private
                .try_into()
                .map_err(|_| ProtocolError::InvalidKey("invalid OPK private".into()))?;
            let our_opk_secret = StaticSecret::from(opk_bytes);
            let dh4 = our_opk_secret.diffie_hellman(&their_base_public);
            secrets.extend_from_slice(dh4.as_bytes());
        }

        // PQXDH: Kyber KEM decapsulation (if Kyber data provided)
        if let Some((kyber_sk_bytes, kyber_ct_bytes)) = kyber_data {
            use libsignal_protocol::kem;
            let kyber_sk = kem::SecretKey::deserialize(kyber_sk_bytes)
                .map_err(|e| ProtocolError::InvalidKey(format!("invalid Kyber secret key: {e}")))?;
            let ct_box: Box<[u8]> = kyber_ct_bytes.into();
            let shared_secret = kyber_sk.decapsulate(&ct_box)
                .map_err(|e| ProtocolError::InvalidKey(format!("Kyber decapsulation failed: {e}")))?;
            secrets.extend_from_slice(&shared_secret);
        }

        // Derive root key + chain key (salt=None per libsignal, same as Alice)
        let hk = Hkdf::<Sha256>::new(None, &secrets);
        let mut okm = [0u8; 96];
        hk.expand(X3DH_INFO, &mut okm)
            .map_err(|e| ProtocolError::InvalidKey(format!("HKDF expand failed: {e}")))?;

        let root_key = okm[0..32].to_vec();
        // Bob gets the same chain_key as Alice's initial_chain_key
        let initial_chain_key = okm[32..64].to_vec();
        // okm[64..96] is PQR key (unused without Kyber)

        // Our signed pre-key public (for the wire format)
        let our_spk_public = PublicKey::from(&our_spk_secret);
        let mut our_spk_pub_wire = Vec::with_capacity(33);
        our_spk_pub_wire.push(0x05);
        our_spk_pub_wire.extend_from_slice(our_spk_public.as_bytes());

        // Their identity in wire format
        let mut their_ik_wire = Vec::with_capacity(33);
        their_ik_wire.push(0x05);
        their_ik_wire.extend_from_slice(&their_ik_bytes);

        // Bob's session: no receiver chain yet (Alice's first message will contain
        // her sending ratchet key, which Bob will process via DH ratchet step).
        // The initial chain_key is stored with their_signed_pre_key as the ratchet key,
        // but on Bob's side we don't know Alice's sending ratchet key until we receive
        // her first message. We store the chain key with a placeholder.
        // Actually, per libsignal: Bob stores the initial chain_key as a receiver chain
        // keyed to Alice's sending ratchet key (from the message). But at session creation
        // time, Bob doesn't have it yet. So Bob's session starts with no chains.
        // The first message from Alice triggers the ratchet step.

        Ok(Self {
            remote_identity_key: their_ik_wire,
            root_key,
            sender_chain_key: initial_chain_key,
            sender_counter: 0,
            local_ephemeral_private: our_signed_pre_key_private.to_vec(),
            local_ephemeral_public: our_spk_pub_wire,
            receiver_chains: Vec::new(),
            previous_counter: 0,
            skipped_keys: Vec::new(),
            base_key: None,
            remote_registration_id: 0,
        })
    }

    /// Encrypt plaintext using the sending chain key.
    ///
    /// Returns `(ciphertext, counter, MessageKeys)` where the caller can use
    /// the MessageKeys to build the MAC and wire format.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, u32, MessageKeys), ProtocolError> {
        let counter = self.sender_counter;

        // Derive message keys and advance the chain
        let (msg_key_seed, next_chain_key) = derive_chain_keys(&self.sender_chain_key)?;
        let keys = derive_message_keys(&msg_key_seed, counter)?;

        // Encrypt with AES-256-CBC + PKCS7
        let ciphertext = aes_cbc_encrypt(&keys.cipher_key, &keys.iv, plaintext)?;

        // Advance the chain
        self.sender_chain_key = next_chain_key;
        self.sender_counter = counter + 1;

        Ok((ciphertext, counter, keys))
    }

    /// Decrypt ciphertext from a received SignalMessage.
    ///
    /// # Arguments
    /// - `ciphertext` - The AES-256-CBC encrypted payload
    /// - `counter` - The message counter from the wire message
    /// - `sender_ratchet_key` - The sender's ratchet public key (33 bytes with 0x05 prefix)
    ///
    /// # Returns
    /// `(plaintext, MessageKeys)` on success.
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        counter: u32,
        sender_ratchet_key: &[u8],
    ) -> Result<(Vec<u8>, MessageKeys), ProtocolError> {
        // Check if we have a skipped key for this message
        if let Some(keys) = self.try_skipped_key(sender_ratchet_key, counter) {
            let plaintext = aes_cbc_decrypt(&keys.cipher_key, &keys.iv, ciphertext)?;
            return Ok((plaintext, keys));
        }

        // Check if this is a new ratchet key (DH ratchet step needed)
        let chain_idx = self.find_receiver_chain(sender_ratchet_key);
        if chain_idx.is_none() {
            // New ratchet key: perform DH ratchet step
            self.perform_ratchet_step(sender_ratchet_key)?;
        }

        // Now get the receiver chain for this ratchet key
        let chain_idx = self.find_receiver_chain(sender_ratchet_key)
            .ok_or_else(|| ProtocolError::InvalidMessage("no receiver chain found after ratchet".into()))?;

        let chain = &self.receiver_chains[chain_idx];

        if counter < chain.chain_index {
            return Err(ProtocolError::DuplicateMessage);
        }

        if counter > chain.chain_index + MAX_MESSAGE_GAP {
            return Err(ProtocolError::InvalidMessage(format!(
                "message counter gap too large: {} vs {}",
                counter, chain.chain_index
            )));
        }

        // Skip ahead in the chain, storing skipped keys
        let mut chain_key = chain.chain_key.clone();
        let mut chain_index = chain.chain_index;

        while chain_index < counter {
            let (msg_key_seed, next_ck) = derive_chain_keys(&chain_key)?;
            let keys = derive_message_keys(&msg_key_seed, chain_index)?;

            // Store skipped key
            if self.skipped_keys.len() < MAX_SKIPPED_KEYS {
                self.skipped_keys.push(SkippedKey {
                    ratchet_key: sender_ratchet_key.to_vec(),
                    counter: chain_index,
                    cipher_key: keys.cipher_key,
                    mac_key: keys.mac_key,
                    iv: keys.iv,
                });
            }

            chain_key = next_ck;
            chain_index += 1;
        }

        // Derive the message key for the target counter
        let (msg_key_seed, next_ck) = derive_chain_keys(&chain_key)?;
        let keys = derive_message_keys(&msg_key_seed, counter)?;

        // Update the chain
        self.receiver_chains[chain_idx].chain_key = next_ck;
        self.receiver_chains[chain_idx].chain_index = counter + 1;

        // Decrypt
        let plaintext = aes_cbc_decrypt(&keys.cipher_key, &keys.iv, ciphertext)?;

        Ok((plaintext, keys))
    }

    /// Perform a DH ratchet step when receiving a new ratchet key.
    fn perform_ratchet_step(&mut self, their_new_ratchet_key: &[u8]) -> Result<(), ProtocolError> {
        let their_raw = strip_key_prefix(their_new_ratchet_key)?;
        let their_ratchet_bytes: [u8; 32] = their_raw
            .try_into()
            .map_err(|_| ProtocolError::InvalidKey("invalid ratchet key length".into()))?;
        let their_ratchet_public = PublicKey::from(their_ratchet_bytes);

        let our_eph_bytes: [u8; 32] = self.local_ephemeral_private.as_slice()
            .try_into()
            .map_err(|_| ProtocolError::InvalidKey("invalid local ephemeral private key".into()))?;
        let our_eph_secret = StaticSecret::from(our_eph_bytes);

        // Step 1: DH with current ephemeral private and their new ratchet key
        let receiver_shared = our_eph_secret.diffie_hellman(&their_ratchet_public);

        // Step 2: Derive new root key and receiver chain key
        let (new_root_key, receiver_chain_key) =
            ratchet_derive(&self.root_key, receiver_shared.as_bytes())?;

        // Step 3: Generate new local ephemeral keypair
        let new_ephemeral_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let new_ephemeral_public = PublicKey::from(&new_ephemeral_secret);

        // Step 4: DH with new ephemeral and their new ratchet key
        let sender_shared = new_ephemeral_secret.diffie_hellman(&their_ratchet_public);

        // Step 5: Derive final root key and sender chain key
        let (final_root_key, sender_chain_key) =
            ratchet_derive(&new_root_key, sender_shared.as_bytes())?;

        // Update state
        self.previous_counter = self.sender_counter;
        self.sender_counter = 0;
        self.root_key = final_root_key;
        self.sender_chain_key = sender_chain_key;
        self.local_ephemeral_private = new_ephemeral_secret.to_bytes().to_vec();

        let mut new_eph_pub_wire = Vec::with_capacity(33);
        new_eph_pub_wire.push(0x05);
        new_eph_pub_wire.extend_from_slice(new_ephemeral_public.as_bytes());
        self.local_ephemeral_public = new_eph_pub_wire;

        // Add new receiver chain
        let receiver_chain = ReceiverChain {
            ratchet_key: their_new_ratchet_key.to_vec(),
            chain_key: receiver_chain_key,
            chain_index: 0,
        };
        self.receiver_chains.push(receiver_chain);

        // Trim old receiver chains
        while self.receiver_chains.len() > MAX_RECEIVER_CHAINS {
            self.receiver_chains.remove(0);
        }

        Ok(())
    }

    /// Find a receiver chain matching the given ratchet key.
    fn find_receiver_chain(&self, ratchet_key: &[u8]) -> Option<usize> {
        self.receiver_chains
            .iter()
            .position(|c| c.ratchet_key == ratchet_key)
    }

    /// Try to find and consume a skipped message key.
    fn try_skipped_key(&mut self, ratchet_key: &[u8], counter: u32) -> Option<MessageKeys> {
        let idx = self.skipped_keys.iter().position(|sk| {
            sk.ratchet_key == ratchet_key && sk.counter == counter
        })?;

        let sk = self.skipped_keys.remove(idx);
        Some(MessageKeys {
            cipher_key: sk.cipher_key,
            mac_key: sk.mac_key,
            iv: sk.iv,
            counter: sk.counter,
        })
    }

    /// Deserialize a session record from bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        serde_json::from_slice(data)
            .map_err(|e| ProtocolError::InvalidMessage(format!("session deserialize failed: {e}")))
    }

    /// Return the remote identity key bytes (33 bytes with 0x05 prefix).
    pub fn remote_identity_key(&self) -> &[u8] {
        &self.remote_identity_key
    }

    /// Return the local ephemeral public key bytes (33 bytes with 0x05 prefix).
    pub fn local_ephemeral_public(&self) -> &[u8] {
        &self.local_ephemeral_public
    }

    /// Return the sender counter.
    pub fn sender_counter(&self) -> u32 {
        self.sender_counter
    }

    /// Return the previous counter.
    pub fn previous_counter(&self) -> u32 {
        self.previous_counter
    }

    /// Return the local ephemeral private key bytes (32 bytes).
    pub fn local_ephemeral_private(&self) -> &[u8] {
        &self.local_ephemeral_private
    }

    /// Return the root key bytes.
    pub fn root_key(&self) -> &[u8] {
        &self.root_key
    }

    /// Return the sender chain key bytes.
    pub fn sender_chain_key(&self) -> &[u8] {
        &self.sender_chain_key
    }

    /// Return the base key (Alice's ephemeral from X3DH) if this is a new pre-key session.
    /// Used to construct the PreKeySignalMessage.
    pub fn base_key(&self) -> Option<&[u8]> {
        self.base_key.as_deref()
    }

    /// Return the remote device's registration ID.
    pub fn remote_registration_id(&self) -> u32 {
        self.remote_registration_id
    }

    /// Set the remote device's registration ID.
    pub fn set_remote_registration_id(&mut self, id: u32) {
        self.remote_registration_id = id;
    }
}

/// Strip the 0x05 prefix from a key if present, returning exactly 32 bytes.
fn strip_key_prefix(key: &[u8]) -> Result<&[u8], ProtocolError> {
    match key.len() {
        32 => Ok(key),
        33 if key[0] == 0x05 => Ok(&key[1..]),
        _ => Err(ProtocolError::InvalidKey(format!(
            "expected 32 or 33-byte key, got {} bytes",
            key.len()
        ))),
    }
}

/// Derive message key seed and next chain key from the current chain key.
///
/// Signal Protocol chain key derivation:
/// ```text
/// message_key_seed = HMAC-SHA256(chain_key, [0x01])
/// next_chain_key   = HMAC-SHA256(chain_key, [0x02])
/// ```
fn derive_chain_keys(chain_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    let mut mac1 = HmacSha256::new_from_slice(chain_key)
        .map_err(|e| ProtocolError::InvalidKey(format!("HMAC init failed: {e}")))?;
    mac1.update(&[0x01]);
    let message_key_seed = mac1.finalize().into_bytes().to_vec();

    let mut mac2 = HmacSha256::new_from_slice(chain_key)
        .map_err(|e| ProtocolError::InvalidKey(format!("HMAC init failed: {e}")))?;
    mac2.update(&[0x02]);
    let next_chain_key = mac2.finalize().into_bytes().to_vec();

    Ok((message_key_seed, next_chain_key))
}

/// Derive the actual message keys (cipher_key, mac_key, iv) from the message key seed.
///
/// ```text
/// (cipher_key[32], mac_key[32], iv[16]) = HKDF-SHA256(
///     salt=None, ikm=message_key_seed, info="WhisperMessageKeys", len=80
/// )
/// ```
fn derive_message_keys(message_key_seed: &[u8], counter: u32) -> Result<MessageKeys, ProtocolError> {
    let hk = Hkdf::<Sha256>::new(None, message_key_seed);
    let mut okm = [0u8; 80];
    hk.expand(WHISPER_MESSAGE_KEYS_INFO, &mut okm)
        .map_err(|e| ProtocolError::InvalidKey(format!("HKDF expand failed: {e}")))?;

    Ok(MessageKeys {
        cipher_key: okm[0..32].to_vec(),
        mac_key: okm[32..64].to_vec(),
        iv: okm[64..80].to_vec(),
        counter,
    })
}

/// Perform a DH ratchet key derivation step.
///
/// ```text
/// (new_root_key, chain_key) = HKDF-SHA256(
///     salt=old_root_key, ikm=dh_output, info="WhisperRatchet", len=64
/// )
/// ```
fn ratchet_derive(root_key: &[u8], dh_output: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    let hk = Hkdf::<Sha256>::new(Some(root_key), dh_output);
    let mut okm = [0u8; 64];
    hk.expand(WHISPER_RATCHET_INFO, &mut okm)
        .map_err(|e| ProtocolError::InvalidKey(format!("HKDF ratchet derive failed: {e}")))?;

    Ok((okm[0..32].to_vec(), okm[32..64].to_vec()))
}

/// Encrypt plaintext with AES-256-CBC + PKCS7 padding.
fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let key_arr: [u8; 32] = key
        .try_into()
        .map_err(|_| ProtocolError::InvalidKey("cipher key must be 32 bytes".into()))?;
    let iv_arr: [u8; 16] = iv
        .try_into()
        .map_err(|_| ProtocolError::InvalidKey("IV must be 16 bytes".into()))?;

    let encryptor = Aes256CbcEnc::new(&key_arr.into(), &iv_arr.into());
    Ok(encryptor.encrypt_padded_vec_mut::<aes::cipher::block_padding::Pkcs7>(plaintext))
}

/// Decrypt ciphertext with AES-256-CBC + PKCS7 unpadding.
fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let key_arr: [u8; 32] = key
        .try_into()
        .map_err(|_| ProtocolError::InvalidKey("cipher key must be 32 bytes".into()))?;
    let iv_arr: [u8; 16] = iv
        .try_into()
        .map_err(|_| ProtocolError::InvalidKey("IV must be 16 bytes".into()))?;

    let decryptor = Aes256CbcDec::new(&key_arr.into(), &iv_arr.into());
    let mut buf = ciphertext.to_vec();
    let plaintext = decryptor
        .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf)
        .map_err(|e| ProtocolError::InvalidMessage(format!("AES-CBC decrypt failed: {e}")))?;

    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let our_identity = IdentityKeyPair::generate();
        let their_identity = IdentityKeyPair::generate();

        let their_signed_pre_key_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let their_signed_pre_key_public = PublicKey::from(&their_signed_pre_key_secret);

        let their_one_time_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let their_one_time_public = PublicKey::from(&their_one_time_secret);

        // Alice establishes a session with Bob
        let (mut alice_session, _kyber_ct) = SessionRecord::new_from_pre_key(
            &our_identity,
            their_identity.public_key_bytes(),
            their_signed_pre_key_public.as_bytes(),
            Some(their_one_time_public.as_bytes()),
            None,
        )
        .unwrap();

        // The sending ratchet key (used in SignalMessage) is local_ephemeral_public
        let alice_ratchet_key = alice_session.local_ephemeral_public().to_vec();
        // The base key (for PreKeySignalMessage) is different
        let alice_base_key = alice_session.base_key().unwrap().to_vec();

        // Encrypt a message
        let plaintext = b"Hello, Bob!";
        let (ciphertext, counter, _keys) = alice_session.encrypt(plaintext).unwrap();
        assert_ne!(&ciphertext[..], plaintext.as_slice());
        assert_eq!(counter, 0);

        // Bob establishes his side using new_from_received_pre_key
        // (base_key is the ephemeral from X3DH, NOT the sending ratchet key)
        let mut bob_session = SessionRecord::new_from_received_pre_key(
            &their_identity,
            &their_signed_pre_key_secret.to_bytes(),
            Some(&their_one_time_secret.to_bytes()),
            our_identity.public_key_bytes(),
            &alice_base_key,
            None,
        )
        .unwrap();

        // Bob decrypts using Alice's sending ratchet key (from SignalMessage, not base key)
        let (decrypted, _keys) = bob_session.decrypt(&ciphertext, counter, &alice_ratchet_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn multiple_messages_increment_counter() {
        let our_identity = IdentityKeyPair::generate();
        let their_identity = IdentityKeyPair::generate();
        let their_spk_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let their_spk_public = PublicKey::from(&their_spk_secret);

        let (mut session, _) = SessionRecord::new_from_pre_key(
            &our_identity,
            their_identity.public_key_bytes(),
            their_spk_public.as_bytes(),
            None,
            None,
        )
        .unwrap();

        let (_, c0, _) = session.encrypt(b"msg 0").unwrap();
        let (_, c1, _) = session.encrypt(b"msg 1").unwrap();
        let (_, c2, _) = session.encrypt(b"msg 2").unwrap();

        assert_eq!(c0, 0);
        assert_eq!(c1, 1);
        assert_eq!(c2, 2);
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let our_identity = IdentityKeyPair::generate();
        let their_identity = IdentityKeyPair::generate();
        let their_spk_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let their_spk_public = PublicKey::from(&their_spk_secret);

        let (session, _) = SessionRecord::new_from_pre_key(
            &our_identity,
            their_identity.public_key_bytes(),
            their_spk_public.as_bytes(),
            None,
            None,
        )
        .unwrap();

        let serialized = session.serialize_to_vec();
        let deserialized = SessionRecord::deserialize(&serialized).unwrap();

        assert_eq!(session.root_key, deserialized.root_key);
        assert_eq!(session.sender_chain_key, deserialized.sender_chain_key);
        assert_eq!(session.remote_identity_key, deserialized.remote_identity_key);
    }

    #[test]
    fn from_bytes_legacy_fallback() {
        let legacy_data = vec![0x01, 0x02, 0x03];
        let record = SessionRecord::from_bytes(legacy_data.clone());
        assert_eq!(record.root_key, legacy_data);
    }

    #[test]
    fn from_bytes_json_roundtrip() {
        let our_identity = IdentityKeyPair::generate();
        let their_identity = IdentityKeyPair::generate();
        let their_spk_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let their_spk_public = PublicKey::from(&their_spk_secret);

        let (session, _) = SessionRecord::new_from_pre_key(
            &our_identity,
            their_identity.public_key_bytes(),
            their_spk_public.as_bytes(),
            None,
            None,
        )
        .unwrap();

        let bytes = session.serialize_to_vec();
        let restored = SessionRecord::from_bytes(bytes);
        assert_eq!(restored.root_key, session.root_key);
        assert_eq!(restored.sender_counter, 0);
    }

    #[test]
    fn decrypt_rejects_duplicate() {
        let our_identity = IdentityKeyPair::generate();
        let their_identity = IdentityKeyPair::generate();
        let their_spk_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let their_spk_public = PublicKey::from(&their_spk_secret);

        let their_one_time_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let their_one_time_public = PublicKey::from(&their_one_time_secret);

        let (mut alice_session, _) = SessionRecord::new_from_pre_key(
            &our_identity,
            their_identity.public_key_bytes(),
            their_spk_public.as_bytes(),
            Some(their_one_time_public.as_bytes()),
            None,
        )
        .unwrap();

        let (ct, counter, _) = alice_session.encrypt(b"test").unwrap();

        let alice_base_key = alice_session.base_key().unwrap().to_vec();
        let alice_ratchet_key = alice_session.local_ephemeral_public().to_vec();
        let mut bob_session = SessionRecord::new_from_received_pre_key(
            &their_identity,
            &their_spk_secret.to_bytes(),
            Some(&their_one_time_secret.to_bytes()),
            our_identity.public_key_bytes(),
            &alice_base_key,
            None,
        )
        .unwrap();

        // First decrypt succeeds
        bob_session.decrypt(&ct, counter, &alice_ratchet_key).unwrap();

        // Second decrypt with same counter fails (duplicate)
        let result = bob_session.decrypt(&ct, counter, &alice_ratchet_key);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_key_lengths_rejected() {
        let our_identity = IdentityKeyPair::generate();

        let result = SessionRecord::new_from_pre_key(
            &our_identity,
            &[0u8; 16],
            &[0u8; 32],
            None,
            None,
        );
        assert!(result.is_err());

        let result = SessionRecord::new_from_pre_key(
            &our_identity,
            &[0u8; 32],
            &[0u8; 16],
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn chain_key_derivation_uses_hmac() {
        let chain_key = vec![0xAA; 32];
        let (seed, next_ck) = derive_chain_keys(&chain_key).unwrap();

        // Verify the derivation is deterministic
        let (seed2, next_ck2) = derive_chain_keys(&chain_key).unwrap();
        assert_eq!(seed, seed2);
        assert_eq!(next_ck, next_ck2);

        // Seed and next_ck should be different
        assert_ne!(seed, next_ck);
    }

    #[test]
    fn message_keys_from_seed() {
        let seed = vec![0xBB; 32];
        let keys = derive_message_keys(&seed, 42).unwrap();

        assert_eq!(keys.cipher_key.len(), 32);
        assert_eq!(keys.mac_key.len(), 32);
        assert_eq!(keys.iv.len(), 16);
        assert_eq!(keys.counter, 42);
    }

    #[test]
    fn aes_cbc_roundtrip() {
        let key = vec![0x42; 32];
        let iv = vec![0x13; 16];
        let plaintext = b"Hello, AES-CBC!";

        let encrypted = aes_cbc_encrypt(&key, &iv, plaintext).unwrap();
        assert_ne!(encrypted.as_slice(), plaintext.as_slice());

        let decrypted = aes_cbc_decrypt(&key, &iv, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn received_pre_key_session_roundtrip() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();

        let bob_spk_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let bob_spk_public = PublicKey::from(&bob_spk_secret);

        // Alice sends to Bob
        let (mut alice_session, _) = SessionRecord::new_from_pre_key(
            &alice_identity,
            bob_identity.public_key_bytes(),
            bob_spk_public.as_bytes(),
            None,
            None,
        )
        .unwrap();

        let (ct, counter, _keys) = alice_session.encrypt(b"hello from alice").unwrap();

        // Bob receives with new_from_received_pre_key
        // base_key = X3DH ephemeral, ratchet_key = sending ratchet key (different after post-X3DH ratchet step)
        let alice_base_key = alice_session.base_key().unwrap().to_vec();
        let alice_ratchet_key = alice_session.local_ephemeral_public().to_vec();
        let mut bob_session = SessionRecord::new_from_received_pre_key(
            &bob_identity,
            &bob_spk_secret.to_bytes(),
            None,
            alice_identity.public_key_bytes(),
            &alice_base_key,
            None,
        )
        .unwrap();

        let (plaintext, _keys) = bob_session.decrypt(&ct, counter, &alice_ratchet_key).unwrap();
        assert_eq!(plaintext, b"hello from alice");

        // Bob responds to Alice
        let (ct2, counter2, _keys2) = bob_session.encrypt(b"hello from bob").unwrap();

        // Alice receives Bob's response (new ratchet key from Bob)
        let bob_ratchet_key = bob_session.local_ephemeral_public();
        let (pt2, _keys2) = alice_session.decrypt(&ct2, counter2, bob_ratchet_key).unwrap();
        assert_eq!(pt2, b"hello from bob");
    }

    #[test]
    fn out_of_order_delivery() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();

        let bob_spk_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let bob_spk_public = PublicKey::from(&bob_spk_secret);

        let (mut alice_session, _) = SessionRecord::new_from_pre_key(
            &alice_identity,
            bob_identity.public_key_bytes(),
            bob_spk_public.as_bytes(),
            None,
            None,
        )
        .unwrap();

        let alice_ratchet_key = alice_session.local_ephemeral_public().to_vec();
        let alice_base_key = alice_session.base_key().unwrap().to_vec();

        let (ct0, c0, _) = alice_session.encrypt(b"msg 0").unwrap();
        let (ct1, c1, _) = alice_session.encrypt(b"msg 1").unwrap();
        let (ct2, c2, _) = alice_session.encrypt(b"msg 2").unwrap();

        let mut bob_session = SessionRecord::new_from_received_pre_key(
            &bob_identity,
            &bob_spk_secret.to_bytes(),
            None,
            alice_identity.public_key_bytes(),
            &alice_base_key,
            None,
        )
        .unwrap();

        // Deliver out of order: msg 2, then msg 0, then msg 1
        let (pt2, _) = bob_session.decrypt(&ct2, c2, &alice_ratchet_key).unwrap();
        assert_eq!(pt2, b"msg 2");

        let (pt0, _) = bob_session.decrypt(&ct0, c0, &alice_ratchet_key).unwrap();
        assert_eq!(pt0, b"msg 0");

        let (pt1, _) = bob_session.decrypt(&ct1, c1, &alice_ratchet_key).unwrap();
        assert_eq!(pt1, b"msg 1");
    }

    #[test]
    fn pqxdh_kyber_roundtrip() {
        use libsignal_protocol::kem;

        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();

        let bob_spk_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let bob_spk_public = PublicKey::from(&bob_spk_secret);

        let bob_opk_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let bob_opk_public = PublicKey::from(&bob_opk_secret);

        // Generate a real Kyber1024 key pair for Bob
        let mut csprng = rand_09::rng();
        let kyber_kp = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut csprng);
        let kyber_pub_bytes = kyber_kp.public_key.serialize();
        let kyber_sk_bytes = kyber_kp.secret_key.serialize();

        // Alice establishes PQXDH session with Bob (includes Kyber)
        let (mut alice_session, kyber_ct) = SessionRecord::new_from_pre_key(
            &alice_identity,
            bob_identity.public_key_bytes(),
            bob_spk_public.as_bytes(),
            Some(bob_opk_public.as_bytes()),
            Some(&kyber_pub_bytes),
        )
        .unwrap();

        // Kyber ciphertext should be present
        assert!(kyber_ct.is_some(), "PQXDH should produce Kyber ciphertext");
        let kyber_ct = kyber_ct.unwrap();

        let alice_ratchet_key = alice_session.local_ephemeral_public().to_vec();
        let alice_base_key = alice_session.base_key().unwrap().to_vec();

        // Alice encrypts a message
        let (ct, counter, _keys) = alice_session.encrypt(b"PQXDH hello!").unwrap();

        // Bob establishes session from received pre-key (with Kyber decapsulation)
        let mut bob_session = SessionRecord::new_from_received_pre_key(
            &bob_identity,
            &bob_spk_secret.to_bytes(),
            Some(&bob_opk_secret.to_bytes()),
            alice_identity.public_key_bytes(),
            &alice_base_key,
            Some((&kyber_sk_bytes, &kyber_ct)),
        )
        .unwrap();

        // Bob decrypts
        let (plaintext, _keys) = bob_session.decrypt(&ct, counter, &alice_ratchet_key).unwrap();
        assert_eq!(plaintext, b"PQXDH hello!");

        // Bob responds
        let (ct2, counter2, _) = bob_session.encrypt(b"PQXDH reply!").unwrap();
        let bob_ratchet_key = bob_session.local_ephemeral_public().to_vec();

        // Alice decrypts Bob's response
        let (pt2, _) = alice_session.decrypt(&ct2, counter2, &bob_ratchet_key).unwrap();
        assert_eq!(pt2, b"PQXDH reply!");
    }
}
