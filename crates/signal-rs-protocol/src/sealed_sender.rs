//! Sealed sender (unidentified delivery) — V1 protocol implementation.
//!
//! Implements Signal's sealed sender protocol which wraps messages so that
//! the server cannot identify the sender. Uses double ECDH + AES-256-CTR +
//! HMAC-SHA256 (truncated to 10 bytes).

use ctr::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use prost::Message as ProstMessage;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::ProtocolError;
use crate::identity::{IdentityKey, IdentityKeyPair};
use crate::types::DeviceId;

use signal_rs_protos::sealed_sender_proto;

type HmacSha256 = Hmac<Sha256>;
type Aes256Ctr = ctr::Ctr32BE<aes::Aes256>;

// ---------------------------------------------------------------------------
// Public types (kept from original)
// ---------------------------------------------------------------------------

/// A sender certificate used for sealed-sender (unidentified) message delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderCertificate {
    pub signer: IdentityKey,
    pub key: Vec<u8>,
    pub sender_uuid: String,
    pub sender_e164: Option<String>,
    pub sender_device_id: DeviceId,
    pub expiration: u64,
    pub serialized: Vec<u8>,
}

/// Controls how unidentified (sealed-sender) delivery is used for a contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum UnidentifiedAccessMode {
    #[default]
    Unknown,
    Disabled,
    Enabled,
    Unrestricted,
}

/// The result of unsealing a sealed-sender message.
#[derive(Debug, Clone)]
pub struct UnsealedMessage {
    /// The sender's UUID (ACI) extracted from the sender certificate.
    pub sender_uuid: uuid::Uuid,
    /// The sender's device ID from the sender certificate.
    pub sender_device_id: DeviceId,
    /// Wire message type: 1 (Whisper) or 3 (PreKey).
    pub msg_type: u32,
    /// The inner ciphertext (still encrypted Signal message, needs session decrypt).
    pub content: Vec<u8>,
    /// The sender's 33-byte identity public key (from encrypted_static).
    pub sender_identity_key: Vec<u8>,
    /// The raw sender certificate bytes.
    pub sender_certificate_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Validation helpers (kept from original)
// ---------------------------------------------------------------------------

/// Validate a sender certificate's expiration against the current timestamp.
pub fn validate_certificate_expiry(
    certificate: &SenderCertificate,
    now_millis: u64,
) -> Result<(), ProtocolError> {
    if certificate.expiration < now_millis {
        return Err(ProtocolError::InvalidMessage(format!(
            "sender certificate expired: certificate expiry {} < current time {}",
            certificate.expiration, now_millis,
        )));
    }
    Ok(())
}

/// Validate that the sender UUID in the certificate matches the sender in the envelope.
pub fn validate_certificate_sender(
    certificate: &SenderCertificate,
    sender_uuid: &uuid::Uuid,
) -> Result<(), ProtocolError> {
    let cert_uuid = uuid::Uuid::parse_str(&certificate.sender_uuid).map_err(|e| {
        ProtocolError::InvalidMessage(format!("invalid UUID in sender certificate: {e}"))
    })?;
    if cert_uuid != *sender_uuid {
        return Err(ProtocolError::InvalidMessage(format!(
            "sender UUID mismatch: certificate has {cert_uuid}, envelope has {sender_uuid}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Low-level crypto helpers
// ---------------------------------------------------------------------------

/// AES-256-CTR with 16-byte zero IV. Symmetric — same function encrypts and decrypts.
fn aes256_ctr_process(data: &mut [u8], key: &[u8; 32]) {
    let iv = [0u8; 16];
    let mut cipher = Aes256Ctr::new(key.into(), &iv.into());
    cipher.apply_keystream(data);
}

/// Full HMAC-SHA256.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// AES-256-CTR encrypt, then append 10-byte truncated HMAC-SHA256.
fn aes256_ctr_hmacsha256_encrypt(
    plaintext: &[u8],
    cipher_key: &[u8; 32],
    mac_key: &[u8; 32],
) -> Vec<u8> {
    let mut ciphertext = plaintext.to_vec();
    aes256_ctr_process(&mut ciphertext, cipher_key);
    let mac = hmac_sha256(mac_key, &ciphertext);
    ciphertext.extend_from_slice(&mac[..10]);
    ciphertext
}

/// Verify 10-byte truncated HMAC-SHA256, then AES-256-CTR decrypt.
fn aes256_ctr_hmacsha256_decrypt(
    data: &[u8],
    cipher_key: &[u8; 32],
    mac_key: &[u8; 32],
) -> Result<Vec<u8>, ProtocolError> {
    if data.len() < 10 {
        return Err(ProtocolError::InvalidMessage(
            "sealed sender ciphertext too short for MAC".into(),
        ));
    }
    let ciphertext = &data[..data.len() - 10];
    let their_mac = &data[data.len() - 10..];
    let our_mac = hmac_sha256(mac_key, ciphertext);
    if our_mac[..10] != *their_mac {
        return Err(ProtocolError::InvalidMessage(
            "sealed sender MAC verification failed".into(),
        ));
    }
    let mut plaintext = ciphertext.to_vec();
    aes256_ctr_process(&mut plaintext, cipher_key);
    Ok(plaintext)
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Keys derived from the ephemeral ECDH (first round).
struct EphemeralKeys {
    chain_key: [u8; 32],
    cipher_key: [u8; 32],
    mac_key: [u8; 32],
}

impl EphemeralKeys {
    /// Derive ephemeral keys from the ECDH shared secret.
    ///
    /// Salt = `"UnidentifiedDelivery" || recipient_pub(33) || ephemeral_pub(33)`
    /// HKDF-SHA256(salt, ikm=shared_secret, info="") → 96 bytes
    fn derive(
        shared_secret: &[u8; 32],
        recipient_identity_pub: &[u8], // 33 bytes
        ephemeral_pub: &[u8],          // 33 bytes
    ) -> Result<Self, ProtocolError> {
        let mut salt = Vec::with_capacity(20 + 33 + 33);
        salt.extend_from_slice(b"UnidentifiedDelivery");
        salt.extend_from_slice(recipient_identity_pub);
        salt.extend_from_slice(ephemeral_pub);

        let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
        let mut okm = [0u8; 96];
        hk.expand(b"", &mut okm)
            .map_err(|e| ProtocolError::InvalidKey(format!("HKDF expand failed: {e}")))?;

        let mut chain_key = [0u8; 32];
        let mut cipher_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        chain_key.copy_from_slice(&okm[0..32]);
        cipher_key.copy_from_slice(&okm[32..64]);
        mac_key.copy_from_slice(&okm[64..96]);

        Ok(Self {
            chain_key,
            cipher_key,
            mac_key,
        })
    }
}

/// Keys derived from the static ECDH (second round).
struct StaticKeys {
    cipher_key: [u8; 32],
    mac_key: [u8; 32],
}

impl StaticKeys {
    /// Derive static keys from the sender-identity↔recipient-identity ECDH.
    ///
    /// Salt = `chain_key(32) || encrypted_static(43)`
    /// HKDF-SHA256(salt, ikm=shared_secret, info="") → 96 bytes
    /// Output: [_unused(32), cipher_key(32), mac_key(32)]
    fn derive(
        shared_secret: &[u8; 32],
        chain_key: &[u8; 32],
        encrypted_static: &[u8],
    ) -> Result<Self, ProtocolError> {
        let mut salt = Vec::with_capacity(32 + encrypted_static.len());
        salt.extend_from_slice(chain_key);
        salt.extend_from_slice(encrypted_static);

        let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
        let mut okm = [0u8; 96];
        hk.expand(b"", &mut okm)
            .map_err(|e| ProtocolError::InvalidKey(format!("HKDF expand failed: {e}")))?;

        let mut cipher_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        // First 32 bytes are unused in V1
        cipher_key.copy_from_slice(&okm[32..64]);
        mac_key.copy_from_slice(&okm[64..96]);

        Ok(Self {
            cipher_key,
            mac_key,
        })
    }
}

// ---------------------------------------------------------------------------
// seal — create a sealed-sender message
// ---------------------------------------------------------------------------

/// Create a sealed-sender (type 6) message wrapping an inner Signal ciphertext.
///
/// # Arguments
/// - `inner_ciphertext` — The encrypted Signal message (PreKeySignalMessage or SignalMessage bytes)
/// - `inner_msg_type` — Wire type of the inner message (1 = Whisper, 3 = PreKey)
/// - `sender_cert_bytes` — Raw `SenderCertificate` protobuf from the server
/// - `sender_identity` — Our identity key pair
/// - `recipient_identity_pub` — Recipient's 33-byte identity public key (0x05 prefix)
/// - `content_hint` — 1 = RESENDABLE
/// - `group_id` — Optional group ID for group messages
pub fn seal(
    inner_ciphertext: &[u8],
    inner_msg_type: u32,
    sender_cert_bytes: &[u8],
    sender_identity: &IdentityKeyPair,
    recipient_identity_pub: &[u8],
    content_hint: u32,
    group_id: Option<&[u8]>,
) -> Result<Vec<u8>, ProtocolError> {
    // 1. Generate ephemeral X25519 key pair
    let ephemeral_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // Build 33-byte ephemeral public (0x05 prefix + 32-byte key)
    let mut ephemeral_pub_33 = Vec::with_capacity(33);
    ephemeral_pub_33.push(0x05);
    ephemeral_pub_33.extend_from_slice(ephemeral_public.as_bytes());

    // 2. ECDH(ephemeral, recipient_identity) — strip 0x05 prefix for DH
    let recipient_raw: [u8; 32] = recipient_identity_pub
        .get(1..33)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| {
            ProtocolError::InvalidKey("recipient identity key must be 33 bytes".into())
        })?;
    let recipient_pub = PublicKey::from(recipient_raw);
    let ephemeral_shared = ephemeral_secret.diffie_hellman(&recipient_pub);

    // 3. Derive EphemeralKeys
    let eph_keys = EphemeralKeys::derive(
        ephemeral_shared.as_bytes(),
        recipient_identity_pub,
        &ephemeral_pub_33,
    )?;

    // 4. Encrypt sender identity (33 bytes) → encrypted_static (43 bytes: 33 ct + 10 mac)
    let sender_pub_33 = sender_identity.public_key().serialize();
    let encrypted_static =
        aes256_ctr_hmacsha256_encrypt(sender_pub_33, &eph_keys.cipher_key, &eph_keys.mac_key);

    // 5. ECDH(sender_identity, recipient_identity)
    let sender_private_bytes: [u8; 32] = sender_identity
        .private_key_bytes()
        .try_into()
        .map_err(|_| ProtocolError::InvalidKey("invalid sender private key length".into()))?;
    let sender_secret = StaticSecret::from(sender_private_bytes);
    let static_shared = sender_secret.diffie_hellman(&recipient_pub);

    // 6. Derive StaticKeys
    let static_keys = StaticKeys::derive(
        static_shared.as_bytes(),
        &eph_keys.chain_key,
        &encrypted_static,
    )?;

    // 7. Build USMC proto
    //    Map wire types: 3 (PreKey) → 1 (PREKEY_MESSAGE), 1 (Whisper) → 2 (MESSAGE)
    let usmc_type = match inner_msg_type {
        3 => 1, // PreKey → PREKEY_MESSAGE
        1 => 2, // Whisper → MESSAGE
        other => other,
    };

    let usmc = sealed_sender_proto::unidentified_sender_message::Message {
        r#type: Some(usmc_type as i32),
        sender_certificate: Some(sender_cert_bytes.to_vec()),
        content: Some(inner_ciphertext.to_vec()),
        content_hint: Some(content_hint as i32),
        group_id: group_id.map(|g| g.to_vec()),
    };
    let usmc_bytes = usmc.encode_to_vec();

    // 8. Encrypt USMC → encrypted_message
    let encrypted_message = aes256_ctr_hmacsha256_encrypt(
        &usmc_bytes,
        &static_keys.cipher_key,
        &static_keys.mac_key,
    );

    // 9. Build UnidentifiedSenderMessage proto
    let usm = sealed_sender_proto::UnidentifiedSenderMessage {
        ephemeral_public: Some(ephemeral_pub_33),
        encrypted_static: Some(encrypted_static),
        encrypted_message: Some(encrypted_message),
    };

    // 10. Return [version_byte] || proto
    //     Version byte 0x11: high nibble = 1 (V1), low nibble = 1 (current)
    let mut result = Vec::with_capacity(1 + usm.encoded_len());
    result.push(0x11);
    result.extend_from_slice(&usm.encode_to_vec());
    Ok(result)
}

// ---------------------------------------------------------------------------
// unseal — decrypt a sealed-sender message
// ---------------------------------------------------------------------------

/// Unseal a sealed-sender (type 6) envelope.
///
/// Decrypts the double-ECDH outer layer to extract the sender's identity,
/// the inner message type, and the inner ciphertext (which still requires
/// session-level decryption).
pub fn unseal(
    data: &[u8],
    our_identity: &IdentityKeyPair,
    _timestamp: u64,
) -> Result<UnsealedMessage, ProtocolError> {
    if data.is_empty() {
        return Err(ProtocolError::InvalidMessage(
            "empty sealed sender data".into(),
        ));
    }

    // 1. Parse version byte: high nibble must be 0 or 1 (V1)
    let version = data[0] >> 4;
    if version > 1 {
        return Err(ProtocolError::InvalidMessage(format!(
            "unsupported sealed sender version: {version}"
        )));
    }

    // 2. Decode UnidentifiedSenderMessage protobuf from data[1..]
    let usm = sealed_sender_proto::UnidentifiedSenderMessage::decode(&data[1..]).map_err(|e| {
        ProtocolError::InvalidMessage(format!(
            "failed to decode UnidentifiedSenderMessage: {e}"
        ))
    })?;

    let ephemeral_pub_bytes = usm
        .ephemeral_public
        .ok_or_else(|| ProtocolError::InvalidMessage("missing ephemeral public key".into()))?;
    let encrypted_static = usm
        .encrypted_static
        .ok_or_else(|| ProtocolError::InvalidMessage("missing encrypted static".into()))?;
    let encrypted_message = usm
        .encrypted_message
        .ok_or_else(|| ProtocolError::InvalidMessage("missing encrypted message".into()))?;

    // 3. ECDH(our_identity_private, ephemeral_public)
    let our_private_bytes: [u8; 32] = our_identity
        .private_key_bytes()
        .try_into()
        .map_err(|_| ProtocolError::InvalidKey("invalid private key length".into()))?;
    let our_secret = StaticSecret::from(our_private_bytes);

    // Strip 0x05 prefix from ephemeral key for DH
    let eph_raw: [u8; 32] = if ephemeral_pub_bytes.len() == 33 && ephemeral_pub_bytes[0] == 0x05 {
        ephemeral_pub_bytes[1..]
            .try_into()
            .map_err(|_| ProtocolError::InvalidKey("bad ephemeral key".into()))?
    } else if ephemeral_pub_bytes.len() == 32 {
        ephemeral_pub_bytes[..]
            .try_into()
            .map_err(|_| ProtocolError::InvalidKey("bad ephemeral key".into()))?
    } else {
        return Err(ProtocolError::InvalidKey(
            "unexpected ephemeral key length".into(),
        ));
    };
    let ephemeral_pub = PublicKey::from(eph_raw);
    let ephemeral_shared = our_secret.diffie_hellman(&ephemeral_pub);

    // Our 33-byte identity public key (recipient in the sender's perspective)
    let our_identity_pub_33 = our_identity.public_key().serialize();

    // Derive EphemeralKeys (salt uses recipient_pub || ephemeral_pub)
    let eph_keys = EphemeralKeys::derive(
        ephemeral_shared.as_bytes(),
        our_identity_pub_33,
        &ephemeral_pub_bytes,
    )?;

    // 4. Decrypt encrypted_static → sender identity public (33 bytes)
    let sender_identity_pub = aes256_ctr_hmacsha256_decrypt(
        &encrypted_static,
        &eph_keys.cipher_key,
        &eph_keys.mac_key,
    )?;

    if sender_identity_pub.len() != 33 {
        return Err(ProtocolError::InvalidMessage(format!(
            "decrypted sender identity key has wrong length: {}",
            sender_identity_pub.len()
        )));
    }

    // 5. ECDH(our_identity_private, sender_identity_public)
    let sender_raw: [u8; 32] = sender_identity_pub[1..]
        .try_into()
        .map_err(|_| ProtocolError::InvalidKey("invalid sender identity key".into()))?;
    let sender_pub = PublicKey::from(sender_raw);
    let static_shared = our_secret.diffie_hellman(&sender_pub);

    // 6. Derive StaticKeys
    let static_keys = StaticKeys::derive(
        static_shared.as_bytes(),
        &eph_keys.chain_key,
        &encrypted_static,
    )?;

    // 7. Decrypt encrypted_message → USMC bytes
    let usmc_bytes = aes256_ctr_hmacsha256_decrypt(
        &encrypted_message,
        &static_keys.cipher_key,
        &static_keys.mac_key,
    )?;

    // 8. Parse USMC proto
    let usmc = sealed_sender_proto::unidentified_sender_message::Message::decode(
        usmc_bytes.as_slice(),
    )
    .map_err(|e| ProtocolError::InvalidMessage(format!("failed to decode USMC: {e}")))?;

    let sender_cert_bytes = usmc
        .sender_certificate
        .ok_or_else(|| ProtocolError::InvalidMessage("missing sender certificate in USMC".into()))?;
    let inner_content = usmc
        .content
        .ok_or_else(|| ProtocolError::InvalidMessage("missing content in USMC".into()))?;
    let usmc_type = usmc.r#type.unwrap_or(1) as u32;

    // 9. Parse sender certificate to extract UUID and device ID
    let sender_cert =
        sealed_sender_proto::SenderCertificate::decode(sender_cert_bytes.as_slice()).map_err(
            |e| {
                ProtocolError::InvalidMessage(format!(
                    "failed to decode SenderCertificate: {e}"
                ))
            },
        )?;

    let cert_inner_bytes = sender_cert.certificate.ok_or_else(|| {
        ProtocolError::InvalidMessage("missing certificate field in SenderCertificate".into())
    })?;
    let cert_inner =
        sealed_sender_proto::sender_certificate::Certificate::decode(cert_inner_bytes.as_slice())
            .map_err(|e| {
                ProtocolError::InvalidMessage(format!(
                    "failed to decode SenderCertificate.Certificate: {e}"
                ))
            })?;

    // Extract sender UUID from the oneof
    let sender_uuid_str = match cert_inner.sender_uuid {
        Some(
            sealed_sender_proto::sender_certificate::certificate::SenderUuid::UuidString(ref s),
        ) => s.clone(),
        Some(sealed_sender_proto::sender_certificate::certificate::SenderUuid::UuidBytes(
            ref b,
        )) => {
            if b.len() == 16 {
                let bytes: [u8; 16] = b[..].try_into().unwrap();
                uuid::Uuid::from_bytes(bytes).to_string()
            } else {
                return Err(ProtocolError::InvalidMessage(
                    "invalid UUID bytes length in sender certificate".into(),
                ));
            }
        }
        None => {
            return Err(ProtocolError::InvalidMessage(
                "missing sender UUID in certificate".into(),
            ));
        }
    };

    let sender_uuid = uuid::Uuid::parse_str(&sender_uuid_str)
        .map_err(|e| ProtocolError::InvalidMessage(format!("invalid sender UUID: {e}")))?;
    let sender_device_id = DeviceId(cert_inner.sender_device.unwrap_or(1));

    // 10. Verify sender identity from encrypted_static matches certificate's identityKey
    if let Some(ref cert_identity) = cert_inner.identity_key
        && *cert_identity != sender_identity_pub
    {
        return Err(ProtocolError::InvalidMessage(
            "sender identity key mismatch: encrypted_static != certificate identity".into(),
        ));
    }

    // 11. Map USMC type to wire type: 1 → 3 (PreKey), 2 → 1 (Whisper)
    let msg_type = match usmc_type {
        1 => 3, // PREKEY_MESSAGE → PreKey wire type 3
        2 => 1, // MESSAGE → Whisper wire type 1
        other => other,
    };

    Ok(UnsealedMessage {
        sender_uuid,
        sender_device_id,
        msg_type,
        content: inner_content,
        sender_identity_key: sender_identity_pub,
        sender_certificate_bytes: sender_cert_bytes,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a mock sender certificate for testing.
    fn build_test_sender_certificate(
        sender_uuid: &uuid::Uuid,
        sender_device: u32,
        identity_key: &[u8],
    ) -> Vec<u8> {
        let cert_inner = sealed_sender_proto::sender_certificate::Certificate {
            sender_e164: None,
            sender_uuid: Some(
                sealed_sender_proto::sender_certificate::certificate::SenderUuid::UuidString(
                    sender_uuid.to_string(),
                ),
            ),
            sender_device: Some(sender_device),
            expires: Some(u64::MAX),
            identity_key: Some(identity_key.to_vec()),
            signer: None,
        };
        let cert_inner_bytes = cert_inner.encode_to_vec();

        let sender_cert = sealed_sender_proto::SenderCertificate {
            certificate: Some(cert_inner_bytes),
            signature: Some(vec![0u8; 64]), // dummy signature
        };
        sender_cert.encode_to_vec()
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let sender_identity = IdentityKeyPair::generate();
        let recipient_identity = IdentityKeyPair::generate();
        let sender_uuid = uuid::Uuid::new_v4();
        let inner_content = b"Hello via sealed sender!";

        let sender_cert_bytes = build_test_sender_certificate(
            &sender_uuid,
            2,
            sender_identity.public_key().serialize(),
        );

        // Seal: PreKey message (wire type 3)
        let sealed = seal(
            inner_content,
            3,
            &sender_cert_bytes,
            &sender_identity,
            recipient_identity.public_key().serialize(),
            1,
            None,
        )
        .unwrap();

        // Version byte should be 0x11
        assert_eq!(sealed[0], 0x11);

        // Unseal from recipient's perspective
        let unsealed = unseal(&sealed, &recipient_identity, 0).unwrap();

        assert_eq!(unsealed.sender_uuid, sender_uuid);
        assert_eq!(unsealed.sender_device_id.0, 2);
        assert_eq!(unsealed.msg_type, 3); // PreKey wire type
        assert_eq!(unsealed.content, inner_content);
        assert_eq!(
            unsealed.sender_identity_key,
            sender_identity.public_key().serialize()
        );
    }

    #[test]
    fn seal_unseal_whisper_type() {
        let sender_identity = IdentityKeyPair::generate();
        let recipient_identity = IdentityKeyPair::generate();
        let sender_uuid = uuid::Uuid::new_v4();

        let sender_cert_bytes = build_test_sender_certificate(
            &sender_uuid,
            1,
            sender_identity.public_key().serialize(),
        );

        // Seal: Whisper message (wire type 1)
        let sealed = seal(
            b"whisper content",
            1,
            &sender_cert_bytes,
            &sender_identity,
            recipient_identity.public_key().serialize(),
            1,
            None,
        )
        .unwrap();

        let unsealed = unseal(&sealed, &recipient_identity, 0).unwrap();
        assert_eq!(unsealed.msg_type, 1); // Whisper wire type
        assert_eq!(unsealed.content, b"whisper content");
    }

    #[test]
    fn unseal_wrong_recipient_fails() {
        let sender_identity = IdentityKeyPair::generate();
        let recipient_identity = IdentityKeyPair::generate();
        let wrong_identity = IdentityKeyPair::generate();

        let sender_cert_bytes = build_test_sender_certificate(
            &uuid::Uuid::new_v4(),
            1,
            sender_identity.public_key().serialize(),
        );

        let sealed = seal(
            b"test",
            3,
            &sender_cert_bytes,
            &sender_identity,
            recipient_identity.public_key().serialize(),
            1,
            None,
        )
        .unwrap();

        // Unsealing with the wrong identity key should fail (MAC mismatch)
        assert!(unseal(&sealed, &wrong_identity, 0).is_err());
    }

    #[test]
    fn unseal_rejects_bad_version() {
        let recipient = IdentityKeyPair::generate();
        // Version byte 0x21 → version 2, unsupported
        let data = vec![0x21, 0x00, 0x01, 0x02];
        assert!(unseal(&data, &recipient, 0).is_err());
    }

    #[test]
    fn unseal_rejects_empty() {
        let recipient = IdentityKeyPair::generate();
        assert!(unseal(&[], &recipient, 0).is_err());
    }

    #[test]
    fn seal_unseal_with_group_id() {
        let sender_identity = IdentityKeyPair::generate();
        let recipient_identity = IdentityKeyPair::generate();
        let sender_uuid = uuid::Uuid::new_v4();
        let group_id = b"some-group-id";

        let sender_cert_bytes = build_test_sender_certificate(
            &sender_uuid,
            1,
            sender_identity.public_key().serialize(),
        );

        let sealed = seal(
            b"group msg",
            3,
            &sender_cert_bytes,
            &sender_identity,
            recipient_identity.public_key().serialize(),
            1,
            Some(group_id),
        )
        .unwrap();

        let unsealed = unseal(&sealed, &recipient_identity, 0).unwrap();
        assert_eq!(unsealed.sender_uuid, sender_uuid);
        assert_eq!(unsealed.content, b"group msg");
    }

    // ---- validate_certificate_expiry tests ----

    #[test]
    fn certificate_expiry_valid() {
        let cert = SenderCertificate {
            signer: IdentityKey::from_bytes(&[0x05; 33]).unwrap(),
            key: vec![0; 32],
            sender_uuid: uuid::Uuid::new_v4().to_string(),
            sender_e164: None,
            sender_device_id: DeviceId(1),
            expiration: u64::MAX,
            serialized: vec![],
        };
        assert!(validate_certificate_expiry(&cert, 1000).is_ok());
    }

    #[test]
    fn certificate_expiry_expired() {
        let cert = SenderCertificate {
            signer: IdentityKey::from_bytes(&[0x05; 33]).unwrap(),
            key: vec![0; 32],
            sender_uuid: uuid::Uuid::new_v4().to_string(),
            sender_e164: None,
            sender_device_id: DeviceId(1),
            expiration: 500,
            serialized: vec![],
        };
        let result = validate_certificate_expiry(&cert, 1000);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("expired"));
    }

    // ---- validate_certificate_sender tests ----

    #[test]
    fn certificate_sender_matches() {
        let uuid = uuid::Uuid::new_v4();
        let cert = SenderCertificate {
            signer: IdentityKey::from_bytes(&[0x05; 33]).unwrap(),
            key: vec![0; 32],
            sender_uuid: uuid.to_string(),
            sender_e164: None,
            sender_device_id: DeviceId(1),
            expiration: u64::MAX,
            serialized: vec![],
        };
        assert!(validate_certificate_sender(&cert, &uuid).is_ok());
    }

    #[test]
    fn certificate_sender_mismatch() {
        let cert_uuid = uuid::Uuid::new_v4();
        let other_uuid = uuid::Uuid::new_v4();
        let cert = SenderCertificate {
            signer: IdentityKey::from_bytes(&[0x05; 33]).unwrap(),
            key: vec![0; 32],
            sender_uuid: cert_uuid.to_string(),
            sender_e164: None,
            sender_device_id: DeviceId(1),
            expiration: u64::MAX,
            serialized: vec![],
        };
        let result = validate_certificate_sender(&cert, &other_uuid);
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("mismatch"));
    }
}
