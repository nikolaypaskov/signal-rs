//! Wire message format types for the Signal Protocol.
//!
//! Handles serialization/deserialization of the three wire message types:
//! - `WireSignalMessage`: `[version_byte][protobuf][8-byte MAC]`
//! - `WirePreKeySignalMessage`: `[version_byte][protobuf]`
//! - `WireSenderKeyMessage`: `[version_byte][protobuf][64-byte Ed25519 signature]`

use prost::Message;

use crate::error::ProtocolError;

/// Signal Protocol version byte: (4 << 4) | 4 = 0x44
/// High nibble = message version (4 = PQXDH), low nibble = current protocol version (4).
pub const SIGNAL_MESSAGE_VERSION: u8 = 0x44;

/// MAC size in bytes (truncated HMAC-SHA256).
const MAC_SIZE: usize = 8;

/// Ed25519 signature size in bytes.
const SIGNATURE_SIZE: usize = 64;

// ---- SignalMessage (type 1, "Whisper") ----

/// A parsed SignalMessage (Whisper message, type 1).
///
/// Wire format: `[1-byte version][protobuf data][8-byte MAC]`
#[derive(Debug, Clone)]
pub struct WireSignalMessage {
    /// The version byte.
    pub version: u8,
    /// The sender's current ratchet public key (33 bytes with 0x05 prefix).
    pub ratchet_key: Vec<u8>,
    /// Message counter in the current chain.
    pub counter: u32,
    /// Counter value from the previous chain.
    pub previous_counter: u32,
    /// AES-256-CBC encrypted content.
    pub ciphertext: Vec<u8>,
    /// The 8-byte truncated HMAC-SHA256 MAC.
    pub mac: Vec<u8>,
    /// The raw protobuf body (version byte not included, MAC not included).
    /// Needed for MAC verification.
    pub serialized_protobuf: Vec<u8>,
}

impl WireSignalMessage {
    /// Deserialize a SignalMessage from wire bytes.
    ///
    /// Format: `[version][protobuf][8-byte MAC]`
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < 1 + MAC_SIZE {
            return Err(ProtocolError::InvalidMessage(
                "SignalMessage too short".into(),
            ));
        }

        let version = bytes[0];
        if (version >> 4) < 3 || (version >> 4) > 4 {
            return Err(ProtocolError::InvalidMessage(format!(
                "unsupported SignalMessage version: {:#x}",
                version
            )));
        }

        let mac_start = bytes.len() - MAC_SIZE;
        let protobuf_bytes = &bytes[1..mac_start];
        let mac = bytes[mac_start..].to_vec();

        let proto = signal_rs_protos::wire_format::SignalMessage::decode(protobuf_bytes)
            .map_err(|e| ProtocolError::InvalidMessage(format!("protobuf decode failed: {e}")))?;

        Ok(Self {
            version,
            ratchet_key: proto.ratchet_key.unwrap_or_default(),
            counter: proto.counter.unwrap_or(0),
            previous_counter: proto.previous_counter.unwrap_or(0),
            ciphertext: proto.ciphertext.unwrap_or_default(),
            mac,
            serialized_protobuf: protobuf_bytes.to_vec(),
        })
    }

    /// Serialize a SignalMessage to wire bytes.
    ///
    /// Builds: `[version][protobuf][8-byte MAC]`
    ///
    /// The MAC is computed as:
    /// `HMAC-SHA256(mac_key, sender_identity || receiver_identity || version_byte || protobuf)[0..8]`
    pub fn serialize(
        ratchet_key: &[u8],
        counter: u32,
        prev_counter: u32,
        ciphertext: &[u8],
        mac_key: &[u8],
        sender_identity: &[u8],
        receiver_identity: &[u8],
    ) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let proto = signal_rs_protos::wire_format::SignalMessage {
            ratchet_key: Some(ratchet_key.to_vec()),
            counter: Some(counter),
            previous_counter: Some(prev_counter),
            ciphertext: Some(ciphertext.to_vec()),
        };

        let protobuf_bytes = proto.encode_to_vec();

        // Compute MAC
        type HmacSha256 = Hmac<Sha256>;
        let mut hmac = HmacSha256::new_from_slice(mac_key).expect("HMAC key length is valid");
        hmac.update(sender_identity);
        hmac.update(receiver_identity);
        hmac.update(&[SIGNAL_MESSAGE_VERSION]);
        hmac.update(&protobuf_bytes);
        let full_mac = hmac.finalize().into_bytes();
        let truncated_mac = &full_mac[..MAC_SIZE];

        let mut output = Vec::with_capacity(1 + protobuf_bytes.len() + MAC_SIZE);
        output.push(SIGNAL_MESSAGE_VERSION);
        output.extend_from_slice(&protobuf_bytes);
        output.extend_from_slice(truncated_mac);

        output
    }

    /// Verify the MAC on this message.
    ///
    /// Recomputes: `HMAC-SHA256(mac_key, sender_identity || receiver_identity || version || protobuf)[0..8]`
    pub fn verify_mac(
        &self,
        mac_key: &[u8],
        sender_identity: &[u8],
        receiver_identity: &[u8],
    ) -> Result<bool, ProtocolError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;
        let mut hmac = HmacSha256::new_from_slice(mac_key)
            .map_err(|e| ProtocolError::InvalidKey(format!("invalid MAC key: {e}")))?;
        hmac.update(sender_identity);
        hmac.update(receiver_identity);
        hmac.update(&[self.version]);
        hmac.update(&self.serialized_protobuf);
        let full_mac = hmac.finalize().into_bytes();

        Ok(full_mac[..MAC_SIZE] == self.mac[..])
    }
}

// ---- PreKeySignalMessage (type 3) ----

/// A parsed PreKeySignalMessage (type 3).
///
/// Wire format: `[1-byte version][protobuf data]`
#[derive(Debug, Clone)]
pub struct WirePreKeySignalMessage {
    /// The version byte.
    pub version: u8,
    /// Optional one-time pre-key ID.
    pub pre_key_id: Option<u32>,
    /// The sender's ephemeral base key (33 bytes with 0x05 prefix).
    pub base_key: Vec<u8>,
    /// The sender's identity key (33 bytes with 0x05 prefix).
    pub identity_key: Vec<u8>,
    /// The serialized inner SignalMessage (complete with version + protobuf + MAC).
    pub message: Vec<u8>,
    /// The sender's registration ID.
    pub registration_id: u32,
    /// The signed pre-key ID used.
    pub signed_pre_key_id: u32,
    /// Optional Kyber pre-key ID (PQXDH).
    pub kyber_pre_key_id: Option<u32>,
    /// Optional Kyber ciphertext from KEM encapsulation (PQXDH).
    pub kyber_ciphertext: Option<Vec<u8>>,
}

impl WirePreKeySignalMessage {
    /// Deserialize a PreKeySignalMessage from wire bytes.
    ///
    /// Format: `[version][protobuf]`
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < 2 {
            return Err(ProtocolError::InvalidMessage(
                "PreKeySignalMessage too short".into(),
            ));
        }

        let version = bytes[0];
        if (version >> 4) < 3 || (version >> 4) > 4 {
            return Err(ProtocolError::InvalidMessage(format!(
                "unsupported PreKeySignalMessage version: {:#x}",
                version
            )));
        }

        let proto =
            signal_rs_protos::wire_format::PreKeySignalMessage::decode(&bytes[1..]).map_err(
                |e| ProtocolError::InvalidMessage(format!("protobuf decode failed: {e}")),
            )?;

        Ok(Self {
            version,
            pre_key_id: proto.pre_key_id,
            base_key: proto.base_key.unwrap_or_default(),
            identity_key: proto.identity_key.unwrap_or_default(),
            message: proto.message.unwrap_or_default(),
            registration_id: proto.registration_id.unwrap_or(0),
            signed_pre_key_id: proto.signed_pre_key_id.unwrap_or(0),
            kyber_pre_key_id: proto.kyber_pre_key_id,
            kyber_ciphertext: proto.kyber_ciphertext,
        })
    }

    /// Serialize a PreKeySignalMessage to wire bytes.
    ///
    /// Format: `[version][protobuf]`
    #[allow(clippy::too_many_arguments)]
    pub fn serialize(
        pre_key_id: Option<u32>,
        base_key: &[u8],
        identity_key: &[u8],
        message: &[u8],
        registration_id: u32,
        signed_pre_key_id: u32,
        kyber_pre_key_id: Option<u32>,
        kyber_ciphertext: Option<&[u8]>,
    ) -> Vec<u8> {
        let proto = signal_rs_protos::wire_format::PreKeySignalMessage {
            pre_key_id,
            base_key: Some(base_key.to_vec()),
            identity_key: Some(identity_key.to_vec()),
            message: Some(message.to_vec()),
            registration_id: Some(registration_id),
            signed_pre_key_id: Some(signed_pre_key_id),
            kyber_pre_key_id,
            kyber_ciphertext: kyber_ciphertext.map(|ct| ct.to_vec()),
        };

        let protobuf_bytes = proto.encode_to_vec();

        let mut output = Vec::with_capacity(1 + protobuf_bytes.len());
        output.push(SIGNAL_MESSAGE_VERSION);
        output.extend_from_slice(&protobuf_bytes);

        output
    }
}

// ---- SenderKeyMessage (type 7) ----

/// A parsed SenderKeyMessage (type 7).
///
/// Wire format: `[1-byte version][protobuf data][64-byte Ed25519 signature]`
#[derive(Debug, Clone)]
pub struct WireSenderKeyMessage {
    /// The version byte.
    pub version: u8,
    /// The distribution UUID (16 bytes).
    pub distribution_uuid: Vec<u8>,
    /// The chain ID.
    pub chain_id: u32,
    /// The iteration (message number in the chain).
    pub iteration: u32,
    /// AES-256-CBC encrypted content.
    pub ciphertext: Vec<u8>,
    /// The 64-byte Ed25519 signature over (version + protobuf).
    pub signature: Vec<u8>,
    /// The raw bytes that were signed (version + protobuf), needed for verification.
    pub signed_data: Vec<u8>,
}

impl WireSenderKeyMessage {
    /// Deserialize a SenderKeyMessage from wire bytes.
    ///
    /// Format: `[version][protobuf][64-byte signature]`
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < 1 + SIGNATURE_SIZE {
            return Err(ProtocolError::InvalidMessage(
                "SenderKeyMessage too short".into(),
            ));
        }

        let version = bytes[0];
        if (version >> 4) < 3 || (version >> 4) > 4 {
            return Err(ProtocolError::InvalidMessage(format!(
                "unsupported SenderKeyMessage version: {:#x}",
                version
            )));
        }

        let sig_start = bytes.len() - SIGNATURE_SIZE;
        let protobuf_bytes = &bytes[1..sig_start];
        let signature = bytes[sig_start..].to_vec();

        let proto =
            signal_rs_protos::wire_format::SenderKeyMessage::decode(protobuf_bytes).map_err(
                |e| ProtocolError::InvalidMessage(format!("protobuf decode failed: {e}")),
            )?;

        Ok(Self {
            version,
            distribution_uuid: proto.distribution_uuid.unwrap_or_default(),
            chain_id: proto.chain_id.unwrap_or(0),
            iteration: proto.iteration.unwrap_or(0),
            ciphertext: proto.ciphertext.unwrap_or_default(),
            signature,
            signed_data: bytes[..sig_start].to_vec(),
        })
    }

    /// Serialize a SenderKeyMessage to wire bytes.
    ///
    /// Format: `[version][protobuf][64-byte signature]`
    ///
    /// The caller must sign `(version + protobuf)` and provide the signature.
    pub fn serialize(
        distribution_uuid: &[u8],
        chain_id: u32,
        iteration: u32,
        ciphertext: &[u8],
        signature: &[u8],
    ) -> Vec<u8> {
        let proto = signal_rs_protos::wire_format::SenderKeyMessage {
            distribution_uuid: Some(distribution_uuid.to_vec()),
            chain_id: Some(chain_id),
            iteration: Some(iteration),
            ciphertext: Some(ciphertext.to_vec()),
        };

        let protobuf_bytes = proto.encode_to_vec();

        let mut output = Vec::with_capacity(1 + protobuf_bytes.len() + signature.len());
        output.push(SIGNAL_MESSAGE_VERSION);
        output.extend_from_slice(&protobuf_bytes);
        output.extend_from_slice(signature);

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_message_roundtrip() {
        let ratchet_key = vec![0x05; 33];
        let ciphertext = b"encrypted data here";
        let mac_key = vec![0xAA; 32];
        let sender_id = vec![0x05; 33];
        let receiver_id = vec![0x05; 33];

        let serialized = WireSignalMessage::serialize(
            &ratchet_key,
            42,
            10,
            ciphertext,
            &mac_key,
            &sender_id,
            &receiver_id,
        );

        let parsed = WireSignalMessage::deserialize(&serialized).unwrap();
        assert_eq!(parsed.version, SIGNAL_MESSAGE_VERSION);
        assert_eq!(parsed.ratchet_key, ratchet_key);
        assert_eq!(parsed.counter, 42);
        assert_eq!(parsed.previous_counter, 10);
        assert_eq!(parsed.ciphertext, ciphertext);

        // Verify MAC
        assert!(parsed.verify_mac(&mac_key, &sender_id, &receiver_id).unwrap());

        // Wrong MAC key should fail
        let wrong_key = vec![0xBB; 32];
        assert!(!parsed.verify_mac(&wrong_key, &sender_id, &receiver_id).unwrap());
    }

    #[test]
    fn prekey_signal_message_roundtrip() {
        let base_key = vec![0x05; 33];
        let identity_key = vec![0x05; 33];
        let inner_message = b"inner signal message bytes";

        let serialized = WirePreKeySignalMessage::serialize(
            Some(100),
            &base_key,
            &identity_key,
            inner_message,
            12345,
            7,
            None,
            None,
        );

        let parsed = WirePreKeySignalMessage::deserialize(&serialized).unwrap();
        assert_eq!(parsed.version, SIGNAL_MESSAGE_VERSION);
        assert_eq!(parsed.pre_key_id, Some(100));
        assert_eq!(parsed.base_key, base_key);
        assert_eq!(parsed.identity_key, identity_key);
        assert_eq!(parsed.message, inner_message);
        assert_eq!(parsed.registration_id, 12345);
        assert_eq!(parsed.signed_pre_key_id, 7);
        assert_eq!(parsed.kyber_pre_key_id, None);
        assert_eq!(parsed.kyber_ciphertext, None);
    }

    #[test]
    fn prekey_signal_message_with_kyber_roundtrip() {
        let base_key = vec![0x05; 33];
        let identity_key = vec![0x05; 33];
        let inner_message = b"inner signal message bytes";
        let kyber_ct = vec![0xAB; 1568]; // Kyber1024 ciphertext size

        let serialized = WirePreKeySignalMessage::serialize(
            Some(100),
            &base_key,
            &identity_key,
            inner_message,
            12345,
            7,
            Some(42),
            Some(&kyber_ct),
        );

        let parsed = WirePreKeySignalMessage::deserialize(&serialized).unwrap();
        assert_eq!(parsed.version, SIGNAL_MESSAGE_VERSION);
        assert_eq!(parsed.kyber_pre_key_id, Some(42));
        assert_eq!(parsed.kyber_ciphertext.as_deref(), Some(kyber_ct.as_slice()));
    }

    #[test]
    fn sender_key_message_roundtrip() {
        let dist_uuid = vec![0x42; 16];
        let ciphertext = b"group encrypted data";
        let signature = vec![0xFF; 64];

        let serialized = WireSenderKeyMessage::serialize(
            &dist_uuid,
            3,
            99,
            ciphertext,
            &signature,
        );

        let parsed = WireSenderKeyMessage::deserialize(&serialized).unwrap();
        assert_eq!(parsed.version, SIGNAL_MESSAGE_VERSION);
        assert_eq!(parsed.distribution_uuid, dist_uuid);
        assert_eq!(parsed.chain_id, 3);
        assert_eq!(parsed.iteration, 99);
        assert_eq!(parsed.ciphertext, ciphertext);
        assert_eq!(parsed.signature, signature);
    }

    #[test]
    fn signal_message_rejects_short_input() {
        assert!(WireSignalMessage::deserialize(&[0x33; 5]).is_err());
    }

    #[test]
    fn prekey_message_rejects_short_input() {
        assert!(WirePreKeySignalMessage::deserialize(&[]).is_err());
        assert!(WirePreKeySignalMessage::deserialize(&[0x33]).is_err());
    }

    #[test]
    fn sender_key_message_rejects_short_input() {
        assert!(WireSenderKeyMessage::deserialize(&[0x33; 10]).is_err());
    }

    #[test]
    fn signal_message_rejects_wrong_version() {
        // Version byte with major version != 3
        let mut data = vec![0x23]; // version 2.3
        data.extend_from_slice(&[0; 20]); // some padding + mac
        assert!(WireSignalMessage::deserialize(&data).is_err());
    }
}
