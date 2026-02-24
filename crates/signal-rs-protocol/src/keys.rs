//! Pre-key, signed pre-key, and Kyber pre-key types and generation functions.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::identity::{IdentityKey, IdentityKeyPair};
use crate::types::DeviceId;

/// Maximum number of pre-keys to generate in a single batch.
pub const PREKEY_BATCH_SIZE: u32 = 100;

/// Maximum pre-key ID value (wraps around after this).
pub const PREKEY_MAXIMUM_ID: u32 = 0x7FFFFE;

// ---------------------------------------------------------------------------
// Key ID wrappers
// ---------------------------------------------------------------------------

/// Identifier for a one-time pre-key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PreKeyId(pub u32);

impl fmt::Display for PreKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for PreKeyId {
    fn from(id: u32) -> Self {
        PreKeyId(id)
    }
}

/// Identifier for a signed pre-key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SignedPreKeyId(pub u32);

impl fmt::Display for SignedPreKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for SignedPreKeyId {
    fn from(id: u32) -> Self {
        SignedPreKeyId(id)
    }
}

/// Identifier for a Kyber (post-quantum) pre-key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct KyberPreKeyId(pub u32);

impl fmt::Display for KyberPreKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for KyberPreKeyId {
    fn from(id: u32) -> Self {
        KyberPreKeyId(id)
    }
}

// ---------------------------------------------------------------------------
// Pre-key records
// ---------------------------------------------------------------------------

/// A one-time pre-key record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyRecord {
    /// The pre-key identifier.
    pub id: PreKeyId,
    /// The public key bytes.
    pub public_key: Vec<u8>,
    /// The private key bytes.
    pub private_key: Vec<u8>,
}

/// A signed pre-key record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPreKeyRecord {
    /// The signed pre-key identifier.
    pub id: SignedPreKeyId,
    /// The public key bytes.
    pub public_key: Vec<u8>,
    /// The private key bytes.
    pub private_key: Vec<u8>,
    /// Signature over the public key, produced by the identity key.
    pub signature: Vec<u8>,
    /// Unix timestamp (in milliseconds) when this key was generated.
    pub timestamp: u64,
}

/// A Kyber (post-quantum) pre-key record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyberPreKeyRecord {
    /// The Kyber pre-key identifier.
    pub id: KyberPreKeyId,
    /// The serialized key pair (encapsulation + decapsulation keys).
    pub key_pair_serialized: Vec<u8>,
    /// Signature over the public portion, produced by the identity key.
    pub signature: Vec<u8>,
    /// Unix timestamp (in milliseconds) when this key was generated.
    pub timestamp: u64,
    /// Whether this is a "last resort" key that is never deleted.
    pub is_last_resort: bool,
}

// ---------------------------------------------------------------------------
// Pre-key bundle (used during session setup)
// ---------------------------------------------------------------------------

/// A bundle of public pre-key material, used by the initiator to establish a
/// new session with a remote device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    /// The remote device's registration ID.
    pub registration_id: u32,
    /// The remote device ID.
    pub device_id: DeviceId,
    /// Optional one-time pre-key (id + public key bytes).
    pub pre_key: Option<(PreKeyId, Vec<u8>)>,
    /// The signed pre-key (id + public key bytes + signature).
    pub signed_pre_key: (SignedPreKeyId, Vec<u8>, Vec<u8>),
    /// The remote identity key.
    pub identity_key: IdentityKey,
    /// Optional Kyber pre-key (id + public key bytes + signature).
    pub kyber_pre_key: Option<(KyberPreKeyId, Vec<u8>, Vec<u8>)>,
}

// ---------------------------------------------------------------------------
// Key generation functions
// ---------------------------------------------------------------------------

/// Generate a random registration ID in the range `[1, 16380]`.
pub fn generate_registration_id() -> u32 {
    use rand::Rng;
    rand::thread_rng().gen_range(1..=16380)
}

/// Generate a batch of one-time Curve25519 pre-keys.
pub fn generate_pre_keys(start_id: u32, count: u32) -> Vec<PreKeyRecord> {
    use rand::rngs::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    let mut keys = Vec::with_capacity(count as usize);
    for i in 0..count {
        let id = (start_id + i) % (PREKEY_MAXIMUM_ID + 1);
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        // Signal's serialized EC public key: 0x05 prefix + 32 bytes
        let mut serialized_public = Vec::with_capacity(33);
        serialized_public.push(0x05);
        serialized_public.extend_from_slice(public.as_bytes());

        keys.push(PreKeyRecord {
            id: PreKeyId(id),
            public_key: serialized_public,
            private_key: secret.to_bytes().to_vec(),
        });
    }
    keys
}

/// Generate a signed pre-key: a Curve25519 keypair signed by the identity key.
pub fn generate_signed_pre_key(
    id: u32,
    identity: &IdentityKeyPair,
) -> SignedPreKeyRecord {
    use rand::rngs::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    // Signal's serialized EC public key: 0x05 prefix + 32 bytes
    let mut serialized_public = Vec::with_capacity(33);
    serialized_public.push(0x05);
    serialized_public.extend_from_slice(public.as_bytes());

    // Signature is over the serialized (prefixed) public key
    let signature = identity.sign(&serialized_public).unwrap_or_default();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    SignedPreKeyRecord {
        id: SignedPreKeyId(id),
        public_key: serialized_public,
        private_key: secret.to_bytes().to_vec(),
        signature,
        timestamp,
    }
}

/// Generate a Kyber pre-key using real ML-KEM-1024 (Kyber1024) from libsignal.
///
/// Generates a real Kyber1024 key pair using libsignal-protocol's KEM
/// implementation, then signs the serialized public key with the identity key.
pub fn generate_kyber_pre_key(
    id: u32,
    identity: &IdentityKeyPair,
    is_last_resort: bool,
) -> KyberPreKeyRecord {
    use libsignal_protocol::kem;

    // libsignal-protocol's KEM requires rand 0.9 CryptoRng trait.
    // We use rand 0.9's thread_rng which satisfies that bound.
    let mut csprng = rand_09::rng();
    let key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut csprng);

    let public_key_bytes = key_pair.public_key.serialize();
    let secret_key_bytes = key_pair.secret_key.serialize();

    // Concatenate public + secret for storage (public first, then secret)
    let mut key_pair_serialized = Vec::with_capacity(public_key_bytes.len() + secret_key_bytes.len());
    key_pair_serialized.extend_from_slice(&public_key_bytes);
    key_pair_serialized.extend_from_slice(&secret_key_bytes);

    // Sign the serialized public key with the identity key
    let signature = identity.sign(&public_key_bytes).unwrap_or_default();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    KyberPreKeyRecord {
        id: KyberPreKeyId(id),
        key_pair_serialized,
        signature,
        timestamp,
        is_last_resort,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_registration_id_in_range() {
        for _ in 0..100 {
            let id = generate_registration_id();
            assert!((1..=16380).contains(&id), "registration id {id} out of range");
        }
    }

    #[test]
    fn generate_pre_keys_batch() {
        let keys = generate_pre_keys(1, 10);
        assert_eq!(keys.len(), 10);
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(key.id.0, (i + 1) as u32);
            assert_eq!(key.public_key.len(), 33); // 0x05 prefix + 32 bytes
            assert_eq!(key.private_key.len(), 32);
        }
    }

    #[test]
    fn generate_pre_keys_wraps_around() {
        let keys = generate_pre_keys(PREKEY_MAXIMUM_ID, 3);
        assert_eq!(keys[0].id.0, PREKEY_MAXIMUM_ID);
        assert_eq!(keys[1].id.0, 0);
        assert_eq!(keys[2].id.0, 1);
    }

    #[test]
    fn generate_signed_pre_key_has_signature() {
        let identity = IdentityKeyPair::generate();
        let spk = generate_signed_pre_key(1, &identity);
        assert_eq!(spk.id.0, 1);
        assert_eq!(spk.public_key.len(), 33); // 0x05 prefix + 32 bytes
        assert_eq!(spk.private_key.len(), 32);
        assert_eq!(spk.signature.len(), 64);
        assert!(spk.timestamp > 0);
    }

    #[test]
    fn generate_kyber_pre_key_has_correct_sizes() {
        let identity = IdentityKeyPair::generate();
        let kpk = generate_kyber_pre_key(1, &identity, true);
        assert_eq!(kpk.id.0, 1);
        // Real Kyber1024: public key is 1569 bytes (1 type byte + 1568),
        // secret key is 3169 bytes (1 type byte + 3168). Total = 4738.
        assert!(kpk.key_pair_serialized.len() > 4000, "key pair should be large (got {})", kpk.key_pair_serialized.len());
        assert_eq!(kpk.signature.len(), 64);
        assert!(kpk.is_last_resort);
    }

    #[test]
    fn kyber_pre_key_public_key_is_valid() {
        use libsignal_protocol::kem;

        let identity = IdentityKeyPair::generate();
        let kpk = generate_kyber_pre_key(1, &identity, false);

        // The public key portion should be deserializable
        // Public key is stored first in key_pair_serialized (1569 bytes for Kyber1024)
        let public_key = kem::PublicKey::deserialize(&kpk.key_pair_serialized[..1569])
            .expect("public key should be deserializable");
        assert_eq!(public_key.key_type(), kem::KeyType::Kyber1024);
    }
}
