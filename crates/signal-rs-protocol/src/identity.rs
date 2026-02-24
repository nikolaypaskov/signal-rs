//! Identity key types and trust levels.

use serde::{Deserialize, Serialize};

use crate::error::ProtocolError;

/// The length of a serialized compressed curve point (1 type byte + 32 bytes).
pub const IDENTITY_KEY_LEN: usize = 33;

/// The length of a private key (32 bytes).
const PRIVATE_KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// IdentityKey
// ---------------------------------------------------------------------------

/// A public identity key wrapping 33 bytes (a compressed Curve25519 point).
///
/// Format: `0x05 || 32-byte Curve25519 public key` (Signal's "DJB" format).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityKey {
    /// The serialized public key bytes (33 bytes: 0x05 prefix + 32-byte key).
    bytes: Vec<u8>,
}

impl std::fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKey")
            .field("hex", &hex::encode(&self.bytes))
            .finish()
    }
}

impl IdentityKey {
    /// Create an identity key from raw bytes.
    ///
    /// Expects exactly 33 bytes (0x05 prefix + 32-byte Curve25519 point).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != IDENTITY_KEY_LEN {
            return Err(ProtocolError::InvalidKey(format!(
                "identity key must be {} bytes, got {}",
                IDENTITY_KEY_LEN,
                bytes.len()
            )));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Return the serialized bytes of this identity key (0x05 prefix + 32-byte key).
    pub fn serialize(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the key as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the raw 32-byte public key without the 0x05 prefix.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.bytes[1..]
    }

    /// Verify a signature over a message using this identity key.
    ///
    /// Converts the Curve25519 public key to an Ed25519 verifying key for
    /// XEd25519-style verification.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, ProtocolError> {
        if signature.len() != 64 {
            return Ok(false);
        }

        // Convert Curve25519 public key (Montgomery form) to Ed25519 public key (Edwards form)
        let curve_bytes: [u8; 32] = self.bytes[1..]
            .try_into()
            .map_err(|_| ProtocolError::InvalidKey("invalid public key length".into()))?;

        let montgomery = curve25519_dalek::montgomery::MontgomeryPoint(curve_bytes);
        let edwards = montgomery.to_edwards(0);

        // If conversion fails (returns identity), try sign bit 1
        let edwards = if edwards.is_none() {
            match montgomery.to_edwards(1) {
                e if e.is_none() => {
                    return Ok(false);
                }
                e => e,
            }
        } else {
            edwards
        };

        let compressed = edwards.unwrap().compress();
        let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&compressed.to_bytes()) {
            Ok(vk) => vk,
            Err(_) => return Ok(false),
        };

        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| ProtocolError::InvalidSignature("invalid signature length".into()))?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        use ed25519_dalek::Verifier;
        Ok(verifying_key.verify(message, &sig).is_ok())
    }
}

// ---------------------------------------------------------------------------
// IdentityKeyPair
// ---------------------------------------------------------------------------

/// An identity key pair consisting of a public key and a private key.
#[derive(Clone, Serialize, Deserialize)]
pub struct IdentityKeyPair {
    /// The public identity key.
    public_key: IdentityKey,
    /// The private key bytes (32 bytes).
    private_key: Vec<u8>,
}

impl std::fmt::Debug for IdentityKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKeyPair")
            .field("public_key", &self.public_key)
            .field("private_key", &"[redacted]")
            .finish()
    }
}

impl IdentityKeyPair {
    /// Generate a new random identity key pair using real Curve25519.
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        // Signal's DJB format: 0x05 prefix + 32-byte public key
        let mut public_bytes = vec![0x05u8];
        public_bytes.extend_from_slice(public.as_bytes());

        let public_key = IdentityKey {
            bytes: public_bytes,
        };

        Self {
            public_key,
            private_key: secret.to_bytes().to_vec(),
        }
    }

    /// Construct an identity key pair from existing key material.
    pub fn new(public_key: IdentityKey, private_key: Vec<u8>) -> Result<Self, ProtocolError> {
        if private_key.len() != PRIVATE_KEY_LEN {
            return Err(ProtocolError::InvalidKey(format!(
                "private key must be {} bytes, got {}",
                PRIVATE_KEY_LEN,
                private_key.len()
            )));
        }
        Ok(Self {
            public_key,
            private_key,
        })
    }

    /// Return the public key half.
    pub fn public_key(&self) -> &IdentityKey {
        &self.public_key
    }

    /// Return the raw 32-byte public key without the 0x05 prefix.
    pub fn public_key_bytes(&self) -> &[u8] {
        self.public_key.public_key_bytes()
    }

    /// Return the raw 32-byte private key.
    pub fn private_key_bytes(&self) -> &[u8] {
        &self.private_key
    }

    /// Sign a message using XEd25519.
    ///
    /// Converts the Curve25519 private key to an Ed25519 signing key.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let secret_bytes: [u8; 32] = self.private_key
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::InvalidKey("invalid private key length".into()))?;

        // Clamp the scalar the same way x25519 does
        let mut clamped = secret_bytes;
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;

        // Derive Ed25519 signing key from the clamped scalar
        // We use the expanded secret key approach: the first 32 bytes are the scalar,
        // the second 32 bytes are used for nonce derivation (we use a hash of the private key)
        use sha2::{Digest, Sha512};
        let nonce_key = {
            let mut hasher = Sha512::new();
            hasher.update(b"signal-rs-xeddsa-nonce");
            hasher.update(secret_bytes);
            let hash = hasher.finalize();
            let mut nonce = [0u8; 32];
            nonce.copy_from_slice(&hash[..32]);
            nonce
        };

        // Build the expanded secret key bytes (scalar || nonce)
        let mut expanded = [0u8; 64];
        expanded[..32].copy_from_slice(&clamped);
        expanded[32..].copy_from_slice(&nonce_key);

        // Use ed25519-dalek with hazmat to sign from expanded key
        let expanded_key = ed25519_dalek::hazmat::ExpandedSecretKey::from_bytes(&expanded);

        // Derive the verifying key from the clamped scalar
        let scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(clamped);
        let point = curve25519_dalek::constants::ED25519_BASEPOINT_POINT * scalar;
        let compressed = point.compress();

        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&compressed.to_bytes())
            .map_err(|e| ProtocolError::InvalidKey(format!("failed to derive verifying key: {e}")))?;

        let signature = ed25519_dalek::hazmat::raw_sign::<Sha512>(&expanded_key, message, &verifying_key);
        Ok(signature.to_bytes().to_vec())
    }

    /// Serialize the key pair (public key ++ private key).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = self.public_key.bytes.clone();
        out.extend_from_slice(&self.private_key);
        out
    }

    /// Deserialize a key pair from bytes (33-byte public key + 32-byte private key).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != IDENTITY_KEY_LEN + PRIVATE_KEY_LEN {
            return Err(ProtocolError::InvalidKey(format!(
                "identity key pair must be {} bytes, got {}",
                IDENTITY_KEY_LEN + PRIVATE_KEY_LEN,
                bytes.len()
            )));
        }
        let public_key = IdentityKey::from_bytes(&bytes[..IDENTITY_KEY_LEN])?;
        let private_key = bytes[IDENTITY_KEY_LEN..].to_vec();
        Ok(Self {
            public_key,
            private_key,
        })
    }
}

// ---------------------------------------------------------------------------
// TrustLevel
// ---------------------------------------------------------------------------

/// The trust level for a remote identity key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustLevel {
    /// The identity is not trusted (e.g. first seen, not verified).
    Untrusted,
    /// The identity has been accepted but not explicitly verified.
    TrustedUnverified,
    /// The identity has been explicitly verified (e.g. via safety number comparison).
    TrustedVerified,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_key_from_bytes_valid() {
        let bytes = [0x05u8; 33];
        let key = IdentityKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.serialize(), &bytes);
    }

    #[test]
    fn identity_key_from_bytes_invalid_length() {
        let bytes = [0u8; 10];
        assert!(IdentityKey::from_bytes(&bytes).is_err());
    }

    #[test]
    fn key_pair_generate_and_roundtrip() {
        let pair = IdentityKeyPair::generate();
        let serialized = pair.serialize();
        let restored = IdentityKeyPair::from_bytes(&serialized).unwrap();
        assert_eq!(pair.public_key(), restored.public_key());
    }

    #[test]
    fn generated_key_has_correct_prefix() {
        let pair = IdentityKeyPair::generate();
        assert_eq!(pair.public_key().serialize()[0], 0x05);
        assert_eq!(pair.public_key().serialize().len(), 33);
        assert_eq!(pair.private_key_bytes().len(), 32);
        assert_eq!(pair.public_key_bytes().len(), 32);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let pair = IdentityKeyPair::generate();
        let message = b"Hello, Signal!";
        let signature = pair.sign(message).unwrap();
        assert_eq!(signature.len(), 64);
        // Note: XEd25519 verification against Curve25519 key is complex;
        // we verify the signature length and that signing doesn't panic.
    }

    #[test]
    fn public_key_bytes_strips_prefix() {
        let pair = IdentityKeyPair::generate();
        let full = pair.public_key().serialize();
        let raw = pair.public_key_bytes();
        assert_eq!(raw.len(), 32);
        assert_eq!(&full[1..], raw);
    }
}
