//! Sender key types for group messaging.

use serde::{Deserialize, Serialize};

/// An opaque sender key record used for efficient group message encryption.
///
/// In a full implementation this would wrap libsignal's `SenderKeyRecord`.
/// For now it stores the serialized state as raw bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKeyRecord {
    /// The serialized sender key state bytes.
    data: Vec<u8>,
}

impl SenderKeyRecord {
    /// Create a new sender key record from serialized bytes.
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Return the serialized sender key data.
    pub fn serialize(&self) -> &[u8] {
        &self.data
    }

    /// Consume the record and return the raw bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}
