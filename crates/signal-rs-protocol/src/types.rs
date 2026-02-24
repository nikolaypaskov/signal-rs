//! Core type definitions used throughout the protocol layer.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

use crate::error::ProtocolError;

// ---------------------------------------------------------------------------
// ServiceIdKind
// ---------------------------------------------------------------------------

/// Discriminates between the two kinds of service identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceIdKind {
    /// Account Identity – the primary, stable identifier.
    Aci,
    /// Phone Number Identity – derived from the phone number.
    Pni,
}

impl fmt::Display for ServiceIdKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceIdKind::Aci => write!(f, "ACI"),
            ServiceIdKind::Pni => write!(f, "PNI"),
        }
    }
}

// ---------------------------------------------------------------------------
// ServiceId
// ---------------------------------------------------------------------------

/// A service identifier that wraps a UUID and a kind discriminator.
///
/// In the Signal protocol every account has two service IDs:
/// - An ACI (Account Identity) that is stable across phone-number changes.
/// - A PNI (Phone Number Identity) that is derived from the phone number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServiceId {
    /// The underlying UUID value.
    pub uuid: Uuid,
    /// Whether this is an ACI or PNI.
    pub kind: ServiceIdKind,
}

impl ServiceId {
    /// Create a new ACI-typed service identifier.
    pub fn aci(uuid: Uuid) -> Self {
        Self {
            uuid,
            kind: ServiceIdKind::Aci,
        }
    }

    /// Create a new PNI-typed service identifier.
    pub fn pni(uuid: Uuid) -> Self {
        Self {
            uuid,
            kind: ServiceIdKind::Pni,
        }
    }

    /// Parse from a raw UUID (defaults to ACI).
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self::aci(uuid)
    }

    /// Returns the raw UUID bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.uuid.as_bytes()
    }
}

impl fmt::Display for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ServiceIdKind::Aci => write!(f, "{}", self.uuid),
            ServiceIdKind::Pni => write!(f, "PNI:{}", self.uuid),
        }
    }
}

impl FromStr for ServiceId {
    type Err = ProtocolError;

    /// Parse a service ID from a string.
    ///
    /// Accepted formats:
    /// - `"<uuid>"` — interpreted as ACI
    /// - `"PNI:<uuid>"` — interpreted as PNI
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("PNI:") {
            let uuid = Uuid::parse_str(rest)
                .map_err(|e| ProtocolError::InvalidMessage(format!("invalid PNI UUID: {e}")))?;
            Ok(ServiceId::pni(uuid))
        } else {
            let uuid = Uuid::parse_str(s)
                .map_err(|e| ProtocolError::InvalidMessage(format!("invalid UUID: {e}")))?;
            Ok(ServiceId::aci(uuid))
        }
    }
}

impl From<Uuid> for ServiceId {
    fn from(uuid: Uuid) -> Self {
        ServiceId::aci(uuid)
    }
}

// ---------------------------------------------------------------------------
// DeviceId
// ---------------------------------------------------------------------------

/// A device identifier (u32 wrapper).
///
/// Each Signal account can have multiple linked devices, each with a unique
/// device ID. The primary device is typically device 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceId(pub u32);

impl DeviceId {
    /// The default device ID for the primary device.
    pub const PRIMARY: DeviceId = DeviceId(1);

    /// Returns the raw u32 value.
    pub fn value(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for DeviceId {
    fn from(id: u32) -> Self {
        DeviceId(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_id_roundtrip() {
        let uuid = Uuid::new_v4();
        let aci = ServiceId::aci(uuid);
        let parsed: ServiceId = aci.to_string().parse().unwrap();
        assert_eq!(aci, parsed);

        let pni = ServiceId::pni(uuid);
        let parsed: ServiceId = pni.to_string().parse().unwrap();
        assert_eq!(pni, parsed);
    }

    #[test]
    fn device_id_primary() {
        assert_eq!(DeviceId::PRIMARY.value(), 1);
    }
}
