//! Protocol addressing — identifies a specific device of a specific account.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::types::{DeviceId, ServiceId};

/// A protocol address uniquely identifies a particular device belonging to a
/// Signal account. It combines a [`ServiceId`] (ACI or PNI) with a
/// [`DeviceId`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtocolAddress {
    /// The account's service identifier.
    pub service_id: ServiceId,
    /// The device identifier within the account.
    pub device_id: DeviceId,
}

impl ProtocolAddress {
    /// Create a new protocol address.
    pub fn new(service_id: ServiceId, device_id: DeviceId) -> Self {
        Self {
            service_id,
            device_id,
        }
    }
}

impl fmt::Display for ProtocolAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.service_id, self.device_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn display_format() {
        let uuid = Uuid::nil();
        let addr = ProtocolAddress::new(ServiceId::aci(uuid), DeviceId(1));
        assert_eq!(
            addr.to_string(),
            "00000000-0000-0000-0000-000000000000.1"
        );
    }
}
