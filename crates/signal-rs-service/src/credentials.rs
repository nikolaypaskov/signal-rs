//! Service authentication credentials.
//!
//! Signal uses HTTP Basic authentication for most authenticated endpoints.
//! The username is `<uuid>.<device_id>` (or just `<uuid>` for the primary device)
//! and the password is an opaque server-generated token.

use std::fmt;

use base64::Engine;
use uuid::Uuid;

use signal_rs_protocol::DeviceId;

/// Credentials used to authenticate with the Signal service.
#[derive(Clone)]
pub struct ServiceCredentials {
    /// The account's ACI (Account Identity) UUID.
    pub uuid: Option<Uuid>,

    /// The account's E.164 phone number (e.g., "+15551234567").
    pub e164: Option<String>,

    /// The password / auth token for this device.
    pub password: Option<String>,

    /// The device ID. Primary device is 1; linked devices get assigned IDs.
    pub device_id: DeviceId,
}

impl fmt::Debug for ServiceCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceCredentials")
            .field("uuid", &self.uuid)
            .field("e164", &self.e164)
            .field("password", &"[REDACTED]")
            .field("device_id", &self.device_id)
            .finish()
    }
}

impl ServiceCredentials {
    /// Build the HTTP Basic Authorization header value.
    ///
    /// Returns `None` if uuid or password is missing.
    pub fn authorization(&self) -> Option<AuthorizationPair> {
        let uuid = self.uuid?;
        let password = self.password.as_ref()?;
        Some(AuthorizationPair::new(uuid, self.device_id, password))
    }

    /// Returns the username portion: `<uuid>` or `<uuid>.<device_id>`.
    pub fn username(&self) -> Option<String> {
        let uuid = self.uuid?;
        if self.device_id == DeviceId::PRIMARY {
            Some(uuid.to_string())
        } else {
            Some(format!("{}.{}", uuid, self.device_id))
        }
    }
}

/// An HTTP Basic authorization pair, pre-encoded for use in headers.
#[derive(Clone)]
pub struct AuthorizationPair {
    /// The raw username (uuid.device_id).
    pub username: String,
    /// The raw password.
    pub password: String,
    /// The base64-encoded "username:password" value for the Authorization header.
    pub encoded: String,
}

impl fmt::Debug for AuthorizationPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationPair")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("encoded", &"[REDACTED]")
            .finish()
    }
}

impl AuthorizationPair {
    /// Create a new authorization pair.
    pub fn new(uuid: Uuid, device_id: DeviceId, password: &str) -> Self {
        let username = if device_id == DeviceId::PRIMARY {
            uuid.to_string()
        } else {
            format!("{uuid}.{device_id}")
        };

        let raw = format!("{username}:{password}");
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());

        Self {
            username,
            password: password.to_string(),
            encoded,
        }
    }

    /// Return the full header value: `"Basic <encoded>"`.
    pub fn as_header_value(&self) -> String {
        format!("Basic {}", self.encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_pair_encodes_correctly() {
        let uuid = Uuid::nil();
        let pair = AuthorizationPair::new(uuid, DeviceId::PRIMARY, "secret");
        assert!(pair.as_header_value().starts_with("Basic "));
        assert_eq!(
            pair.username,
            "00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn linked_device_username_includes_device_id() {
        let uuid = Uuid::nil();
        let pair = AuthorizationPair::new(uuid, DeviceId(2), "pw");
        assert!(pair.username.ends_with(".2"));
    }
}
