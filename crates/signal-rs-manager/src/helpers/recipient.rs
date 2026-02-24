//! Recipient helper -- contact discovery and recipient resolution.
//!
//! Responsible for:
//! - Resolving RecipientIdentifier to protocol addresses (ACI + device list)
//! - Looking up users via CDSI (Contact Discovery Service)
//! - Caching recipient information
//! - Managing the local recipient database

use uuid::Uuid;

use tracing::{debug, info, warn};

use signal_rs_protocol::ServiceId;
use signal_rs_protocol::stores::SessionStore;
use signal_rs_service::api::cds::CdsApi;
use signal_rs_store::Database;

use crate::error::{ManagerError, Result};
use crate::types::RecipientIdentifier;

/// Normalize a phone number to E.164 format.
///
/// Strips whitespace, dashes, dots, parentheses, and ensures the number
/// starts with a `+` prefix.
///
/// # Examples
///
/// ```
/// use signal_rs_manager::helpers::recipient::normalize_phone_number;
///
/// assert_eq!(normalize_phone_number("+1 (555) 123-4567"), "+15551234567");
/// assert_eq!(normalize_phone_number("15551234567"), "+15551234567");
/// assert_eq!(normalize_phone_number("+44.20.7946.0958"), "+442079460958");
/// ```
pub fn normalize_phone_number(number: &str) -> String {
    // Strip all non-digit characters except leading +
    let mut result = String::with_capacity(number.len());
    let trimmed = number.trim();

    for (i, ch) in trimmed.chars().enumerate() {
        if ch == '+' && i == 0 {
            result.push('+');
        } else if ch.is_ascii_digit() {
            result.push(ch);
        }
        // Skip spaces, dashes, dots, parentheses, etc.
    }

    // Ensure the number starts with +
    if !result.starts_with('+') {
        result.insert(0, '+');
    }

    result
}

/// Helper for recipient resolution.
#[derive(Default)]
pub struct RecipientHelper;

impl RecipientHelper {
    /// Create a new recipient helper.
    pub fn new() -> Self {
        Self
    }

    /// Resolve a recipient identifier to an ACI UUID.
    ///
    /// For phone numbers, this first checks the local store, then falls back
    /// to a CDSI (Contact Discovery Service) lookup if available.
    pub async fn resolve_to_uuid(
        &self,
        db: &Database,
        recipient: &RecipientIdentifier,
    ) -> Result<Uuid> {
        debug!(%recipient, "resolving recipient to UUID");

        match recipient {
            RecipientIdentifier::Uuid(uuid) => {
                debug!(%uuid, "recipient is already a UUID");
                Ok(*uuid)
            }
            RecipientIdentifier::PhoneNumber(number) => {
                // Normalize the phone number to E.164 before lookup
                let normalized = normalize_phone_number(number);
                let number = &normalized;

                // Look up in local store first
                if let Some(r) = db.get_recipient_by_number(number)?
                    && let Some(ref aci) = r.aci
                        && let Ok(uuid) = Uuid::parse_str(aci) {
                            debug!(%number, %uuid, "resolved phone number from local store");
                            return Ok(uuid);
                        }
                // Not in local store — create a local entry for future use
                let _r = db.get_or_create_recipient_by_number(number)?;
                debug!(%number, "phone number not in local store, CDSI lookup needed");
                Err(ManagerError::Other(format!(
                    "phone number {number} not found in local store. \
                     Use discover_contacts() to perform a CDSI lookup first."
                )))
            }
            RecipientIdentifier::Username(username) => {
                // Look up in local store
                if let Some(r) = db.get_recipient_by_username(username)?
                    && let Some(ref aci) = r.aci
                        && let Ok(uuid) = Uuid::parse_str(aci) {
                            debug!(%username, %uuid, "resolved username from local store");
                            return Ok(uuid);
                        }
                Err(ManagerError::Other(format!(
                    "username {username} not found in local store"
                )))
            }
        }
    }

    /// Resolve a phone number to an ACI UUID, performing a CDSI lookup if needed.
    ///
    /// This method first checks the local store. If the number is not found,
    /// it calls CDSI to discover the ACI, updates the local store, and returns
    /// the resolved UUID.
    pub async fn resolve_phone_number_via_cdsi(
        &self,
        db: &Database,
        cds_api: &CdsApi<'_>,
        phone_number: &str,
    ) -> Result<Uuid> {
        let normalized = normalize_phone_number(phone_number);

        // Check local store first
        if let Some(r) = db.get_recipient_by_number(&normalized)?
            && let Some(ref aci) = r.aci
                && let Ok(uuid) = Uuid::parse_str(aci) {
                    debug!(%normalized, %uuid, "resolved phone number from local store");
                    return Ok(uuid);
                }

        // Not found locally — perform CDSI lookup
        info!(%normalized, "performing CDSI lookup for phone number");
        self.discover_contacts(db, cds_api, std::slice::from_ref(&normalized)).await?;

        // Check the store again after CDSI discovery
        if let Some(r) = db.get_recipient_by_number(&normalized)?
            && let Some(ref aci) = r.aci
                && let Ok(uuid) = Uuid::parse_str(aci) {
                    info!(%normalized, %uuid, "resolved phone number via CDSI");
                    return Ok(uuid);
                }

        Err(ManagerError::Other(format!(
            "phone number {normalized} could not be resolved via CDSI — \
             the number may not be registered on Signal"
        )))
    }

    /// Get the device IDs for a recipient.
    ///
    /// Looks up existing sessions in the store to determine known device IDs.
    /// Always includes the primary device (device ID 1).
    pub async fn get_device_ids(&self, db: &Database, uuid: &Uuid) -> Result<Vec<u32>> {
        debug!(%uuid, "getting device IDs");

        let service_id = ServiceId::aci(*uuid);

        // Get sub-device sessions (device IDs other than 1)
        let sub_devices = db.get_sub_device_sessions(&service_id)
            .map_err(|e| ManagerError::Other(format!("failed to get device sessions: {e}")))?;

        // Always include the primary device
        let mut device_ids = vec![1u32];
        for device_id in sub_devices {
            device_ids.push(device_id.value());
        }

        debug!(%uuid, device_count = device_ids.len(), "resolved device IDs");
        Ok(device_ids)
    }

    /// Look up phone numbers via CDSI and update the local store.
    ///
    /// Performs a CDSI WebSocket lookup, then stores discovered ACI/PNI
    /// mappings in the local recipient database. If CDSI is unreachable,
    /// the numbers are still stored locally for future resolution.
    pub async fn discover_contacts(
        &self,
        db: &Database,
        cds_api: &CdsApi<'_>,
        numbers: &[String],
    ) -> Result<()> {
        debug!(count = numbers.len(), "discovering contacts via CDSI");

        match cds_api.lookup(numbers, None).await {
            Ok((results, _token)) => {
                for result in results {
                    if let Some(aci) = result.aci {
                        // Create or update the recipient in the store
                        let r = db.get_or_create_recipient_by_number(&result.e164)?;
                        let mut r = r;
                        r.aci = Some(aci.to_string());
                        if let Some(pni) = result.pni {
                            r.pni = Some(pni.to_string());
                        }
                        db.update_recipient(&r)?;
                        info!(e164 = %result.e164, %aci, "discovered contact");
                    }
                }
                Ok(())
            }
            Err(e) => {
                warn!(error = %e, "CDSI lookup failed");
                // Store the numbers locally so they can be resolved in a future attempt.
                for number in numbers {
                    let _r = db.get_or_create_recipient_by_number(number)?;
                    debug!(%number, "created local recipient entry (CDSI lookup failed)");
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_e164_already_valid() {
        assert_eq!(normalize_phone_number("+15551234567"), "+15551234567");
    }

    #[test]
    fn normalize_strips_spaces_and_dashes() {
        assert_eq!(normalize_phone_number("+1 555-123-4567"), "+15551234567");
    }

    #[test]
    fn normalize_strips_parentheses() {
        assert_eq!(normalize_phone_number("+1 (555) 123-4567"), "+15551234567");
    }

    #[test]
    fn normalize_adds_plus_prefix() {
        assert_eq!(normalize_phone_number("15551234567"), "+15551234567");
    }

    #[test]
    fn normalize_strips_dots() {
        assert_eq!(normalize_phone_number("+44.20.7946.0958"), "+442079460958");
    }

    #[test]
    fn normalize_handles_leading_whitespace() {
        assert_eq!(normalize_phone_number("  +15551234567  "), "+15551234567");
    }

    #[test]
    fn normalize_digits_only_no_plus() {
        assert_eq!(normalize_phone_number("442079460958"), "+442079460958");
    }

    #[test]
    fn normalize_empty_string() {
        assert_eq!(normalize_phone_number(""), "+");
    }

    #[test]
    fn normalize_plus_only() {
        assert_eq!(normalize_phone_number("+"), "+");
    }
}
