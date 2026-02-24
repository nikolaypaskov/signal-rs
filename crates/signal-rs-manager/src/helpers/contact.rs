//! Contact helper -- contact management operations.
//!
//! Responsible for:
//! - Looking up contacts by phone number, UUID, or username
//! - Setting contact names and blocked status
//! - Managing the block list
//! - Contact sync with the storage service

use tracing::{debug, info, warn};

use signal_rs_store::Database;

use crate::error::{ManagerError, Result};
use crate::types::RecipientIdentifier;

/// Helper for contact operations.
#[derive(Default)]
pub struct ContactHelper;

impl ContactHelper {
    /// Create a new contact helper.
    pub fn new() -> Self {
        Self
    }

    /// Resolve a RecipientIdentifier to a store recipient, returning its row id.
    fn resolve_recipient_id(
        db: &Database,
        recipient: &RecipientIdentifier,
    ) -> Result<i64> {
        match recipient {
            RecipientIdentifier::Uuid(uuid) => {
                let r = db.get_recipient_by_aci(&uuid.to_string())?
                    .ok_or_else(|| ManagerError::Other(format!(
                        "recipient not found for UUID {uuid}"
                    )))?;
                Ok(r.id)
            }
            RecipientIdentifier::PhoneNumber(number) => {
                let r = db.get_recipient_by_number(number)?
                    .ok_or_else(|| ManagerError::Other(format!(
                        "recipient not found for number {number}"
                    )))?;
                Ok(r.id)
            }
            RecipientIdentifier::Username(username) => {
                let r = db.get_recipient_by_username(username)?
                    .ok_or_else(|| ManagerError::Other(format!(
                        "recipient not found for username {username}"
                    )))?;
                Ok(r.id)
            }
        }
    }

    /// Set a contact's display name.
    pub async fn set_name(
        &self,
        db: &Database,
        recipient: &RecipientIdentifier,
        given_name: &str,
        family_name: Option<&str>,
    ) -> Result<()> {
        debug!(%recipient, given_name, ?family_name, "setting contact name");

        let recipient_id = Self::resolve_recipient_id(db, recipient)?;
        let mut r = db.get_recipient_by_id(recipient_id)?
            .ok_or_else(|| ManagerError::Other("recipient not found".into()))?;

        r.given_name = Some(given_name.to_string());
        r.family_name = family_name.map(|s| s.to_string());
        db.update_recipient(&r)?;

        info!(%recipient, "contact name updated");
        Ok(())
    }

    /// Block or unblock a list of contacts.
    pub async fn set_blocked(
        &self,
        db: &Database,
        recipients: &[RecipientIdentifier],
        blocked: bool,
    ) -> Result<()> {
        debug!(count = recipients.len(), blocked, "setting blocked status");

        for recipient in recipients {
            match Self::resolve_recipient_id(db, recipient) {
                Ok(recipient_id) => {
                    db.set_recipient_blocked(recipient_id, blocked)?;
                    debug!(%recipient, blocked, "updated blocked status");
                }
                Err(e) => {
                    warn!(%recipient, error = %e, "failed to resolve recipient for blocking");
                }
            }
        }

        info!(count = recipients.len(), blocked, "blocked status updated");
        Ok(())
    }

    /// Set the disappearing messages timer for a 1:1 conversation.
    pub async fn set_expiration_timer(
        &self,
        db: &Database,
        recipient: &RecipientIdentifier,
        seconds: u32,
    ) -> Result<()> {
        debug!(%recipient, seconds, "setting expiration timer");

        let recipient_id = Self::resolve_recipient_id(db, recipient)?;
        let timer = if seconds == 0 { None } else { Some(seconds as i64) };
        db.set_recipient_expiration(recipient_id, timer)?;

        info!(%recipient, seconds, "expiration timer updated");
        Ok(())
    }
}
