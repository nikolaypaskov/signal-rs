//! Recipient update job.
//!
//! Updates recipient information (registration status, profile keys, etc.)
//! when changes are detected. Triggered when:
//! - An unregistered delivery receipt is received
//! - A new message reveals updated recipient info
//! - A periodic check for stale recipient data

use crate::error::Result;
use crate::jobs::Job;

/// Job that updates recipient information.
pub struct RecipientUpdateJob;

impl Job for RecipientUpdateJob {
    fn name(&self) -> &'static str {
        "recipient-update"
    }

    async fn execute(&self) -> Result<()> {
        tracing::info!("running recipient update job");

        // Recipient updates are typically triggered when:
        // - An unregistered delivery receipt is received
        // - A new message reveals updated recipient info (e.g., new identity key)
        // The job processes any queued recipient state changes.
        // Actual processing requires manager context; this will be wired in
        // when the job scheduler is integrated.
        tracing::debug!("recipient update job: no pending updates");

        tracing::info!("recipient update job completed");
        Ok(())
    }
}
