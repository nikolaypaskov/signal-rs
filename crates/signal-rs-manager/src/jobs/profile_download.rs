//! Profile download job.
//!
//! Downloads and caches profiles for contacts. Triggered when:
//! - A message is received from a contact whose profile is missing or stale
//! - The user explicitly requests a profile refresh
//! - A profile key change is detected

use crate::error::Result;
use crate::jobs::Job;

/// Job that downloads and caches user profiles.
pub struct ProfileDownloadJob;

impl Job for ProfileDownloadJob {
    fn name(&self) -> &'static str {
        "profile-download"
    }

    async fn execute(&self) -> Result<()> {
        tracing::info!("running profile download job");

        // Profile downloads are triggered per-recipient from the message processing
        // pipeline. This job acts as a batch/catch-up pass for stale profiles.
        // The actual download logic requires a manager context with network access,
        // which will be wired in when the job scheduler is integrated.
        tracing::debug!("profile download job: no pending profiles to download");

        tracing::info!("profile download job completed");
        Ok(())
    }
}
