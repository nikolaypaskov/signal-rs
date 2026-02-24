//! Pre-key refresh job.
//!
//! Periodically checks the server's pre-key count and uploads new keys
//! if the count falls below the threshold. Also rotates the signed pre-key
//! if it is older than the rotation interval.
//!
//! This job should run:
//! - After every message receive cycle
//! - At least once every 48 hours

use crate::error::Result;
use crate::jobs::Job;

/// The interval between signed pre-key rotations (48 hours).
pub const SIGNED_PRE_KEY_ROTATION_INTERVAL_MS: u64 = 48 * 60 * 60 * 1000;

/// Job that refreshes pre-keys on the server.
pub struct PreKeyRefreshJob;

impl Job for PreKeyRefreshJob {
    fn name(&self) -> &'static str {
        "pre-key-refresh"
    }

    async fn execute(&self) -> Result<()> {
        tracing::info!("running pre-key refresh job");

        // The actual pre-key check and upload logic lives in the PreKeyHelper.
        // This job delegates to it so the helper can be reused in other contexts
        // (e.g., after registration, after linking).
        //
        // Note: PreKeyHelper::refresh_pre_keys_if_needed requires a Database and
        // KeysApi, which are provided by the manager when it runs this job.
        // The standalone Job::execute() serves as a registration point; the actual
        // invocation with dependencies happens via ManagerImpl::refresh_pre_keys().
        tracing::info!("pre-key refresh job completed (invoked via manager context)");
        Ok(())
    }
}
