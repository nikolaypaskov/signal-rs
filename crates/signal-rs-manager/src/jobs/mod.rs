//! Background jobs — periodic and event-driven tasks.
//!
//! Jobs are triggered either periodically (e.g., pre-key refresh every 48h)
//! or in response to events (e.g., profile download after receiving a message
//! from a new contact).

pub mod expiration;
pub mod pre_key_refresh;
pub mod profile_download;
pub mod scheduler;
pub mod storage_sync;
pub mod recipient_update;

use crate::error::Result;

/// A background job that can be executed by the manager.
pub trait Job {
    /// A human-readable name for this job (used in logging).
    fn name(&self) -> &'static str;

    /// Execute the job.
    ///
    /// Returns `Ok(())` if the job completed successfully, or an error.
    /// Jobs should be idempotent — running them multiple times should be safe.
    fn execute(&self) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Whether this job should run now based on the last execution time.
    ///
    /// Returns `true` if the job is due for execution.
    fn should_run(&self) -> bool {
        true
    }
}
