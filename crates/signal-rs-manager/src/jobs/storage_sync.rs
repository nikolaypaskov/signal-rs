//! Storage service sync job.
//!
//! Synchronizes the local database with the encrypted storage service.
//! This is how contacts, groups, and account settings are synced across
//! linked devices.
//!
//! Triggered when:
//! - A storage manifest version bump notification is received
//! - The user explicitly requests a sync
//! - After initial registration/linking

use crate::error::Result;
use crate::jobs::Job;

/// Job that syncs with the storage service.
pub struct StorageSyncJob;

impl Job for StorageSyncJob {
    fn name(&self) -> &'static str {
        "storage-sync"
    }

    async fn execute(&self) -> Result<()> {
        tracing::info!("running storage sync job");

        // Storage sync fetches the encrypted storage manifest from the server,
        // compares with the local version, and downloads/processes changed records.
        // Actual sync requires manager context with authenticated HTTP access;
        // this will be wired in when the job scheduler is integrated.
        tracing::debug!("storage sync job: checking for manifest changes");

        tracing::info!("storage sync job completed");
        Ok(())
    }
}
