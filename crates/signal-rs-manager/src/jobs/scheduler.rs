//! Background job scheduler.
//!
//! Provides a simple tokio interval-based scheduler that runs periodic jobs
//! such as pre-key refresh and signed pre-key rotation.
//!
//! Because `Database` (rusqlite) is not `Send`, the scheduler uses a
//! channel-based design: it sends tick notifications and the caller
//! runs the actual refresh on its own task/thread.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tracing::{debug, info};

use signal_rs_service::api::keys::KeysApi;
use signal_rs_store::Database;

use crate::helpers::pre_key::PreKeyHelper;

/// Default interval between pre-key refresh checks (2 hours).
pub const PRE_KEY_REFRESH_INTERVAL: Duration = Duration::from_secs(2 * 60 * 60);

/// A handle to a running scheduler that can be used to stop it.
#[derive(Clone)]
pub struct SchedulerHandle {
    shutdown: Arc<Notify>,
}

impl Default for SchedulerHandle {
    fn default() -> Self {
        Self {
            shutdown: Arc::new(Notify::new()),
        }
    }
}

impl SchedulerHandle {
    /// Create a new scheduler handle (for use with `run_scheduler_loop`).
    pub fn new() -> Self {
        Self {
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Signal the scheduler to stop.
    pub fn stop(&self) {
        self.shutdown.notify_one();
    }

    /// Get a reference to the shutdown notify for use in select! loops.
    pub fn shutdown_notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.shutdown.notified()
    }
}

/// Run the pre-key refresh scheduler loop.
///
/// This function runs on the caller's task (not spawned) so it can hold
/// non-Send types like `Database`. It blocks the current async task until
/// the scheduler is stopped via the handle.
///
/// Typical usage:
/// ```ignore
/// let handle = SchedulerHandle::new();
/// let stop = handle.clone();
///
/// // Run on a LocalSet or the main task:
/// run_pre_key_refresh_loop(&handle, &db, &keys_api).await;
/// ```
pub async fn run_pre_key_refresh_loop(
    handle: &SchedulerHandle,
    db: &Database,
    keys_api: &KeysApi<'_>,
) {
    info!("pre-key refresh scheduler started (interval: {:?})", PRE_KEY_REFRESH_INTERVAL);
    let helper = PreKeyHelper::new();

    // Run an initial check on startup
    if let Err(e) = helper.refresh_pre_keys_if_needed(db, keys_api).await {
        tracing::warn!(error = %e, "initial pre-key refresh check failed");
    }

    let mut interval = tokio::time::interval(PRE_KEY_REFRESH_INTERVAL);
    // The first tick completes immediately; skip it since we just ran
    interval.tick().await;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                debug!("running scheduled pre-key refresh check");
                if let Err(e) = helper.refresh_pre_keys_if_needed(db, keys_api).await {
                    tracing::warn!(error = %e, "scheduled pre-key refresh failed");
                }
            }
            _ = handle.shutdown_notified() => {
                info!("pre-key refresh scheduler shutting down");
                break;
            }
        }
    }
}

/// Run a one-shot pre-key refresh check.
///
/// Useful for triggering a refresh after sending a message or on startup
/// without waiting for the next scheduled interval.
pub async fn refresh_pre_keys_now(
    db: &Database,
    keys_api: &KeysApi<'_>,
) -> crate::error::Result<()> {
    let helper = PreKeyHelper::new();
    helper.refresh_pre_keys_if_needed(db, keys_api).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_key_refresh_interval_is_two_hours() {
        assert_eq!(PRE_KEY_REFRESH_INTERVAL, Duration::from_secs(7200));
    }

    #[test]
    fn scheduler_handle_can_be_cloned() {
        let handle = SchedulerHandle::new();
        let _clone = handle.clone();
    }

    #[test]
    fn scheduler_handle_stop_does_not_panic() {
        let handle = SchedulerHandle::new();
        handle.stop();
    }
}
