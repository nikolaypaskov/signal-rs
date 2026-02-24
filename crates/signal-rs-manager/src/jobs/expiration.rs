//! Disappearing message expiration job.
//!
//! Periodically deletes messages whose `expires_at` timestamp has passed.
//! Uses the same handle/loop pattern as the pre-key refresh scheduler.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tracing::{debug, info, warn};

use signal_rs_store::Database;

/// How often to check for expired messages (30 seconds).
pub const EXPIRATION_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// A handle to a running expiration loop that can be used to stop it.
#[derive(Clone)]
pub struct ExpirationHandle {
    shutdown: Arc<Notify>,
}

impl Default for ExpirationHandle {
    fn default() -> Self {
        Self {
            shutdown: Arc::new(Notify::new()),
        }
    }
}

impl ExpirationHandle {
    /// Create a new expiration handle.
    pub fn new() -> Self {
        Self::default()
    }

    /// Signal the expiration loop to stop.
    pub fn stop(&self) {
        self.shutdown.notify_one();
    }

    /// Get a reference to the shutdown notify for use in select! loops.
    pub fn shutdown_notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.shutdown.notified()
    }
}

/// Run the expiration loop that periodically deletes expired messages.
///
/// This function runs on the caller's task (not spawned) so it can hold
/// non-Send types like `Database`. It blocks the current async task until
/// the loop is stopped via the handle.
pub async fn run_expiration_loop(handle: &ExpirationHandle, db: &Database) {
    info!(
        "expiration loop started (interval: {:?})",
        EXPIRATION_CHECK_INTERVAL
    );

    // Run an initial sweep on startup
    delete_expired_now(db);

    let mut interval = tokio::time::interval(EXPIRATION_CHECK_INTERVAL);
    // The first tick completes immediately; skip it since we just ran
    interval.tick().await;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                debug!("running scheduled expiration sweep");
                delete_expired_now(db);
            }
            _ = handle.shutdown_notified() => {
                info!("expiration loop shutting down");
                break;
            }
        }
    }
}

/// Delete all expired messages as of now.
fn delete_expired_now(db: &Database) {
    let now_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    match db.delete_expired_messages(now_millis) {
        Ok(0) => {
            debug!("no expired messages to delete");
        }
        Ok(count) => {
            info!(count, "deleted expired messages");
        }
        Err(e) => {
            warn!(error = %e, "failed to delete expired messages");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiration_check_interval_is_30_seconds() {
        assert_eq!(EXPIRATION_CHECK_INTERVAL, Duration::from_secs(30));
    }

    #[test]
    fn expiration_handle_can_be_cloned() {
        let handle = ExpirationHandle::new();
        let _clone = handle.clone();
    }

    #[test]
    fn expiration_handle_stop_does_not_panic() {
        let handle = ExpirationHandle::new();
        handle.stop();
    }

    #[tokio::test]
    async fn expiration_loop_shuts_down_on_signal() {
        let handle = ExpirationHandle::new();
        let db = Database::open_in_memory().unwrap();

        let stop = handle.clone();
        // Signal shutdown immediately
        stop.stop();

        // The loop should exit promptly
        run_expiration_loop(&handle, &db).await;
    }

    #[test]
    fn delete_expired_now_runs_without_panic() {
        let db = Database::open_in_memory().unwrap();
        delete_expired_now(&db);
    }
}
