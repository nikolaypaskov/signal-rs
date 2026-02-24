use std::path::PathBuf;

use color_eyre::Result;

use signal_rs_manager::context::Context;
use signal_rs_manager::manager::{ManagerImpl, SignalManager};
use signal_rs_service::config::{ServiceConfig, ServiceEnvironment};
use signal_rs_store::Database;
use signal_rs_store::passphrase;

#[derive(clap::Args)]
pub struct LinkArgs {
    #[arg(short, long, help = "Device name for this linked device")]
    pub name: Option<String>,
}

pub async fn execute(args: LinkArgs, global: &super::GlobalOpts) -> Result<()> {
    let device_name = if let Some(name) = &args.name {
        name.clone()
    } else {
        hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "signal-rs".to_string())
    };

    // Create data directory
    let data_dir = directories::ProjectDirs::from("org", "signal-rs", "signal-rs")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".signal-rs"));

    std::fs::create_dir_all(&data_dir)?;
    let db_path = data_dir.join("linked-device.db");

    let pp = passphrase::resolve_passphrase(global.db_passphrase.as_deref())
        .map_err(|e| color_eyre::eyre::eyre!("passphrase prompt failed: {e}"))?;

    let store = Database::open(&db_path, &pp)
        .map_err(|e| color_eyre::eyre::eyre!("failed to open database: {e}"))?;

    let config = ServiceConfig::from_env(ServiceEnvironment::Production);
    let context = Context::unauthenticated(config, store);
    let manager = ManagerImpl::new(context);

    // The manager's link() method handles the full flow internally,
    // including waiting for the primary device. It prints the QR code
    // via the uri it generates.
    // First, get the URI from the provisioning start so we can display it.
    eprintln!("Starting device linking...\n");

    let phone_number = manager
        .link(&device_name)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("device linking failed: {e:?}"))?;

    // Drop the manager (and its Context/Database) to close the SQLite connection
    // and checkpoint the WAL before renaming the database file.
    drop(manager);

    // Rename the db file to use the phone number
    let new_db_path = data_dir.join(format!("{}.db", phone_number.replace('+', "")));
    if db_path != new_db_path {
        // Also rename WAL and SHM files if they exist
        let wal_path = db_path.with_extension("db-wal");
        let shm_path = db_path.with_extension("db-shm");
        let new_wal_path = new_db_path.with_extension("db-wal");
        let new_shm_path = new_db_path.with_extension("db-shm");

        if let Err(e) = std::fs::rename(&db_path, &new_db_path) {
            tracing::warn!("failed to rename database: {e}");
        }
        // Clean up WAL/SHM files (they should be empty after checkpoint, but rename to be safe)
        if wal_path.exists() {
            let _ = std::fs::rename(&wal_path, &new_wal_path);
        }
        if shm_path.exists() {
            let _ = std::fs::rename(&shm_path, &new_shm_path);
        }
    }

    eprintln!("\nDevice linked successfully!");
    eprintln!("Phone number: {phone_number}");
    eprintln!("Device name: {device_name}");

    Ok(())
}
