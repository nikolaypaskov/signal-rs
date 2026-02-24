use std::path::PathBuf;

use color_eyre::Result;

use signal_rs_manager::context::Context;
use signal_rs_manager::manager::{ManagerImpl, SignalManager};
use signal_rs_service::config::{ServiceConfig, ServiceEnvironment};
use signal_rs_store::Database;
use signal_rs_store::passphrase;

#[derive(clap::Args)]
pub struct VerifyArgs {
    #[arg(help = "Verification code received via SMS or voice")]
    pub code: String,

    #[arg(long, help = "Registration lock PIN")]
    pub pin: Option<String>,

    #[arg(short, long, help = "Account phone number")]
    pub phone: Option<String>,
}

pub async fn execute(args: VerifyArgs) -> Result<()> {
    // Find account database
    let data_dir = directories::ProjectDirs::from("org", "signal-rs", "signal-rs")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".signal-rs"));

    // Find existing database - either use --phone to locate, or find the only one
    let db_path = if let Some(phone) = &args.phone {
        data_dir.join(format!("{}.db", phone.replace('+', "")))
    } else {
        // Look for any .db file
        let entries: Vec<_> = std::fs::read_dir(&data_dir)
            .map_err(|e| color_eyre::eyre::eyre!("failed to read data dir: {e}"))?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|ext| ext == "db").unwrap_or(false))
            .collect();

        match entries.len() {
            0 => return Err(color_eyre::eyre::eyre!("no account found - run `signal-rs register` first")),
            1 => entries[0].path(),
            _ => return Err(color_eyre::eyre::eyre!("multiple accounts found - use --phone to specify")),
        }
    };

    if !db_path.exists() {
        return Err(color_eyre::eyre::eyre!(
            "no account database found at {} - run `signal-rs register` first",
            db_path.display()
        ));
    }

    let passphrase = passphrase::resolve_passphrase(None)
        .map_err(|e| color_eyre::eyre::eyre!("passphrase resolution failed: {e}"))?;

    let store = Database::open(&db_path, &passphrase)
        .map_err(|e| color_eyre::eyre::eyre!("failed to open database: {e}"))?;

    let config = ServiceConfig::from_env(ServiceEnvironment::Production);
    let context = Context::unauthenticated(config, store);
    let manager = ManagerImpl::new(context);

    let spinner = indicatif::ProgressBar::new_spinner();
    spinner.set_message("Verifying code and registering account...");
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));

    manager
        .verify(&args.code, args.pin.as_deref())
        .await
        .map_err(|e| color_eyre::eyre::eyre!("verification failed: {e}"))?;

    spinner.finish_with_message("Account registered!");

    let aci = manager.get_self_uuid().await
        .map(|u| u.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    eprintln!("Account registered successfully.");
    eprintln!("ACI: {aci}");

    Ok(())
}
