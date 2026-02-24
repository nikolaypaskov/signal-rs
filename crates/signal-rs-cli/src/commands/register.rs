use std::path::PathBuf;

use color_eyre::Result;

use signal_rs_manager::context::Context;
use signal_rs_manager::manager::{ManagerImpl, SignalManager};
use signal_rs_service::config::{ServiceConfig, ServiceEnvironment};
use signal_rs_store::Database;
use signal_rs_store::passphrase;

#[derive(clap::Args)]
pub struct RegisterArgs {
    #[arg(help = "Phone number to register (e.g., +1234567890)")]
    pub phone: Option<String>,

    #[arg(long, help = "Use voice call instead of SMS for verification")]
    pub voice: bool,

    #[arg(long, help = "CAPTCHA token for rate-limit bypass")]
    pub captcha: Option<String>,
}

pub async fn execute(args: RegisterArgs) -> Result<()> {
    let number = if let Some(phone) = &args.phone {
        phone.clone()
    } else {
        inquire::Text::new("Phone number (e.g., +1234567890):")
            .prompt()
            .map_err(|e| color_eyre::eyre::eyre!("prompt failed: {e}"))?
    };

    if !number.starts_with('+') {
        return Err(color_eyre::eyre::eyre!("phone number must start with '+'"));
    }

    // Determine data directory
    let data_dir = directories::ProjectDirs::from("org", "signal-rs", "signal-rs")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".signal-rs"));

    std::fs::create_dir_all(&data_dir)?;
    let db_path = data_dir.join(format!("{}.db", number.replace('+', "")));

    let pp = passphrase::prompt_new_passphrase()
        .map_err(|e| color_eyre::eyre::eyre!("passphrase prompt failed: {e}"))?;

    let store = Database::open(&db_path, &pp)
        .map_err(|e| color_eyre::eyre::eyre!("failed to open database: {e}"))?;

    let config = ServiceConfig::from_env(ServiceEnvironment::Production);
    let context = Context::unauthenticated(config, store);
    let manager = ManagerImpl::new(context);

    let spinner = indicatif::ProgressBar::new_spinner();
    spinner.set_message("Requesting verification code...");
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));

    manager
        .register(&number, args.voice, args.captcha.as_deref())
        .await
        .map_err(|e| color_eyre::eyre::eyre!("registration failed: {e}"))?;

    spinner.finish_with_message("Verification code sent!");

    let transport = if args.voice { "voice call" } else { "SMS" };
    eprintln!("Verification code sent via {transport} to {number}");
    eprintln!("Run `signal-rs verify <CODE>` to complete registration.");

    Ok(())
}
