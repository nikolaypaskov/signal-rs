use color_eyre::Result;

use signal_rs_manager::manager::SignalManager;

use super::{load_manager, GlobalOpts};

#[derive(clap::Args)]
pub struct LookupArgs {
    #[arg(help = "Username to look up (e.g., alice.42)")]
    pub username: String,
}

pub async fn execute(args: LookupArgs, global: &GlobalOpts) -> Result<()> {
    let manager = load_manager(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;

    let uuid = manager
        .lookup_username(&args.username)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("username lookup failed: {e}"))?;

    println!("UUID: {uuid}");

    // Try to find additional info (phone number) from the local store
    let recipients = manager.get_recipients().await.unwrap_or_default();

    if let Some(r) = recipients.iter().find(|r| r.uuid == uuid) {
        if let Some(ref number) = r.number {
            println!("Phone: {number}");
        }
        if let Some(ref name) = r.profile_name {
            println!("Name: {name}");
        }
    }

    Ok(())
}
