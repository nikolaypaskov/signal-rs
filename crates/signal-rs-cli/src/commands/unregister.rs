use color_eyre::Result;

use signal_rs_manager::manager::SignalManager;

use super::{load_manager, GlobalOpts};

#[derive(clap::Args)]
pub struct UnregisterArgs {
    #[arg(long, help = "Delete the account from the server")]
    pub delete_account: bool,
}

pub async fn execute(args: UnregisterArgs, global: &GlobalOpts) -> Result<()> {
    let manager = load_manager(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;

    if args.delete_account {
        manager.delete_account().await
            .map_err(|e| color_eyre::eyre::eyre!("failed to delete account: {e}"))?;
        eprintln!("Account deleted from server.");
    } else {
        manager.unregister().await
            .map_err(|e| color_eyre::eyre::eyre!("failed to unregister: {e}"))?;
        eprintln!("Account unregistered.");
    }

    Ok(())
}
