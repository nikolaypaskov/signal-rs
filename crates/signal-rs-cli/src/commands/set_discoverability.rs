use color_eyre::Result;

use signal_rs_manager::manager::SignalManager;

use super::{load_manager, GlobalOpts};

#[derive(clap::Args)]
pub struct SetDiscoverabilityArgs {
    #[arg(long, conflicts_with = "not_discoverable", help = "Make phone number discoverable")]
    pub discoverable: bool,

    #[arg(long, conflicts_with = "discoverable", help = "Make phone number not discoverable")]
    pub not_discoverable: bool,
}

pub async fn execute(args: SetDiscoverabilityArgs, global: &GlobalOpts) -> Result<()> {
    if !args.discoverable && !args.not_discoverable {
        return Err(color_eyre::eyre::eyre!(
            "specify either --discoverable or --not-discoverable"
        ));
    }

    let manager = load_manager(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;

    let discoverable = args.discoverable;
    manager
        .set_phone_number_discoverability(discoverable)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to set discoverability: {e}"))?;

    if discoverable {
        eprintln!("Phone number is now discoverable.");
    } else {
        eprintln!("Phone number is now not discoverable.");
    }

    Ok(())
}
