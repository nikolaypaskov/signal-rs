use color_eyre::Result;

use signal_rs_manager::manager::SignalManager;

use super::{load_manager, GlobalOpts};

#[derive(clap::Args)]
pub struct UpdateConfigurationArgs {
    #[arg(long, help = "Enable or disable read receipts")]
    pub read_receipts: Option<bool>,

    #[arg(long, help = "Enable or disable typing indicators")]
    pub typing_indicators: Option<bool>,

    #[arg(long, help = "Enable or disable link previews")]
    pub link_previews: Option<bool>,

    #[arg(long, help = "Enable or disable unidentified delivery indicators")]
    pub unidentified_delivery_indicators: Option<bool>,
}

pub async fn execute(args: UpdateConfigurationArgs, global: &GlobalOpts) -> Result<()> {
    let manager = load_manager(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;

    let mut config = manager.get_configuration().await
        .map_err(|e| color_eyre::eyre::eyre!("failed to get configuration: {e}"))?;

    if let Some(v) = args.read_receipts {
        config.read_receipts = v;
    }
    if let Some(v) = args.typing_indicators {
        config.typing_indicators = v;
    }
    if let Some(v) = args.link_previews {
        config.link_previews = v;
    }
    if let Some(v) = args.unidentified_delivery_indicators {
        config.unidentified_delivery_indicators = v;
    }

    manager.update_configuration(config).await
        .map_err(|e| color_eyre::eyre::eyre!("failed to update configuration: {e}"))?;

    eprintln!("Configuration updated.");
    Ok(())
}
