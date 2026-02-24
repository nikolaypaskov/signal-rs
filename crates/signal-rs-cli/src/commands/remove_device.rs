use color_eyre::Result;

use signal_rs_manager::manager::SignalManager;

use super::{load_manager, GlobalOpts};

#[derive(clap::Args)]
pub struct RemoveDeviceArgs {
    #[arg(short, long, help = "Device ID to remove")]
    pub device_id: u32,
}

pub async fn execute(args: RemoveDeviceArgs, global: &GlobalOpts) -> Result<()> {
    let manager = load_manager(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;

    manager.remove_linked_device(args.device_id).await
        .map_err(|e| color_eyre::eyre::eyre!("failed to remove device: {e}"))?;

    eprintln!("Device {} removed.", args.device_id);
    Ok(())
}
