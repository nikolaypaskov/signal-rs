use color_eyre::Result;

use signal_rs_manager::manager::SignalManager;

use super::{load_manager, GlobalOpts};
use crate::output;

#[derive(clap::Args)]
pub struct ListDevicesArgs {}

pub async fn execute(_args: ListDevicesArgs, global: &GlobalOpts) -> Result<()> {
    let manager = load_manager(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;

    let devices = manager.get_linked_devices().await
        .map_err(|e| color_eyre::eyre::eyre!("failed to list devices: {e}"))?;

    output::print_list(&global.output, &devices);
    Ok(())
}
