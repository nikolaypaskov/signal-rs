use color_eyre::Result;

use signal_rs_manager::manager::SignalManager;

use super::{load_manager, GlobalOpts};
use crate::output;

#[derive(clap::Args)]
pub struct ListGroupsArgs {
    #[arg(short, long, help = "Show detailed group information")]
    pub detailed: bool,

    #[arg(long, help = "Show group members")]
    pub members: bool,
}

pub async fn execute(_args: ListGroupsArgs, global: &GlobalOpts) -> Result<()> {
    let manager = load_manager(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;

    let groups = manager.get_groups().await
        .map_err(|e| color_eyre::eyre::eyre!("failed to list groups: {e}"))?;

    output::print_list(&global.output, &groups);

    Ok(())
}
