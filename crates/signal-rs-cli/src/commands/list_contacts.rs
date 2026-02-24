use color_eyre::Result;

use signal_rs_manager::manager::SignalManager;

use super::{load_manager, GlobalOpts};
use crate::output;

#[derive(clap::Args)]
pub struct ListContactsArgs {
    #[arg(long, help = "Include blocked contacts")]
    pub blocked: bool,

    #[arg(long, help = "Filter by name")]
    pub name: Option<String>,
}

pub async fn execute(args: ListContactsArgs, global: &GlobalOpts) -> Result<()> {
    let manager = load_manager(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;

    let mut recipients = manager.get_recipients().await
        .map_err(|e| color_eyre::eyre::eyre!("failed to list contacts: {e}"))?;

    // Filter out blocked unless --blocked is set
    if !args.blocked {
        recipients.retain(|r| !r.is_blocked);
    }

    // Filter by name if provided
    if let Some(ref name_filter) = args.name {
        let lower = name_filter.to_lowercase();
        recipients.retain(|r| {
            r.profile_name
                .as_ref()
                .map(|n| n.to_lowercase().contains(&lower))
                .unwrap_or(false)
                || r.number
                    .as_ref()
                    .map(|n| n.contains(&lower))
                    .unwrap_or(false)
                || r.username
                    .as_ref()
                    .map(|n| n.to_lowercase().contains(&lower))
                    .unwrap_or(false)
        });
    }

    output::print_list(&global.output, &recipients);
    Ok(())
}
