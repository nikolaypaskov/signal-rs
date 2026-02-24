use color_eyre::Result;

use signal_rs_manager::manager::SignalManager;

use super::{load_manager, parse_recipient, GlobalOpts};
use crate::output;

#[derive(clap::Args)]
pub struct ListIdentitiesArgs {
    #[arg(short, long, help = "Filter by recipient number or UUID")]
    pub recipient: Option<String>,
}

pub async fn execute(args: ListIdentitiesArgs, global: &GlobalOpts) -> Result<()> {
    let manager = load_manager(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;

    let mut identities = manager.get_identities().await
        .map_err(|e| color_eyre::eyre::eyre!("failed to list identities: {e}"))?;

    // Filter by recipient if provided
    if let Some(ref recipient_str) = args.recipient {
        let recipient = parse_recipient(recipient_str);
        match recipient {
            signal_rs_manager::types::RecipientIdentifier::Uuid(uuid) => {
                identities.retain(|i| i.address == uuid);
            }
            _ => {
                // For phone/username, we'd need to resolve to UUID - skip filtering
            }
        }
    }

    output::print_list(&global.output, &identities);
    Ok(())
}
