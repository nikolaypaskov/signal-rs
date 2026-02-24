use color_eyre::Result;

use signal_rs_manager::manager::SignalManager;

use super::{load_manager, parse_recipient, GlobalOpts};

#[derive(clap::Args)]
pub struct UnblockArgs {
    #[arg(short, long, help = "Recipient phone number or UUID to unblock")]
    pub recipient: Vec<String>,

    #[arg(short, long, help = "Group ID to unblock")]
    pub group_id: Vec<String>,
}

pub async fn execute(args: UnblockArgs, global: &GlobalOpts) -> Result<()> {
    let manager = load_manager(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;

    if !args.recipient.is_empty() {
        let recipients: Vec<_> = args.recipient.iter().map(|s| parse_recipient(s)).collect();
        manager.set_contacts_blocked(&recipients, false).await
            .map_err(|e| color_eyre::eyre::eyre!("failed to unblock contacts: {e}"))?;
        eprintln!("Unblocked {} contact(s).", args.recipient.len());
    }

    if !args.group_id.is_empty() {
        manager.set_groups_blocked(&args.group_id, false).await
            .map_err(|e| color_eyre::eyre::eyre!("failed to unblock groups: {e}"))?;
        eprintln!("Unblocked {} group(s).", args.group_id.len());
    }

    if args.recipient.is_empty() && args.group_id.is_empty() {
        eprintln!("No recipients or groups specified. Use --recipient or --group-id.");
    }

    Ok(())
}
