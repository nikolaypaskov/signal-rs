use color_eyre::Result;

use super::{load_manager, parse_recipient, GlobalOpts};

#[derive(clap::Args)]
pub struct RemoveContactArgs {
    #[arg(short, long, help = "Recipient phone number or UUID to remove")]
    pub recipient: String,

    #[arg(long, help = "Also hide the conversation")]
    pub hide: bool,
}

pub async fn execute(args: RemoveContactArgs, global: &GlobalOpts) -> Result<()> {
    let manager = load_manager(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;
    let recipient = parse_recipient(&args.recipient);

    // Resolve the recipient in the store and delete
    let store_recipient = tokio::task::block_in_place(|| {
        match &recipient {
            signal_rs_manager::types::RecipientIdentifier::Uuid(uuid) => {
                manager.context().store.get_recipient_by_aci(&uuid.to_string())
            }
            signal_rs_manager::types::RecipientIdentifier::PhoneNumber(number) => {
                manager.context().store.get_recipient_by_number(number)
            }
            signal_rs_manager::types::RecipientIdentifier::Username(username) => {
                manager.context().store.get_recipient_by_username(username)
            }
        }
    }).map_err(|e| color_eyre::eyre::eyre!("store error: {e}"))?;

    let store_recipient = store_recipient
        .ok_or_else(|| color_eyre::eyre::eyre!("recipient not found: {}", args.recipient))?;

    if args.hide {
        let mut r = store_recipient.clone();
        r.hidden = true;
        tokio::task::block_in_place(|| {
            manager.context().store.update_recipient(&r)
        }).map_err(|e| color_eyre::eyre::eyre!("failed to hide recipient: {e}"))?;
        eprintln!("Contact hidden.");
    } else {
        tokio::task::block_in_place(|| {
            manager.context().store.delete_recipient(store_recipient.id)
        }).map_err(|e| color_eyre::eyre::eyre!("failed to delete recipient: {e}"))?;
        eprintln!("Contact removed.");
    }

    Ok(())
}
