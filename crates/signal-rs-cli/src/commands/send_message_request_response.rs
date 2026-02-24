use color_eyre::{Result, eyre::eyre};
use signal_rs_manager::manager::SignalManager;

use super::{load_manager, parse_recipient, GlobalOpts};

#[derive(clap::Args)]
pub struct SendMessageRequestResponseArgs {
    #[arg(short, long, help = "Recipient phone number, UUID, or username")]
    pub recipient: Option<String>,

    #[arg(short, long, help = "Group ID (base64-encoded)")]
    pub group_id: Option<String>,

    #[arg(long, help = "Accept the message request")]
    pub accept: bool,

    #[arg(long, help = "Delete the message request")]
    pub delete: bool,

    #[arg(long, help = "Block the sender")]
    pub block: bool,

    #[arg(long, help = "Block and delete the message request")]
    pub block_and_delete: bool,
}

pub async fn execute(args: SendMessageRequestResponseArgs, global: &GlobalOpts) -> Result<()> {
    use signal_rs_manager::types::RecipientIdentifier;

    // Determine response type from flags (protobuf enum values)
    let response_type = if args.accept {
        1 // ACCEPT
    } else if args.delete {
        2 // DELETE
    } else if args.block {
        3 // BLOCK
    } else if args.block_and_delete {
        4 // BLOCK_AND_DELETE
    } else {
        return Err(eyre!(
            "must specify one of --accept, --delete, --block, or --block-and-delete"
        ));
    };

    if args.recipient.is_none() && args.group_id.is_none() {
        return Err(eyre!("must specify either --recipient or --group-id"));
    }

    let manager = load_manager(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;

    // Resolve the thread ACI if a recipient was provided
    let thread_aci = if let Some(ref r) = args.recipient {
        let recipient = parse_recipient(r);
        match recipient {
            RecipientIdentifier::Uuid(uuid) => Some(uuid.to_string()),
            _ => {
                let uuid = manager
                    .resolve_recipient_to_uuid(&recipient)
                    .await
                    .map_err(|e| eyre!("failed to resolve recipient: {e}"))?;
                Some(uuid.to_string())
            }
        }
    } else {
        None
    };

    manager
        .send_message_request_response(
            thread_aci.as_deref(),
            args.group_id.as_deref(),
            response_type,
        )
        .await
        .map_err(|e| eyre!("failed to send message request response: {e}"))?;

    eprintln!("Message request response sent.");
    Ok(())
}
