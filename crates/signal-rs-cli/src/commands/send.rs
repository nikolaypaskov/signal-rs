use color_eyre::Result;

#[derive(clap::Args)]
pub struct SendArgs {
    #[arg(short, long, help = "Message text (reads from stdin if not provided)")]
    pub message: Option<String>,

    #[arg(long, help = "Attachment file paths")]
    pub attachment: Vec<String>,

    #[arg(short, long, help = "Recipient phone number, UUID, or username")]
    pub recipient: Vec<String>,

    #[arg(short, long, help = "Group ID")]
    pub group_id: Option<String>,

    #[arg(long, help = "Quote a message by its timestamp")]
    pub quote_timestamp: Option<u64>,

    #[arg(long, help = "Quote author")]
    pub quote_author: Option<String>,

    #[arg(long, help = "Message expiration timer in seconds")]
    pub expiration: Option<u32>,

    #[arg(long, help = "Preview URL")]
    pub preview_url: Option<String>,

    #[arg(long, help = "Edit a previously sent message")]
    pub edit_timestamp: Option<u64>,

    #[arg(long, help = "Send as end session message")]
    pub end_session: bool,

    #[arg(long, help = "Notify self about sent message")]
    pub notify_self: bool,
}

pub async fn execute(args: SendArgs, global: &super::GlobalOpts) -> Result<()> {
    let manager = super::load_manager(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;

    // Determine message text: from arg, or read from stdin
    let message = if let Some(ref text) = args.message {
        text.clone()
    } else if args.end_session {
        String::new()
    } else {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)
            .map_err(|e| color_eyre::eyre::eyre!("failed to read from stdin: {e}"))?;
        buf
    };

    let recipients: Vec<_> = args.recipient.iter().map(|s| super::parse_recipient(s)).collect();

    if recipients.is_empty() && args.group_id.is_none() {
        return Err(color_eyre::eyre::eyre!("no recipients specified. Use --recipient or --group-id."));
    }

    use signal_rs_manager::manager::SignalManager;

    if let Some(edit_ts) = args.edit_timestamp {
        let result = manager.send_edit_message(
            &recipients, edit_ts, &message, &args.attachment, &[],
        ).await
            .map_err(|e| color_eyre::eyre::eyre!("failed to send edit: {e}"))?;
        eprintln!("Edit sent (timestamp: {}).", result.timestamp);
    } else {
        let result = manager.send_message(
            &recipients, &message, &args.attachment, args.quote_timestamp, &[],
        ).await
            .map_err(|e| color_eyre::eyre::eyre!("failed to send message: {e}"))?;

        for r in &result.results {
            if r.success {
                eprintln!("Message sent to {} (sealed sender: {}).", r.recipient, r.is_unidentified);
            } else {
                eprintln!("Failed to send to {}: {}", r.recipient,
                    r.error.as_deref().unwrap_or("unknown error"));
            }
        }
        eprintln!("Timestamp: {}", result.timestamp);
    }

    Ok(())
}
