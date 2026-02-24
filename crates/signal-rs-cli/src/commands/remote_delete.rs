use color_eyre::Result;

#[derive(clap::Args)]
pub struct RemoteDeleteArgs {
    #[arg(short, long, help = "Recipient phone number, UUID, or username")]
    pub recipient: Vec<String>,

    #[arg(short, long, help = "Group ID")]
    pub group_id: Option<String>,

    #[arg(short, long, help = "Timestamp of the message to delete")]
    pub target_timestamp: u64,
}

pub async fn execute(args: RemoteDeleteArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    let recipients: Vec<_> = args.recipient.iter().map(|s| super::parse_recipient(s)).collect();

    if recipients.is_empty() && args.group_id.is_none() {
        return Err(color_eyre::eyre::eyre!("no recipients specified. Use --recipient or --group-id."));
    }

    let result = manager.send_remote_delete(&recipients, args.target_timestamp).await
        .map_err(|e| color_eyre::eyre::eyre!("failed to send remote delete: {e}"))?;

    eprintln!("Remote delete sent for message {} (timestamp: {}).", args.target_timestamp, result.timestamp);
    Ok(())
}
