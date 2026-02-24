use color_eyre::Result;

#[derive(clap::Args)]
pub struct SendPollTerminateArgs {
    #[arg(short, long, help = "Recipient phone number, UUID, or username")]
    pub recipient: Vec<String>,

    #[arg(short, long, help = "Group ID")]
    pub group_id: Option<String>,

    #[arg(long, help = "Poll message ID to terminate")]
    pub poll_id: u64,
}

pub async fn execute(args: SendPollTerminateArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    let recipients: Vec<_> = args.recipient.iter().map(|s| super::parse_recipient(s)).collect();

    if recipients.is_empty() && args.group_id.is_none() {
        return Err(color_eyre::eyre::eyre!(
            "no recipients specified. Use --recipient or --group-id."
        ));
    }

    let result = manager
        .send_poll_terminate(&recipients, args.poll_id)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to terminate poll: {e}"))?;

    for r in &result.results {
        if r.success {
            eprintln!("Poll termination sent to {}.", r.recipient);
        } else {
            eprintln!(
                "Failed to send poll termination to {}: {}",
                r.recipient,
                r.error.as_deref().unwrap_or("unknown error")
            );
        }
    }
    eprintln!("Poll terminated (timestamp: {}).", result.timestamp);
    Ok(())
}
