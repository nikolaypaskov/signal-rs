use color_eyre::Result;

#[derive(clap::Args)]
pub struct SendPollVoteArgs {
    #[arg(short, long, help = "Recipient phone number, UUID, or username")]
    pub recipient: Vec<String>,

    #[arg(short, long, help = "Group ID")]
    pub group_id: Option<String>,

    #[arg(long, help = "Poll message ID to vote on")]
    pub poll_id: u64,

    #[arg(long, help = "Option indices to vote for (0-based)")]
    pub vote: Vec<u32>,
}

pub async fn execute(args: SendPollVoteArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    let recipients: Vec<_> = args.recipient.iter().map(|s| super::parse_recipient(s)).collect();

    if recipients.is_empty() && args.group_id.is_none() {
        return Err(color_eyre::eyre::eyre!(
            "no recipients specified. Use --recipient or --group-id."
        ));
    }

    if args.vote.is_empty() {
        return Err(color_eyre::eyre::eyre!("at least one --vote index is required"));
    }

    let result = manager
        .send_poll_vote(&recipients, args.poll_id, &args.vote)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to send poll vote: {e}"))?;

    for r in &result.results {
        if r.success {
            eprintln!("Vote sent to {}.", r.recipient);
        } else {
            eprintln!(
                "Failed to send vote to {}: {}",
                r.recipient,
                r.error.as_deref().unwrap_or("unknown error")
            );
        }
    }
    eprintln!("Vote submitted (timestamp: {}).", result.timestamp);
    Ok(())
}
