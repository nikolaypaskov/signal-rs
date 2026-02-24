use color_eyre::Result;

#[derive(clap::Args)]
pub struct SendPollCreateArgs {
    #[arg(short, long, help = "Recipient phone number, UUID, or username")]
    pub recipient: Vec<String>,

    #[arg(short, long, help = "Group ID")]
    pub group_id: Option<String>,

    #[arg(short, long, help = "Poll question")]
    pub question: String,

    #[arg(short = 'O', long, help = "Poll options")]
    pub option: Vec<String>,

    #[arg(long, help = "Allow multiple selections")]
    pub multi_select: bool,
}

pub async fn execute(args: SendPollCreateArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    let recipients: Vec<_> = args.recipient.iter().map(|s| super::parse_recipient(s)).collect();

    if recipients.is_empty() && args.group_id.is_none() {
        return Err(color_eyre::eyre::eyre!(
            "no recipients specified. Use --recipient or --group-id."
        ));
    }

    if args.option.len() < 2 {
        return Err(color_eyre::eyre::eyre!("a poll requires at least 2 options"));
    }

    let result = manager
        .send_poll_create(&recipients, &args.question, &args.option, args.multi_select)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to create poll: {e}"))?;

    for r in &result.results {
        if r.success {
            eprintln!("Poll sent to {}.", r.recipient);
        } else {
            eprintln!(
                "Failed to send poll to {}: {}",
                r.recipient,
                r.error.as_deref().unwrap_or("unknown error")
            );
        }
    }
    eprintln!("Poll created (timestamp: {}).", result.timestamp);
    Ok(())
}
