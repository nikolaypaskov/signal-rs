use color_eyre::Result;

#[derive(clap::Args)]
pub struct SendReactionArgs {
    #[arg(short, long, help = "Recipient phone number, UUID, or username")]
    pub recipient: Vec<String>,

    #[arg(short, long, help = "Group ID")]
    pub group_id: Option<String>,

    #[arg(short, long, help = "Emoji to react with")]
    pub emoji: String,

    #[arg(short = 'A', long, help = "Author of the target message")]
    pub target_author: String,

    #[arg(short, long, help = "Timestamp of the target message")]
    pub target_timestamp: u64,

    #[arg(long, help = "Remove a previous reaction")]
    pub remove: bool,
}

pub async fn execute(args: SendReactionArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    let recipients: Vec<_> = args.recipient.iter().map(|s| super::parse_recipient(s)).collect();

    if recipients.is_empty() && args.group_id.is_none() {
        return Err(color_eyre::eyre::eyre!("no recipients specified. Use --recipient or --group-id."));
    }

    let target_author = super::parse_recipient(&args.target_author);

    let result = manager.send_reaction(
        &recipients, &args.emoji, &target_author, args.target_timestamp, args.remove,
    ).await
        .map_err(|e| color_eyre::eyre::eyre!("failed to send reaction: {e}"))?;

    if args.remove {
        eprintln!("Reaction removed (timestamp: {}).", result.timestamp);
    } else {
        eprintln!("Reaction '{}' sent (timestamp: {}).", args.emoji, result.timestamp);
    }
    Ok(())
}
