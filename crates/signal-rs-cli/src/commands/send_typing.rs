use color_eyre::Result;

#[derive(clap::Args)]
pub struct SendTypingArgs {
    #[arg(short, long, help = "Recipient phone number, UUID, or username")]
    pub recipient: Vec<String>,

    #[arg(short, long, help = "Group ID")]
    pub group_id: Option<String>,

    #[arg(long, help = "Send stop typing indicator")]
    pub stop: bool,
}

pub async fn execute(args: SendTypingArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    if args.recipient.is_empty() && args.group_id.is_none() {
        return Err(color_eyre::eyre::eyre!("no recipients specified. Use --recipient or --group-id."));
    }

    for r in &args.recipient {
        let recipient = super::parse_recipient(r);
        manager.send_typing(&recipient, args.stop).await
            .map_err(|e| color_eyre::eyre::eyre!("failed to send typing indicator: {e}"))?;
    }

    let action = if args.stop { "stop" } else { "start" };
    eprintln!("Typing indicator ({action}) sent.");
    Ok(())
}
