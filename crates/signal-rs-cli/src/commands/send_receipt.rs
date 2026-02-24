use color_eyre::Result;

#[derive(clap::Args)]
pub struct SendReceiptArgs {
    #[arg(short, long, help = "Recipient phone number, UUID, or username")]
    pub recipient: String,

    #[arg(short, long, help = "Timestamps of messages to mark as read")]
    pub target_timestamp: Vec<u64>,

    #[arg(long, default_value = "read", help = "Receipt type (read, viewed)")]
    pub receipt_type: String,
}

pub async fn execute(args: SendReceiptArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    let recipient = super::parse_recipient(&args.recipient);

    if args.target_timestamp.is_empty() {
        return Err(color_eyre::eyre::eyre!("no target timestamps specified. Use --target-timestamp."));
    }

    match args.receipt_type.as_str() {
        "read" => {
            manager.send_read_receipt(&recipient, &args.target_timestamp).await
                .map_err(|e| color_eyre::eyre::eyre!("failed to send read receipt: {e}"))?;
            eprintln!("Read receipt sent for {} message(s).", args.target_timestamp.len());
        }
        "viewed" => {
            manager.send_viewed_receipt(&recipient, &args.target_timestamp).await
                .map_err(|e| color_eyre::eyre::eyre!("failed to send viewed receipt: {e}"))?;
            eprintln!("Viewed receipt sent for {} message(s).", args.target_timestamp.len());
        }
        other => {
            return Err(color_eyre::eyre::eyre!("unknown receipt type: {other}. Use 'read' or 'viewed'."));
        }
    }

    Ok(())
}
