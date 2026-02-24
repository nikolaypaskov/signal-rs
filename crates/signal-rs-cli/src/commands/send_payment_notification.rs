use color_eyre::Result;

#[derive(clap::Args)]
pub struct SendPaymentNotificationArgs {
    #[arg(short, long, help = "Recipient phone number, UUID, or username")]
    pub recipient: String,

    #[arg(long, help = "Payment receipt data")]
    pub receipt: String,

    #[arg(long, help = "Optional note")]
    pub note: Option<String>,
}

pub async fn execute(args: SendPaymentNotificationArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    let recipient = super::parse_recipient(&args.recipient);

    let result = manager
        .send_payment_notification(&recipient, &args.receipt, args.note.as_deref())
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to send payment notification: {e}"))?;

    for r in &result.results {
        if r.success {
            eprintln!("Payment notification sent to {}.", r.recipient);
        } else {
            eprintln!(
                "Failed to send payment notification to {}: {}",
                r.recipient,
                r.error.as_deref().unwrap_or("unknown error")
            );
        }
    }
    eprintln!("Timestamp: {}", result.timestamp);
    Ok(())
}
