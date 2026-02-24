use color_eyre::Result;

#[derive(clap::Args)]
pub struct GetUserStatusArgs {
    #[arg(short, long, help = "Phone numbers to check registration status")]
    pub recipient: Vec<String>,
}

pub async fn execute(args: GetUserStatusArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    if args.recipient.is_empty() {
        return Err(color_eyre::eyre::eyre!("no recipients specified. Use --recipient."));
    }

    let recipients = manager.get_recipients().await
        .map_err(|e| color_eyre::eyre::eyre!("failed to query recipients: {e}"))?;

    for number in &args.recipient {
        let found = recipients.iter().find(|r| {
            r.number.as_deref() == Some(number.as_str())
        });
        if let Some(r) = found {
            println!("{}: registered (UUID: {})", number, r.uuid);
        } else {
            println!("{number}: not found in local contacts");
        }
    }

    Ok(())
}
