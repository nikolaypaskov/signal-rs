use color_eyre::Result;

#[derive(clap::Args)]
pub struct StartChangeNumberArgs {
    #[arg(help = "New phone number (e.g., +1234567890)")]
    pub number: String,

    #[arg(long, help = "Use voice call instead of SMS for verification")]
    pub voice: bool,

    #[arg(long, help = "CAPTCHA token for rate-limit bypass")]
    pub captcha: Option<String>,
}

pub async fn execute(args: StartChangeNumberArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    manager
        .start_change_number(&args.number, args.voice, args.captcha.as_deref())
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to start number change: {e}"))?;

    eprintln!(
        "Verification code requested for {}. Use finish-change-number to complete.",
        args.number
    );
    Ok(())
}
