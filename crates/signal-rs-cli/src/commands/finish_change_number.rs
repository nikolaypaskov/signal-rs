use color_eyre::Result;

#[derive(clap::Args)]
pub struct FinishChangeNumberArgs {
    #[arg(help = "New phone number (e.g., +1234567890)")]
    pub number: String,

    #[arg(help = "Verification code")]
    pub code: String,

    #[arg(long, help = "Registration lock PIN")]
    pub pin: Option<String>,
}

pub async fn execute(args: FinishChangeNumberArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    manager
        .finish_change_number(&args.number, &args.code, args.pin.as_deref())
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to finish number change: {e}"))?;

    eprintln!("Phone number changed to {}.", args.number);
    Ok(())
}
