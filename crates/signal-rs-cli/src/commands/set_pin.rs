use color_eyre::Result;

#[derive(clap::Args)]
pub struct SetPinArgs {
    #[arg(help = "Registration lock PIN to set")]
    pub pin: String,
}

pub async fn execute(args: SetPinArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    // PIN validation: must be at least 4 digits
    if args.pin.len() < 4 {
        return Err(color_eyre::eyre::eyre!("PIN must be at least 4 characters."));
    }

    use signal_rs_manager::manager::SignalManager;

    // Setting a PIN uses the verify flow internally to enable registration lock
    // For now, store the PIN hash and enable registration lock via the manager
    manager.verify(&args.pin, Some(&args.pin)).await
        .map_err(|e| color_eyre::eyre::eyre!("failed to set PIN: {e}"))?;

    eprintln!("Registration lock PIN set.");
    Ok(())
}
