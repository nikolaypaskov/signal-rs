use color_eyre::Result;

#[derive(clap::Args)]
pub struct RemovePinArgs {}

pub async fn execute(_args: RemovePinArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    // Remove registration lock by updating account attributes
    manager.update_account_attributes().await
        .map_err(|e| color_eyre::eyre::eyre!("failed to remove PIN: {e}"))?;

    eprintln!("Registration lock PIN removed.");
    Ok(())
}
