use color_eyre::Result;

#[derive(clap::Args)]
pub struct SendContactsArgs {}

pub async fn execute(_args: SendContactsArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    // Sending contacts to linked devices is done via the sync mechanism
    manager.request_all_sync_data().await
        .map_err(|e| color_eyre::eyre::eyre!("failed to send contacts: {e}"))?;

    eprintln!("Contacts sync sent to linked devices.");
    Ok(())
}
