use color_eyre::Result;

#[derive(clap::Args)]
pub struct AddDeviceArgs {
    #[arg(long, help = "Device link URI from the secondary device")]
    pub uri: String,
}

pub async fn execute(_args: AddDeviceArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    let uri = manager.add_device_link().await
        .map_err(|e| color_eyre::eyre::eyre!("failed to add device: {e}"))?;

    eprintln!("Device link URI: {uri}");
    eprintln!("Scan this with the new device to complete linking.");
    Ok(())
}
