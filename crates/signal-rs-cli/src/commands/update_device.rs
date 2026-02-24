use color_eyre::Result;

#[derive(clap::Args)]
pub struct UpdateDeviceArgs {
    #[arg(short, long, help = "Device ID to update")]
    pub device_id: u32,

    #[arg(short, long, help = "New device name")]
    pub name: Option<String>,
}

pub async fn execute(args: UpdateDeviceArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    let name = args
        .name
        .as_deref()
        .ok_or_else(|| color_eyre::eyre::eyre!("--name is required"))?;

    manager
        .update_device_name(args.device_id, name)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to update device: {e}"))?;

    eprintln!("Device {} updated.", args.device_id);
    Ok(())
}
