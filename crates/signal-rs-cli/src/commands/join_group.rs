use color_eyre::Result;

#[derive(clap::Args)]
pub struct JoinGroupArgs {
    #[arg(long, help = "Group invite link URL")]
    pub uri: String,
}

pub async fn execute(args: JoinGroupArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    let group = manager.join_group(&args.uri).await
        .map_err(|e| color_eyre::eyre::eyre!("failed to join group: {e}"))?;

    eprintln!("Joined group '{}' (ID: {}).", group.name, group.id);
    Ok(())
}
