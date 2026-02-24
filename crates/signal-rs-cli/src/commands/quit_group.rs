use color_eyre::Result;

#[derive(clap::Args)]
pub struct QuitGroupArgs {
    #[arg(short, long, help = "Group ID to leave")]
    pub group_id: String,

    #[arg(long, help = "Also delete the local group data")]
    pub delete: bool,
}

pub async fn execute(args: QuitGroupArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    manager.quit_group(&args.group_id).await
        .map_err(|e| color_eyre::eyre::eyre!("failed to leave group: {e}"))?;

    eprintln!("Left group {}.", args.group_id);

    if args.delete {
        manager.delete_group(&args.group_id).await
            .map_err(|e| color_eyre::eyre::eyre!("failed to delete local group data: {e}"))?;
        eprintln!("Local group data deleted.");
    }

    Ok(())
}
