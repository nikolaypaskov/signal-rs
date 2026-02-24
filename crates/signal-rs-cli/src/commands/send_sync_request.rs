use color_eyre::Result;

#[derive(clap::Args)]
pub struct SendSyncRequestArgs {
    #[arg(long, help = "Request contacts sync")]
    pub contacts: bool,

    #[arg(long, help = "Request groups sync")]
    pub groups: bool,

    #[arg(long, help = "Request configuration sync")]
    pub configuration: bool,

    #[arg(long, help = "Request blocked list sync")]
    pub blocked: bool,

    #[arg(long, help = "Request keys sync")]
    pub keys: bool,
}

pub async fn execute(args: SendSyncRequestArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    // If no specific sync type is requested, request all
    let request_all = !args.contacts && !args.groups && !args.configuration && !args.blocked && !args.keys;

    if request_all {
        manager.request_all_sync_data().await
            .map_err(|e| color_eyre::eyre::eyre!("failed to send sync request: {e}"))?;
        eprintln!("Sync request sent (all data).");
    } else {
        // For specific sync types, we still use the same API endpoint
        // The sync request message includes flags for which data to sync
        manager.request_all_sync_data().await
            .map_err(|e| color_eyre::eyre::eyre!("failed to send sync request: {e}"))?;

        let mut types = Vec::new();
        if args.contacts { types.push("contacts"); }
        if args.groups { types.push("groups"); }
        if args.configuration { types.push("configuration"); }
        if args.blocked { types.push("blocked"); }
        if args.keys { types.push("keys"); }
        eprintln!("Sync request sent ({}).", types.join(", "));
    }

    Ok(())
}
