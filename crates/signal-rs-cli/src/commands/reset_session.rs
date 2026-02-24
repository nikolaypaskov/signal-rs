use color_eyre::Result;

use super::GlobalOpts;

#[derive(clap::Args)]
pub struct ResetSessionArgs {
    /// Skip confirmation prompt
    #[arg(long)]
    pub yes: bool,
}

pub async fn execute(args: ResetSessionArgs, global: &GlobalOpts) -> Result<()> {
    let db = super::load_database(
        global.account.as_deref(),
        global.config.as_deref(),
        global.db_passphrase.as_deref(),
    )?;

    if !args.yes {
        let confirm = inquire::Confirm::new(
            "Purge all sessions and pre-keys? Contacts will need to re-establish sessions.",
        )
        .with_default(false)
        .prompt()
        .map_err(|e| color_eyre::eyre::eyre!("prompt failed: {e}"))?;

        if !confirm {
            eprintln!("Cancelled.");
            return Ok(());
        }
    }

    db.purge_crypto_state()
        .map_err(|e| color_eyre::eyre::eyre!("failed to purge crypto state: {e}"))?;

    eprintln!("All sessions and pre-keys purged.");

    // Re-upload fresh pre-keys to the server so contacts can reach us.
    let manager = super::load_manager(
        global.account.as_deref(),
        global.config.as_deref(),
        global.db_passphrase.as_deref(),
    )?;

    let http = manager.context().service.get_http()?;
    let keys_api = signal_rs_service::api::keys::KeysApi::new(&http);
    let helper = signal_rs_manager::helpers::pre_key::PreKeyHelper::new();

    helper
        .generate_and_upload_pre_keys(&manager.context().store, &keys_api)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to upload fresh pre-keys: {e}"))?;

    eprintln!("Fresh pre-keys uploaded. Contacts will establish new sessions on next message.");
    Ok(())
}
