use color_eyre::Result;

#[derive(clap::Args)]
pub struct AddStickerPackArgs {
    #[arg(long, help = "Sticker pack URL or pack ID")]
    pub uri: String,
}

pub async fn execute(args: AddStickerPackArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    // Parse URI: could be a URL like "https://signal.art/addstickers/#pack_id=...&pack_key=..."
    // or just a pack_id:pack_key pair
    let (pack_id, pack_key) = if args.uri.contains("pack_id=") {
        // Extract fragment (everything after #)
        let fragment = args.uri.split_once('#')
            .map(|(_, f)| f)
            .unwrap_or("");
        let params: std::collections::HashMap<_, _> = fragment
            .split('&')
            .filter_map(|p| p.split_once('='))
            .collect();
        let id = params.get("pack_id")
            .ok_or_else(|| color_eyre::eyre::eyre!("missing pack_id in URL"))?;
        let key = params.get("pack_key")
            .ok_or_else(|| color_eyre::eyre::eyre!("missing pack_key in URL"))?;
        (id.to_string(), key.to_string())
    } else {
        let parts: Vec<&str> = args.uri.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(color_eyre::eyre::eyre!("expected pack_id:pack_key or a sticker pack URL"));
        }
        (parts[0].to_string(), parts[1].to_string())
    };

    manager.install_sticker_pack(&pack_id, &pack_key).await
        .map_err(|e| color_eyre::eyre::eyre!("failed to install sticker pack: {e}"))?;

    eprintln!("Sticker pack {pack_id} installed.");
    Ok(())
}
