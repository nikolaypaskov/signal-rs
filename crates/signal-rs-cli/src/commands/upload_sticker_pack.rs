use color_eyre::Result;

#[derive(clap::Args)]
pub struct UploadStickerPackArgs {
    #[arg(help = "Path to sticker pack directory or manifest")]
    pub path: String,
}

pub async fn execute(args: UploadStickerPackArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    let pack_id = manager.upload_sticker_pack(&args.path).await
        .map_err(|e| color_eyre::eyre::eyre!("failed to upload sticker pack: {e}"))?;

    eprintln!("Sticker pack uploaded. Pack ID: {pack_id}");
    Ok(())
}
