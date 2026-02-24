use color_eyre::Result;

#[derive(clap::Args)]
pub struct ListStickerPacksArgs {}

pub async fn execute(_args: ListStickerPacksArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    let packs = manager.get_sticker_packs().await
        .map_err(|e| color_eyre::eyre::eyre!("failed to list sticker packs: {e}"))?;

    if packs.is_empty() {
        eprintln!("No sticker packs installed.");
    } else {
        for pack in &packs {
            let title = pack.title.as_deref().unwrap_or("(untitled)");
            let author = pack.author.as_deref().unwrap_or("(unknown)");
            let status = if pack.installed { "installed" } else { "not installed" };
            println!("{} - {} by {} [{}]", pack.pack_id, title, author, status);
        }
    }

    Ok(())
}
