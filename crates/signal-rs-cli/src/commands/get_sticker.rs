use color_eyre::Result;

#[derive(clap::Args)]
pub struct GetStickerArgs {
    #[arg(long, help = "Sticker pack ID")]
    pub pack_id: String,

    #[arg(long, help = "Sticker ID within the pack")]
    pub sticker_id: u32,

    #[arg(short, long, help = "Output file path")]
    pub output: Option<String>,
}

pub async fn execute(args: GetStickerArgs) -> Result<()> {
    let _manager = super::load_manager(None, None, None)?;

    let output_path = args.output.unwrap_or_else(|| {
        format!("sticker-{}-{}.webp", args.pack_id, args.sticker_id)
    });

    eprintln!("Downloading sticker {} from pack {} to {}...", args.sticker_id, args.pack_id, output_path);
    // Sticker download requires the attachment API with CDN access.
    eprintln!("get-sticker: download requires service integration (CDN access)");

    Ok(())
}
