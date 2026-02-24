use color_eyre::Result;

#[derive(clap::Args)]
pub struct GetAttachmentArgs {
    #[arg(long, help = "Attachment ID (CDN key)")]
    pub id: String,

    #[arg(short, long, help = "Output file path")]
    pub output: Option<String>,

    #[arg(long, help = "Attachment encryption key (hex-encoded)")]
    pub key: Option<String>,
}

pub async fn execute(args: GetAttachmentArgs) -> Result<()> {
    let _manager = super::load_manager(None, None, None)?;

    let output_path = args.output.unwrap_or_else(|| {
        format!("attachment-{}", args.id)
    });

    eprintln!("Downloading attachment {} to {}...", args.id, output_path);

    // Attachment download requires the attachment API with CDN access.
    // The attachment ID maps to a CDN key that the service layer resolves.
    // Steps to implement:
    //   1. Resolve CDN URL from attachment ID
    //   2. Download encrypted blob from CDN
    //   3. Decrypt with AES-256-CBC using the attachment key
    //   4. Verify HMAC-SHA256 digest
    //   5. Write plaintext to output path
    eprintln!("get-attachment: download requires CDN service integration");
    eprintln!("Output path would be: {output_path}");
    if let Some(ref key) = args.key {
        eprintln!("Encryption key provided ({} hex chars)", key.len());
    }

    Ok(())
}
