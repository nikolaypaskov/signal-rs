use color_eyre::Result;

#[derive(clap::Args)]
pub struct GetAvatarArgs {
    #[arg(short, long, help = "Recipient phone number or UUID")]
    pub recipient: Option<String>,

    #[arg(short, long, help = "Group ID (hex-encoded)")]
    pub group_id: Option<String>,

    #[arg(short, long, help = "Output file path")]
    pub output: Option<String>,
}

pub async fn execute(args: GetAvatarArgs) -> Result<()> {
    let _manager = super::load_manager(None, None, None)?;

    if args.recipient.is_none() && args.group_id.is_none() {
        return Err(color_eyre::eyre::eyre!("specify --recipient or --group-id"));
    }

    let output_path = args.output.unwrap_or_else(|| "avatar.jpg".to_string());

    if let Some(ref recipient) = args.recipient {
        eprintln!("Downloading avatar for {recipient} to {output_path}...");
        // To implement:
        //   1. Look up recipient's profile_avatar_url_path from the database
        //   2. Fetch the avatar from the CDN using the profile key for decryption
        //   3. Save decrypted image to output path

        // Check if we have the avatar URL in the database
        let db = super::load_database(None, None, None)?;
        let r = if recipient.starts_with('+') {
            db.get_recipient_by_number(recipient).ok().flatten()
        } else {
            db.get_recipient_by_aci(recipient).ok().flatten()
        };

        if let Some(r) = r {
            if let Some(ref avatar_path) = r.profile_avatar_url_path {
                eprintln!("Avatar CDN path: {avatar_path}");
            } else {
                eprintln!("No avatar URL found for this recipient.");
            }
        } else {
            eprintln!("Recipient not found in local database.");
        }
    } else if let Some(ref group_id) = args.group_id {
        eprintln!("Downloading avatar for group {group_id} to {output_path}...");
        // Group avatars are stored in the group data protobuf.
    }

    eprintln!("get-avatar: download requires CDN service integration");

    Ok(())
}
