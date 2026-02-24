use color_eyre::Result;

#[derive(clap::Args)]
pub struct UpdateProfileArgs {
    #[arg(long, help = "Set profile given name")]
    pub given_name: Option<String>,

    #[arg(long, help = "Set profile family name")]
    pub family_name: Option<String>,

    #[arg(long, help = "Set profile about text")]
    pub about: Option<String>,

    #[arg(long, help = "Set profile about emoji")]
    pub about_emoji: Option<String>,

    #[arg(long, help = "Set avatar image file path")]
    pub avatar: Option<String>,

    #[arg(long, help = "Remove current avatar")]
    pub remove_avatar: bool,
}

pub async fn execute(args: UpdateProfileArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    manager.update_profile(
        args.given_name.as_deref(),
        args.family_name.as_deref(),
        args.about.as_deref(),
        args.about_emoji.as_deref(),
        args.avatar.as_deref(),
        args.remove_avatar,
    ).await
        .map_err(|e| color_eyre::eyre::eyre!("failed to update profile: {e}"))?;

    eprintln!("Profile updated.");
    Ok(())
}
