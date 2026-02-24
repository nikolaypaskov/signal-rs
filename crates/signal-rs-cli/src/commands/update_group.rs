use color_eyre::Result;

#[derive(clap::Args)]
pub struct UpdateGroupArgs {
    #[arg(short, long, help = "Group ID to update (omit to create new group)")]
    pub group_id: Option<String>,

    #[arg(short, long, help = "Set group name")]
    pub name: Option<String>,

    #[arg(short, long, help = "Set group description")]
    pub description: Option<String>,

    #[arg(long, help = "Set group avatar image file path")]
    pub avatar: Option<String>,

    #[arg(long, help = "Add members by phone number or UUID")]
    pub member: Vec<String>,

    #[arg(long, help = "Remove members by phone number or UUID")]
    pub remove_member: Vec<String>,

    #[arg(long, help = "Add admins by phone number or UUID")]
    pub admin: Vec<String>,

    #[arg(long, help = "Remove admins by phone number or UUID")]
    pub remove_admin: Vec<String>,

    #[arg(long, help = "Set group link state (enabled, enabled-with-approval, disabled)")]
    pub link: Option<String>,

    #[arg(long, help = "Set message expiration timer in seconds")]
    pub expiration: Option<u32>,

    #[arg(long, help = "Set permission to add members (every-member, only-admins)")]
    pub set_permission_add_member: Option<String>,

    #[arg(long, help = "Set permission to edit details (every-member, only-admins)")]
    pub set_permission_edit_details: Option<String>,

    #[arg(long, help = "Set permission to send messages (every-member, only-admins)")]
    pub set_permission_send_messages: Option<String>,
}

pub async fn execute(args: UpdateGroupArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    if let Some(ref group_id) = args.group_id {
        let add_members: Vec<_> = args.member.iter().map(|s| super::parse_recipient(s)).collect();
        let remove_members: Vec<_> = args.remove_member.iter().map(|s| super::parse_recipient(s)).collect();
        let add_admins: Vec<_> = args.admin.iter().map(|s| super::parse_recipient(s)).collect();
        let remove_admins: Vec<_> = args.remove_admin.iter().map(|s| super::parse_recipient(s)).collect();

        let group = manager.update_group(
            group_id,
            args.name.as_deref(),
            args.description.as_deref(),
            args.avatar.as_deref(),
            &add_members,
            &remove_members,
            &add_admins,
            &remove_admins,
        ).await
            .map_err(|e| color_eyre::eyre::eyre!("failed to update group: {e}"))?;

        eprintln!("Group '{}' updated.", group.name);
    } else {
        // Create new group
        let name = args.name.as_deref()
            .ok_or_else(|| color_eyre::eyre::eyre!("--name is required when creating a new group"))?;
        let members: Vec<_> = args.member.iter().map(|s| super::parse_recipient(s)).collect();

        let group = manager.create_group(name, &members, args.avatar.as_deref()).await
            .map_err(|e| color_eyre::eyre::eyre!("failed to create group: {e}"))?;

        eprintln!("Group '{}' created (ID: {}).", group.name, group.id);
    }

    Ok(())
}
