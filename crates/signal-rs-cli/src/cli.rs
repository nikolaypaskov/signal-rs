use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "signal-rs",
    version,
    about = "A modern Signal messenger CLI client",
    long_about = "signal-rs is a fast, modern command-line client for Signal messenger.\nBuilt in Rust for performance and reliability.",
    after_help = "Use `signal-rs <COMMAND> --help` for more information about a command."
)]
pub struct Cli {
    #[arg(
        short,
        long,
        global = true,
        help = "Account phone number (e.g., +1234567890)"
    )]
    pub account: Option<String>,

    #[arg(
        short,
        long,
        global = true,
        help = "Config directory",
        env = "SIGNAL_RS_CONFIG"
    )]
    pub config: Option<String>,

    #[arg(
        short,
        long,
        global = true,
        default_value = "plain",
        help = "Output format"
    )]
    pub output: OutputFormat,

    #[arg(
        short,
        long,
        global = true,
        action = clap::ArgAction::Count,
        help = "Increase verbosity (-v, -vv, -vvv)"
    )]
    pub verbose: u8,

    #[arg(long, global = true, help = "Log to file")]
    pub log_file: Option<String>,

    #[arg(
        long,
        global = true,
        default_value = "live",
        help = "Service environment"
    )]
    pub service_environment: ServiceEnvironment,

    #[arg(
        long,
        global = true,
        env = "SIGNAL_RS_DB_PASSPHRASE",
        hide_env_values = true,
        help = "Database encryption passphrase"
    )]
    pub db_passphrase: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    Plain,
    Json,
    Table,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum ServiceEnvironment {
    Live,
    Staging,
}

#[derive(Subcommand)]
pub enum Command {
    /// Register a new account
    Register(crate::commands::register::RegisterArgs),
    /// Verify registration code
    Verify(crate::commands::verify::VerifyArgs),
    /// Link as secondary device
    Link(crate::commands::link::LinkArgs),
    /// Send a message
    Send(crate::commands::send::SendArgs),
    /// Receive messages
    Receive(crate::commands::receive::ReceiveArgs),
    /// List contacts
    ListContacts(crate::commands::list_contacts::ListContactsArgs),
    /// List groups
    ListGroups(crate::commands::list_groups::ListGroupsArgs),
    /// List linked devices
    ListDevices(crate::commands::list_devices::ListDevicesArgs),
    /// List identity keys
    ListIdentities(crate::commands::list_identities::ListIdentitiesArgs),
    /// Update your profile
    UpdateProfile(crate::commands::update_profile::UpdateProfileArgs),
    /// Create or update a group
    UpdateGroup(crate::commands::update_group::UpdateGroupArgs),
    /// Block a contact or group
    Block(crate::commands::block::BlockArgs),
    /// Unblock a contact or group
    Unblock(crate::commands::unblock::UnblockArgs),
    /// Trust an identity
    Trust(crate::commands::trust::TrustArgs),
    /// Send a reaction
    SendReaction(crate::commands::send_reaction::SendReactionArgs),
    /// Delete a message remotely
    RemoteDelete(crate::commands::remote_delete::RemoteDeleteArgs),
    /// Send a typing indicator
    SendTyping(crate::commands::send_typing::SendTypingArgs),
    /// Send a read receipt
    SendReceipt(crate::commands::send_receipt::SendReceiptArgs),
    /// Run in daemon/persistent mode
    Daemon(crate::commands::daemon::DaemonArgs),
    /// Create a poll
    SendPollCreate(crate::commands::send_poll_create::SendPollCreateArgs),
    /// Vote on a poll
    SendPollVote(crate::commands::send_poll_vote::SendPollVoteArgs),
    /// Terminate a poll
    SendPollTerminate(crate::commands::send_poll_terminate::SendPollTerminateArgs),
    /// Get user registration status
    GetUserStatus(crate::commands::get_user_status::GetUserStatusArgs),
    /// Join a group via invite link
    JoinGroup(crate::commands::join_group::JoinGroupArgs),
    /// Leave a group
    QuitGroup(crate::commands::quit_group::QuitGroupArgs),
    /// Upload a sticker pack
    UploadStickerPack(crate::commands::upload_sticker_pack::UploadStickerPackArgs),
    /// Install a sticker pack
    AddStickerPack(crate::commands::add_sticker_pack::AddStickerPackArgs),
    /// List sticker packs
    ListStickerPacks(crate::commands::list_sticker_packs::ListStickerPacksArgs),
    /// Add a linked device
    AddDevice(crate::commands::add_device::AddDeviceArgs),
    /// Remove a linked device
    RemoveDevice(crate::commands::remove_device::RemoveDeviceArgs),
    /// Update a linked device
    UpdateDevice(crate::commands::update_device::UpdateDeviceArgs),
    /// Look up a user by username
    Lookup(crate::commands::lookup::LookupArgs),
    /// Set phone number discoverability
    SetDiscoverability(crate::commands::set_discoverability::SetDiscoverabilityArgs),
    /// Set registration lock PIN
    SetPin(crate::commands::set_pin::SetPinArgs),
    /// Remove registration lock PIN
    RemovePin(crate::commands::remove_pin::RemovePinArgs),
    /// Update contact
    UpdateContact(crate::commands::update_contact::UpdateContactArgs),
    /// Remove a contact
    RemoveContact(crate::commands::remove_contact::RemoveContactArgs),
    /// Update account settings
    UpdateAccount(crate::commands::update_account::UpdateAccountArgs),
    /// Update configuration
    UpdateConfiguration(crate::commands::update_configuration::UpdateConfigurationArgs),
    /// Search messages
    Search(crate::commands::search::SearchArgs),
    /// Show message history for a conversation
    History(crate::commands::history::HistoryArgs),
    /// Backup or restore messages, contacts, and groups
    Backup(crate::commands::backup::BackupArgs),
    /// Show account status
    Status(crate::commands::status::StatusArgs),
    /// Get attachment
    GetAttachment(crate::commands::get_attachment::GetAttachmentArgs),
    /// Get avatar
    GetAvatar(crate::commands::get_avatar::GetAvatarArgs),
    /// Get sticker
    GetSticker(crate::commands::get_sticker::GetStickerArgs),
    /// Request sync data from primary device
    SendSyncRequest(crate::commands::send_sync_request::SendSyncRequestArgs),
    /// Send contacts to linked devices
    SendContacts(crate::commands::send_contacts::SendContactsArgs),
    /// Submit rate limit challenge
    SubmitRateLimitChallenge(
        crate::commands::submit_rate_limit_challenge::SubmitRateLimitChallengeArgs,
    ),
    /// Respond to message request
    SendMessageRequestResponse(
        crate::commands::send_message_request_response::SendMessageRequestResponseArgs,
    ),
    /// Send payment notification
    SendPaymentNotification(
        crate::commands::send_payment_notification::SendPaymentNotificationArgs,
    ),
    /// Start phone number change
    StartChangeNumber(crate::commands::start_change_number::StartChangeNumberArgs),
    /// Finish phone number change
    FinishChangeNumber(crate::commands::finish_change_number::FinishChangeNumberArgs),
    /// Unregister account
    Unregister(crate::commands::unregister::UnregisterArgs),
    /// Delete local account data
    DeleteLocalAccountData(crate::commands::delete_local_account_data::DeleteLocalAccountDataArgs),
    /// Purge all sessions and pre-keys, then re-upload fresh keys
    ResetSession(crate::commands::reset_session::ResetSessionArgs),
    /// List accounts
    ListAccounts(crate::commands::list_accounts::ListAccountsArgs),
    /// Generate shell completions
    Completions(crate::commands::completions::CompletionsArgs),
    /// Launch TUI mode
    #[command(name = "tui")]
    Tui,
    /// Show version information
    Version,
}
