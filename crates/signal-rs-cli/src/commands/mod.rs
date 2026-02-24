pub mod add_device;
pub mod add_sticker_pack;
pub mod backup;
pub mod block;
pub mod completions;
pub mod daemon;
pub mod delete_local_account_data;
pub mod finish_change_number;
pub mod get_attachment;
pub mod get_avatar;
pub mod get_sticker;
pub mod get_user_status;
pub mod history;
pub mod join_group;
pub mod link;
pub mod list_accounts;
pub mod lookup;
pub mod list_contacts;
pub mod list_devices;
pub mod list_groups;
pub mod list_identities;
pub mod list_sticker_packs;
pub mod quit_group;
pub mod receive;
pub mod register;
pub mod reset_session;
pub mod remote_delete;
pub mod remove_contact;
pub mod remove_device;
pub mod remove_pin;
pub mod search;
pub mod send;
pub mod send_contacts;
pub mod send_message_request_response;
pub mod send_payment_notification;
pub mod send_poll_create;
pub mod send_poll_terminate;
pub mod send_poll_vote;
pub mod send_reaction;
pub mod send_receipt;
pub mod send_sync_request;
pub mod send_typing;
pub mod set_discoverability;
pub mod set_pin;
pub mod start_change_number;
pub mod status;
pub mod submit_rate_limit_challenge;
pub mod trust;
pub mod unblock;
pub mod unregister;
pub mod update_account;
pub mod update_configuration;
pub mod update_contact;
pub mod update_device;
pub mod update_group;
pub mod update_profile;
pub mod upload_sticker_pack;
pub mod verify;
pub mod version;

use std::path::PathBuf;

use color_eyre::eyre::eyre;
use signal_rs_manager::context::Context;
use signal_rs_manager::manager::ManagerImpl;
use signal_rs_manager::types::RecipientIdentifier;
use signal_rs_service::config::{ServiceConfig, ServiceEnvironment};
use signal_rs_service::credentials::ServiceCredentials;
use signal_rs_store::Database;
use signal_rs_store::database::account_keys;
use signal_rs_protocol::DeviceId;

use crate::cli::Command;

/// Get the default data directory for signal-rs.
pub fn data_dir() -> PathBuf {
    directories::ProjectDirs::from("org", "signal-rs", "signal-rs")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".signal-rs"))
}

/// Load a ManagerImpl for the given account.
///
/// Opens the database, loads credentials, and creates an authenticated manager context.
pub fn load_manager(
    account: Option<&str>,
    config_dir: Option<&str>,
    db_passphrase: Option<&str>,
) -> color_eyre::Result<ManagerImpl> {
    let dir = config_dir
        .map(PathBuf::from)
        .unwrap_or_else(data_dir);

    std::fs::create_dir_all(&dir)?;

    let db_path = if let Some(phone) = account {
        let normalized = phone.replace('+', "");
        dir.join(format!("{normalized}.db"))
    } else {
        // Find the first .db file in the directory
        find_default_db(&dir)?
    };

    if !db_path.exists() {
        return Err(eyre!(
            "no database found at {}. Register or link first.",
            db_path.display()
        ));
    }

    let passphrase = resolve_or_migrate_passphrase(&db_path, db_passphrase)?;

    let store = Database::open(&db_path, &passphrase)
        .map_err(|e| eyre!("failed to open database: {e}"))?;

    // Load credentials from the database to create an authenticated context
    let uuid_str = store.get_kv_string(account_keys::ACI_UUID)
        .map_err(|e| eyre!("failed to read UUID: {e}"))?;
    let password = store.get_kv_string(account_keys::PASSWORD)
        .map_err(|e| eyre!("failed to read password: {e}"))?;
    let device_id_str = store.get_kv_string(account_keys::DEVICE_ID)
        .map_err(|e| eyre!("failed to read device ID: {e}"))?;

    let service_config = ServiceConfig::from_env(ServiceEnvironment::Production);

    let context = if let (Some(uuid_str), Some(password)) = (uuid_str, password) {
        let uuid = uuid::Uuid::parse_str(&uuid_str)
            .map_err(|e| eyre!("invalid UUID in database: {e}"))?;
        let device_id: u32 = device_id_str
            .unwrap_or_else(|| "1".to_string())
            .parse()
            .unwrap_or(1);

        let creds = ServiceCredentials {
            uuid: Some(uuid),
            e164: None,
            password: Some(password),
            device_id: DeviceId(device_id),
        };
        let conn_mgr = signal_rs_service::net::connection::ConnectionManager::new(
            service_config.clone(),
            creds,
        );
        Context::new(service_config, store, conn_mgr)
    } else {
        Context::unauthenticated(service_config, store)
    };

    Ok(ManagerImpl::new(context))
}

/// Find the first .db file in a directory.
fn find_default_db(dir: &std::path::Path) -> color_eyre::Result<PathBuf> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| eyre!("cannot read data directory {}: {e}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("db") {
            return Ok(path);
        }
    }

    Err(eyre!(
        "no account database found in {}. Register or link first.",
        dir.display()
    ))
}

/// Load just the database (without a full authenticated manager).
///
/// Useful for local-only operations like search and status.
pub fn load_database(
    account: Option<&str>,
    config_dir: Option<&str>,
    db_passphrase: Option<&str>,
) -> color_eyre::Result<Database> {
    let dir = config_dir
        .map(PathBuf::from)
        .unwrap_or_else(data_dir);

    std::fs::create_dir_all(&dir)?;

    let db_path = if let Some(phone) = account {
        let normalized = phone.replace('+', "");
        dir.join(format!("{normalized}.db"))
    } else {
        find_default_db(&dir)?
    };

    if !db_path.exists() {
        return Err(eyre!(
            "no database found at {}. Register or link first.",
            db_path.display()
        ));
    }

    let passphrase = resolve_or_migrate_passphrase(&db_path, db_passphrase)?;

    Database::open(&db_path, &passphrase)
        .map_err(|e| eyre!("failed to open database: {e}"))
}

/// Resolve a passphrase and auto-migrate an unencrypted database if detected.
fn resolve_or_migrate_passphrase(
    db_path: &std::path::Path,
    cli_passphrase: Option<&str>,
) -> color_eyre::Result<String> {
    use signal_rs_store::passphrase;

    if db_path.exists() && !Database::is_encrypted(db_path)? {
        eprintln!("Unencrypted database detected at {}. Encrypting...", db_path.display());
        let pp = passphrase::prompt_new_passphrase()
            .map_err(|e| eyre!("passphrase prompt failed: {e}"))?;
        Database::encrypt_existing(db_path, &pp)
            .map_err(|e| eyre!("failed to encrypt database: {e}"))?;
        eprintln!("Database encrypted successfully.");
        return Ok(pp);
    }

    passphrase::resolve_passphrase(cli_passphrase)
        .map_err(|e| eyre!("passphrase resolution failed: {e}"))
}

/// Parse a string as a recipient identifier.
///
/// Detects whether the string is a UUID, phone number, or username:
/// - UUID: contains dashes and hex characters (e.g., "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
/// - Phone number: starts with "+"
/// - Username: everything else
pub fn parse_recipient(s: &str) -> RecipientIdentifier {
    if s.starts_with('+') {
        RecipientIdentifier::PhoneNumber(s.to_string())
    } else if uuid::Uuid::parse_str(s).is_ok() {
        RecipientIdentifier::Uuid(uuid::Uuid::parse_str(s).unwrap())
    } else {
        RecipientIdentifier::Username(s.to_string())
    }
}

/// Global options extracted from the CLI for use by commands.
pub struct GlobalOpts {
    pub account: Option<String>,
    pub config: Option<String>,
    pub output: crate::cli::OutputFormat,
    pub db_passphrase: Option<String>,
}

pub async fn dispatch(cli: crate::cli::Cli) -> color_eyre::Result<()> {
    let global = GlobalOpts {
        account: cli.account,
        config: cli.config,
        output: cli.output,
        db_passphrase: cli.db_passphrase,
    };

    match cli.command {
        Command::Register(args) => register::execute(args).await,
        Command::Verify(args) => verify::execute(args).await,
        Command::Link(args) => link::execute(args, &global).await,
        Command::Send(args) => send::execute(args, &global).await,
        Command::Receive(args) => receive::execute(args, &global).await,
        Command::ListContacts(args) => list_contacts::execute(args, &global).await,
        Command::ListGroups(args) => list_groups::execute(args, &global).await,
        Command::ListDevices(args) => list_devices::execute(args, &global).await,
        Command::ListIdentities(args) => list_identities::execute(args, &global).await,
        Command::UpdateProfile(args) => update_profile::execute(args).await,
        Command::UpdateGroup(args) => update_group::execute(args).await,
        Command::Block(args) => block::execute(args, &global).await,
        Command::Unblock(args) => unblock::execute(args, &global).await,
        Command::Trust(args) => trust::execute(args, &global).await,
        Command::SendReaction(args) => send_reaction::execute(args).await,
        Command::RemoteDelete(args) => remote_delete::execute(args).await,
        Command::SendTyping(args) => send_typing::execute(args).await,
        Command::SendReceipt(args) => send_receipt::execute(args).await,
        Command::Daemon(args) => daemon::execute(args).await,
        Command::SendPollCreate(args) => send_poll_create::execute(args).await,
        Command::SendPollVote(args) => send_poll_vote::execute(args).await,
        Command::SendPollTerminate(args) => send_poll_terminate::execute(args).await,
        Command::GetUserStatus(args) => get_user_status::execute(args).await,
        Command::JoinGroup(args) => join_group::execute(args).await,
        Command::QuitGroup(args) => quit_group::execute(args).await,
        Command::UploadStickerPack(args) => upload_sticker_pack::execute(args).await,
        Command::AddStickerPack(args) => add_sticker_pack::execute(args).await,
        Command::ListStickerPacks(args) => list_sticker_packs::execute(args).await,
        Command::AddDevice(args) => add_device::execute(args).await,
        Command::RemoveDevice(args) => remove_device::execute(args, &global).await,
        Command::UpdateDevice(args) => update_device::execute(args).await,
        Command::Lookup(args) => lookup::execute(args, &global).await,
        Command::SetDiscoverability(args) => set_discoverability::execute(args, &global).await,
        Command::SetPin(args) => set_pin::execute(args).await,
        Command::RemovePin(args) => remove_pin::execute(args).await,
        Command::UpdateContact(args) => update_contact::execute(args, &global).await,
        Command::RemoveContact(args) => remove_contact::execute(args, &global).await,
        Command::UpdateAccount(args) => update_account::execute(args, &global).await,
        Command::UpdateConfiguration(args) => update_configuration::execute(args, &global).await,
        Command::Search(args) => search::execute(args, &global).await,
        Command::History(args) => history::execute(args, &global).await,
        Command::Backup(args) => backup::execute(args, &global).await,
        Command::Status(args) => status::execute(args, &global).await,
        Command::GetAttachment(args) => get_attachment::execute(args).await,
        Command::GetAvatar(args) => get_avatar::execute(args).await,
        Command::GetSticker(args) => get_sticker::execute(args).await,
        Command::SendSyncRequest(args) => send_sync_request::execute(args).await,
        Command::SendContacts(args) => send_contacts::execute(args).await,
        Command::SubmitRateLimitChallenge(args) => {
            submit_rate_limit_challenge::execute(args).await
        }
        Command::SendMessageRequestResponse(args) => {
            send_message_request_response::execute(args, &global).await
        }
        Command::SendPaymentNotification(args) => {
            send_payment_notification::execute(args).await
        }
        Command::StartChangeNumber(args) => start_change_number::execute(args).await,
        Command::FinishChangeNumber(args) => finish_change_number::execute(args).await,
        Command::Unregister(args) => unregister::execute(args, &global).await,
        Command::DeleteLocalAccountData(args) => {
            delete_local_account_data::execute(args, &global).await
        }
        Command::ResetSession(args) => reset_session::execute(args, &global).await,
        Command::ListAccounts(args) => list_accounts::execute(args).await,
        Command::Completions(args) => completions::execute(args).await,
        Command::Tui => {
            eprintln!("TUI mode: use the `signal-rs-tui` binary instead.");
            Ok(())
        }
        Command::Version => version::execute().await,
    }
}
