use base64::Engine;
use color_eyre::Result;
use serde::{Deserialize, Serialize};

use super::{load_database, GlobalOpts};

#[derive(clap::Args)]
pub struct BackupArgs {
    #[command(subcommand)]
    pub action: BackupAction,
}

#[derive(clap::Subcommand)]
pub enum BackupAction {
    /// Export messages, contacts, and groups to a JSON file
    Export(ExportArgs),
    /// Restore from a JSON backup file
    Restore(RestoreArgs),
}

#[derive(clap::Args)]
pub struct ExportArgs {
    /// Output file path (defaults to stdout)
    #[arg(short, long)]
    pub output: Option<String>,
}

#[derive(clap::Args)]
pub struct RestoreArgs {
    /// Input backup file path
    #[arg(short, long)]
    pub input: String,
}

/// The top-level backup structure.
#[derive(Serialize, Deserialize)]
struct Backup {
    version: u32,
    exported_at: String,
    contacts: Vec<ContactBackup>,
    groups: Vec<GroupBackup>,
    threads: Vec<ThreadBackup>,
}

#[derive(Serialize, Deserialize)]
struct ContactBackup {
    aci: Option<String>,
    phone_number: Option<String>,
    username: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    blocked: bool,
}

#[derive(Serialize, Deserialize)]
struct GroupBackup {
    group_id: String,
    master_key: String,
    blocked: bool,
}

#[derive(Serialize, Deserialize)]
struct ThreadBackup {
    thread_id: i64,
    recipient_id: Option<i64>,
    group_id: Option<i64>,
    messages: Vec<MessageBackup>,
}

#[derive(Serialize, Deserialize)]
struct MessageBackup {
    id: i64,
    timestamp: i64,
    sender_id: Option<i64>,
    body: Option<String>,
    message_type: i64,
    attachments_json: Option<String>,
    quote_id: Option<i64>,
}

pub async fn execute(args: BackupArgs, global: &GlobalOpts) -> Result<()> {
    match args.action {
        BackupAction::Export(export_args) => execute_export(export_args, global).await,
        BackupAction::Restore(restore_args) => execute_restore(restore_args, global).await,
    }
}

async fn execute_export(args: ExportArgs, global: &GlobalOpts) -> Result<()> {
    let db = load_database(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;

    // Export contacts
    let recipients = db
        .list_contacts()
        .map_err(|e| color_eyre::eyre::eyre!("failed to list contacts: {e}"))?;

    let contacts: Vec<ContactBackup> = recipients
        .iter()
        .map(|r| ContactBackup {
            aci: r.aci.clone(),
            phone_number: r.number.clone(),
            username: r.username.clone(),
            given_name: r.given_name.clone(),
            family_name: r.family_name.clone(),
            blocked: r.blocked,
        })
        .collect();

    // Export groups
    let all_groups = db
        .list_all_groups()
        .map_err(|e| color_eyre::eyre::eyre!("failed to list groups: {e}"))?;

    let groups: Vec<GroupBackup> = all_groups
        .iter()
        .map(|g| GroupBackup {
            group_id: base64::engine::general_purpose::STANDARD.encode(&g.group_id),
            master_key: base64::engine::general_purpose::STANDARD.encode(&g.master_key),
            blocked: g.blocked,
        })
        .collect();

    // Export threads and messages
    let threads = db
        .list_threads()
        .map_err(|e| color_eyre::eyre::eyre!("failed to list threads: {e}"))?;

    let mut thread_backups = Vec::new();
    for thread in &threads {
        let messages = db
            .get_messages_by_thread(thread.id, u32::MAX, None)
            .map_err(|e| color_eyre::eyre::eyre!("failed to get messages: {e}"))?;

        let message_backups: Vec<MessageBackup> = messages
            .iter()
            .map(|m| MessageBackup {
                id: m.id,
                timestamp: m.timestamp,
                sender_id: m.sender_id,
                body: m.body.clone(),
                message_type: m.message_type as i64,
                attachments_json: m.attachments_json.clone(),
                quote_id: m.quote_id,
            })
            .collect();

        thread_backups.push(ThreadBackup {
            thread_id: thread.id,
            recipient_id: thread.recipient_id,
            group_id: thread.group_id,
            messages: message_backups,
        });
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let backup = Backup {
        version: 1,
        exported_at: format!("{now}"),
        contacts,
        groups,
        threads: thread_backups,
    };

    let json = serde_json::to_string_pretty(&backup)
        .map_err(|e| color_eyre::eyre::eyre!("failed to serialize backup: {e}"))?;

    if let Some(ref output_path) = args.output {
        std::fs::write(output_path, &json)
            .map_err(|e| color_eyre::eyre::eyre!("failed to write backup file: {e}"))?;
        eprintln!(
            "Backup exported to {} ({} contacts, {} groups, {} threads).",
            output_path,
            backup.contacts.len(),
            backup.groups.len(),
            backup.threads.len()
        );
    } else {
        println!("{json}");
    }

    Ok(())
}

async fn execute_restore(args: RestoreArgs, global: &GlobalOpts) -> Result<()> {
    let db = load_database(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;

    let json = std::fs::read_to_string(&args.input)
        .map_err(|e| color_eyre::eyre::eyre!("failed to read backup file: {e}"))?;

    let backup: Backup = serde_json::from_str(&json)
        .map_err(|e| color_eyre::eyre::eyre!("failed to parse backup file: {e}"))?;

    if backup.version != 1 {
        return Err(color_eyre::eyre::eyre!(
            "unsupported backup version: {}",
            backup.version
        ));
    }

    // Restore contacts
    let mut contacts_restored = 0u64;
    for contact in &backup.contacts {
        if let Some(ref aci) = contact.aci {
            let r = db
                .get_or_create_recipient(aci)
                .map_err(|e| color_eyre::eyre::eyre!("failed to create recipient: {e}"))?;

            // Update the recipient with backup data
            if (contact.given_name.is_some()
                || contact.family_name.is_some()
                || contact.phone_number.is_some())
                && let Err(e) = db.update_recipient_profile(
                    r.id,
                    contact.given_name.as_deref(),
                    contact.family_name.as_deref(),
                    None, // about
                    None, // about_emoji
                    None, // avatar_path
                )
            {
                tracing::warn!(error = %e, "failed to update recipient profile during restore");
            }
            if contact.phone_number.is_some() || contact.username.is_some() {
                let mut updated = r.clone();
                if let Some(ref phone) = contact.phone_number {
                    updated.number = Some(phone.clone());
                }
                if let Some(ref username) = contact.username {
                    updated.username = Some(username.clone());
                }
                if let Err(e) = db.update_recipient(&updated) {
                    tracing::warn!(error = %e, "failed to update recipient fields during restore");
                }
            }
            if contact.blocked
                && let Err(e) = db.set_recipient_blocked(r.id, true)
            {
                tracing::warn!(error = %e, "failed to set recipient blocked during restore");
            }
            contacts_restored += 1;
        }
    }

    // Restore groups
    let mut groups_restored = 0u64;
    for group in &backup.groups {
        let group_id = base64::engine::general_purpose::STANDARD
            .decode(&group.group_id)
            .map_err(|e| color_eyre::eyre::eyre!("invalid group_id base64: {e}"))?;
        let master_key = base64::engine::general_purpose::STANDARD
            .decode(&group.master_key)
            .map_err(|e| color_eyre::eyre::eyre!("invalid master_key base64: {e}"))?;

        // Check if group already exists
        if db
            .get_group_by_group_id(&group_id)
            .map_err(|e| color_eyre::eyre::eyre!("db error: {e}"))?
            .is_none()
        {
            let dist_id = uuid::Uuid::new_v4();
            db.insert_group(&group_id, &master_key, dist_id.as_bytes())
                .map_err(|e| color_eyre::eyre::eyre!("failed to insert group: {e}"))?;
            if group.blocked {
                db.set_group_blocked(&group_id, true)
                    .map_err(|e| color_eyre::eyre::eyre!("failed to set group blocked: {e}"))?;
            }
            groups_restored += 1;
        }
    }

    // Restore messages
    let mut messages_restored = 0u64;
    for thread_backup in &backup.threads {
        // Create or find the thread
        let thread = if let Some(recipient_id) = thread_backup.recipient_id {
            db.get_or_create_thread_for_recipient(recipient_id)
                .map_err(|e| color_eyre::eyre::eyre!("failed to create thread: {e}"))?
        } else {
            // Skip threads we can't resolve
            continue;
        };

        for msg in &thread_backup.messages {
            // Skip if message already exists (by timestamp + sender)
            if let Some(sender_id) = msg.sender_id
                && db
                    .get_message_by_timestamp_and_sender(msg.timestamp, sender_id)
                    .map_err(|e| color_eyre::eyre::eyre!("db error: {e}"))?
                    .is_some()
                {
                    continue;
                }

            let msg_type =
                signal_rs_store::models::message::MessageType::from_i64(msg.message_type);

            db.insert_message(
                thread.id,
                msg.sender_id,
                msg.timestamp,
                None,
                msg.body.as_deref(),
                msg_type,
                msg.quote_id,
                None,
                msg.attachments_json.as_deref(),
            )
            .map_err(|e| color_eyre::eyre::eyre!("failed to insert message: {e}"))?;
            messages_restored += 1;
        }
    }

    eprintln!(
        "Restore complete: {contacts_restored} contacts, {groups_restored} groups, {messages_restored} messages restored from backup."
    );

    Ok(())
}
