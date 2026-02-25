use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Parser;
use color_eyre::eyre::eyre;
use color_eyre::Result;
use signal_rs_manager::context::Context;
use signal_rs_manager::helpers::pre_key::PreKeyHelper;
use signal_rs_manager::manager::{ManagerImpl, SignalManager};
use signal_rs_manager::types::RecipientIdentifier;
use signal_rs_protocol::{DeviceId, ServiceIdKind};
use signal_rs_service::api::keys::KeysApi;
use signal_rs_service::config::{ServiceConfig, ServiceEnvironment};
use signal_rs_service::credentials::ServiceCredentials;
use signal_rs_store::Database;
use signal_rs_store::database::account_keys;
use tracing::{debug, info, warn};

#[derive(Parser)]
#[command(name = "signal-rs-bridge", about = "Claude Code via Signal messenger")]
struct Cli {
    /// Only respond to messages from this sender (UUID or phone number, required)
    #[arg(long)]
    owner: String,

    /// Working directory for Claude Code
    #[arg(long, default_value = ".")]
    directory: PathBuf,

    /// Signal account phone number (e.g. +15551234567). Auto-detected if only one account exists.
    #[arg(long)]
    account: Option<String>,

    /// Path to the signal-rs config/data directory
    #[arg(long)]
    config: Option<String>,

    /// Database passphrase (or set SIGNAL_RS_DB_PASSPHRASE env var)
    #[arg(long)]
    db_passphrase: Option<String>,

    /// Maximum message length before chunking (Signal limit is ~6000)
    #[arg(long, default_value_t = 3000)]
    max_message_length: usize,

    /// Model to pass to `claude --model`
    #[arg(long)]
    model: Option<String>,

    /// Command to invoke Claude Code (default: "claude")
    #[arg(long, default_value = "claude")]
    claude_command: String,

    /// Pass --dangerously-skip-permissions to claude
    #[arg(long)]
    dangerously_skip_permissions: bool,

    /// Increase log verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();

    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| filter.into()),
        )
        .init();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run(cli))
}

async fn run(cli: Cli) -> Result<()> {
    let manager = load_manager(
        cli.account.as_deref(),
        cli.config.as_deref(),
        cli.db_passphrase.as_deref(),
    )?;

    let owner = resolve_owner(&cli.owner, &manager)?;
    let directory = std::fs::canonicalize(&cli.directory)
        .map_err(|e| eyre!("invalid directory '{}': {e}", cli.directory.display()))?;

    // Ensure pre-keys are uploaded so other devices can establish sessions with us.
    // This is critical for linked devices — without pre-keys on the server, no one
    // can send messages to this device.
    eprintln!("Checking pre-key status...");
    if let Err(e) = ensure_pre_keys(&manager).await {
        warn!("pre-key refresh failed: {e}");
        eprintln!("Warning: pre-key refresh failed: {e}");
        eprintln!("Other devices may not be able to send messages to this device.");
    } else {
        eprintln!("Pre-keys OK.");
    }

    eprintln!("signal-rs-bridge started");
    eprintln!("  owner: {owner}");
    eprintln!("  directory: {}", directory.display());
    if let Some(ref model) = cli.model {
        eprintln!("  model: {model}");
    }
    eprintln!("  max message length: {}", cli.max_message_length);
    eprintln!("Listening for messages... (press Ctrl+C to stop)");

    let start_time = Instant::now();
    let mut session_active = true; // tracks whether to use --continue
    let mut current_model: Option<String> = cli.model.clone();

    // Use a persistent WebSocket connection (same pattern as the TUI).
    // This avoids creating a new WebSocket every 30 seconds which causes
    // the server to return 4409 "Connected elsewhere" errors.
    let mut reconnect_delay = Duration::from_secs(2);
    let max_reconnect_delay = Duration::from_secs(60);

    loop {
        info!("opening persistent WebSocket connection");
        eprintln!("Connecting to Signal...");

        let ws = match manager.connect_message_pipe().await {
            Ok(ws) => {
                reconnect_delay = Duration::from_secs(2);
                eprintln!("Connected. Waiting for messages...");
                info!("persistent WebSocket connected");
                ws
            }
            Err(e) => {
                warn!("failed to connect WebSocket: {e}");
                eprintln!("Connection failed: {e}. Retrying in {reconnect_delay:?}...");
                tokio::time::sleep(reconnect_delay).await;
                reconnect_delay = (reconnect_delay * 2).min(max_reconnect_delay);
                continue;
            }
        };

        // Receive loop: process incoming messages from the persistent WebSocket.
        loop {
            let request = match ws.receive_request().await {
                Ok(req) => req,
                Err(e) => {
                    warn!("WebSocket disconnected: {e}");
                    eprintln!("WebSocket disconnected: {e}. Reconnecting...");
                    break; // break inner loop to reconnect
                }
            };

            let messages = match manager.process_incoming_ws_request(&ws, request).await {
                Ok(msgs) => msgs,
                Err(e) => {
                    warn!("error processing message: {e}");
                    continue;
                }
            };

            for msg in &messages {
                // Skip group messages
                if msg.group_id.is_some() {
                    debug!("skipping group message");
                    continue;
                }

                // Skip reactions, view-once, and messages without text
                if msg.reaction.is_some() || msg.is_view_once {
                    debug!("skipping reaction/view-once message");
                    continue;
                }

                let text = match msg.text.as_deref() {
                    Some(t) if !t.trim().is_empty() => t.trim(),
                    _ => continue,
                };

                // Verify sender is the allowed owner
                let sender_uuid = match &msg.sender {
                    Some(s) => s,
                    None => continue, // skip outgoing/sync messages
                };

                if !is_owner(sender_uuid, &owner) {
                    debug!(sender = %sender_uuid, "ignoring message from non-owner");
                    continue;
                }

                let sender_recipient = match uuid::Uuid::parse_str(sender_uuid) {
                    Ok(uuid) => RecipientIdentifier::Uuid(uuid),
                    Err(_) => {
                        warn!(sender = %sender_uuid, "cannot parse sender UUID");
                        continue;
                    }
                };

                info!(text = %text, "received message from owner");

                // Send read receipt
                if let Err(e) = manager.send_read_receipt(&sender_recipient, &[msg.timestamp]).await {
                    debug!("failed to send read receipt: {e}");
                }

                // Handle special commands
                if text.starts_with('/') {
                    let handled = handle_command(
                        text,
                        &manager,
                        &sender_recipient,
                        &start_time,
                        &mut session_active,
                        &mut current_model,
                        cli.max_message_length,
                    )
                    .await;
                    if handled {
                        continue;
                    }
                }

                // Send typing indicator
                if let Err(e) = manager.send_typing(&sender_recipient, false).await {
                    debug!("failed to send typing indicator: {e}");
                }

                // Invoke Claude Code
                let response = invoke_claude(
                    text,
                    &directory,
                    session_active,
                    current_model.as_deref(),
                    cli.dangerously_skip_permissions,
                    &cli.claude_command,
                )
                .await;

                // Stop typing indicator
                if let Err(e) = manager.send_typing(&sender_recipient, true).await {
                    debug!("failed to stop typing indicator: {e}");
                }

                // After first successful invocation, continue the session
                session_active = true;

                // Send response back, chunked if necessary
                let chunks = chunk_message(&response, cli.max_message_length);
                for chunk in &chunks {
                    if let Err(e) = manager
                        .send_message(std::slice::from_ref(&sender_recipient), chunk, &[], None, &[])
                        .await
                    {
                        warn!("failed to send response: {e}");
                    }
                }

                info!(chunks = chunks.len(), "sent response");
            }
        }
    }
}

/// Ensure pre-keys are available on the server for this device.
///
/// Checks the server pre-key count and uploads a fresh batch if needed.
/// This is essential for linked devices — without pre-keys, other devices
/// cannot establish sessions and messages won't be delivered.
async fn ensure_pre_keys(manager: &ManagerImpl) -> Result<()> {
    let http = manager.context().service.get_http()?;
    let keys_api = KeysApi::new(&http);

    // Check current count
    let count = keys_api
        .get_pre_key_count(ServiceIdKind::Aci)
        .await
        .map_err(|e| eyre!("failed to check pre-key count: {e}"))?;

    eprintln!(
        "  Server pre-key count: {} EC, {} PQ",
        count.count, count.pq_count
    );

    if count.count < 10 {
        eprintln!("  Pre-key count low, uploading fresh batch...");
        let helper = PreKeyHelper::new();
        helper
            .generate_and_upload_pre_keys(&manager.context().store, &keys_api)
            .await
            .map_err(|e| eyre!("failed to upload pre-keys: {e}"))?;
        eprintln!("  Fresh pre-keys uploaded.");
    }

    Ok(())
}

/// Handle special slash commands. Returns true if the command was handled.
async fn handle_command(
    text: &str,
    manager: &ManagerImpl,
    sender: &RecipientIdentifier,
    start_time: &Instant,
    session_active: &mut bool,
    current_model: &mut Option<String>,
    max_len: usize,
) -> bool {
    let parts: Vec<&str> = text.splitn(2, ' ').collect();
    let cmd = parts[0].to_lowercase();
    let arg = parts.get(1).map(|s| s.trim());

    let reply = match cmd.as_str() {
        "/reset" => {
            *session_active = false;
            "Session reset. Next message will start a fresh Claude conversation.".to_string()
        }
        "/status" => {
            let uptime = start_time.elapsed();
            let hours = uptime.as_secs() / 3600;
            let minutes = (uptime.as_secs() % 3600) / 60;
            let model_str = current_model
                .as_deref()
                .unwrap_or("default");
            format!(
                "Bridge status:\n  Uptime: {hours}h {minutes}m\n  Session: {}\n  Model: {model_str}",
                if *session_active { "active (--continue)" } else { "fresh" }
            )
        }
        "/model" => {
            if let Some(name) = arg {
                *current_model = Some(name.to_string());
                format!("Model switched to: {name}")
            } else {
                let model_str = current_model
                    .as_deref()
                    .unwrap_or("default");
                format!("Current model: {model_str}\nUsage: /model <name>")
            }
        }
        _ => return false,
    };

    let chunks = chunk_message(&reply, max_len);
    for chunk in &chunks {
        if let Err(e) = manager
            .send_message(std::slice::from_ref(sender), chunk, &[], None, &[])
            .await
        {
            warn!("failed to send command reply: {e}");
        }
    }
    true
}

/// Invoke `claude` CLI and return its stdout output.
async fn invoke_claude(
    prompt: &str,
    directory: &std::path::Path,
    use_continue: bool,
    model: Option<&str>,
    dangerously_skip_permissions: bool,
    claude_command: &str,
) -> String {
    // Build the shell command string. We run through the shell so that
    // aliases and functions from the user's profile are available.
    let mut shell_cmd = format!("{claude_command} --print");

    if use_continue {
        shell_cmd.push_str(" --continue");
    }

    if dangerously_skip_permissions {
        shell_cmd.push_str(" --dangerously-skip-permissions");
    }

    shell_cmd.push_str(" --output-format text");

    if let Some(m) = model {
        shell_cmd.push_str(&format!(" --model {}", shell_escape(m)));
    }

    shell_cmd.push_str(&format!(" -p {}", shell_escape(prompt)));

    let mut cmd = tokio::process::Command::new("zsh");
    cmd.arg("-i").arg("-c").arg(&shell_cmd);
    cmd.current_dir(directory);

    info!(prompt = %prompt, "invoking claude");

    match cmd.output().await {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();

            if output.status.success() {
                if stdout.trim().is_empty() {
                    "(Claude returned an empty response)".to_string()
                } else {
                    stdout
                }
            } else {
                let code = output.status.code().unwrap_or(-1);
                warn!(code, stderr = %stderr, "claude process failed");
                format!("Error (exit code {code}):\n{stderr}")
            }
        }
        Err(e) => {
            warn!(error = %e, "failed to spawn claude process");
            format!("Failed to run claude: {e}")
        }
    }
}

/// Escape a string for safe use in a shell command.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Split a message into chunks on newline boundaries.
fn chunk_message(text: &str, max_len: usize) -> Vec<String> {
    if text.len() <= max_len {
        return vec![text.to_string()];
    }

    let mut chunks = Vec::new();
    let mut current = String::new();

    for line in text.lines() {
        // If adding this line would exceed the limit, flush current chunk
        if !current.is_empty() && current.len() + line.len() + 1 > max_len {
            chunks.push(current.clone());
            current.clear();
        }

        // If a single line exceeds max_len, split it at max_len boundaries
        if line.len() > max_len {
            if !current.is_empty() {
                chunks.push(current.clone());
                current.clear();
            }
            let mut remaining = line;
            while remaining.len() > max_len {
                chunks.push(remaining[..max_len].to_string());
                remaining = &remaining[max_len..];
            }
            if !remaining.is_empty() {
                current.push_str(remaining);
            }
        } else {
            if !current.is_empty() {
                current.push('\n');
            }
            current.push_str(line);
        }
    }

    if !current.is_empty() {
        chunks.push(current);
    }

    chunks
}

/// Resolve the owner argument to a UUID-based RecipientIdentifier.
///
/// Message senders are always identified by UUID, so we need to resolve
/// phone numbers and usernames to UUIDs via the database.
fn resolve_owner(s: &str, manager: &ManagerImpl) -> Result<RecipientIdentifier> {
    if let Ok(uuid) = uuid::Uuid::parse_str(s) {
        return Ok(RecipientIdentifier::Uuid(uuid));
    }

    let store = &manager.context().store;

    if s.starts_with('+') {
        if let Ok(Some(recipient)) = store.get_recipient_by_number(s)
            && let Some(aci) = &recipient.aci
        {
            let uuid = uuid::Uuid::parse_str(aci)
                .map_err(|e| eyre!("invalid UUID for phone {s}: {e}"))?;
            info!(phone = s, uuid = %uuid, "resolved owner phone to UUID");
            return Ok(RecipientIdentifier::Uuid(uuid));
        }
        warn!(phone = s, "could not resolve phone number to UUID — owner matching may fail");
        Ok(RecipientIdentifier::PhoneNumber(s.to_string()))
    } else {
        if let Ok(Some(recipient)) = store.get_recipient_by_username(s)
            && let Some(aci) = &recipient.aci
        {
            let uuid = uuid::Uuid::parse_str(aci)
                .map_err(|e| eyre!("invalid UUID for username {s}: {e}"))?;
            info!(username = s, uuid = %uuid, "resolved owner username to UUID");
            return Ok(RecipientIdentifier::Uuid(uuid));
        }
        warn!(username = s, "could not resolve username to UUID — owner matching may fail");
        Ok(RecipientIdentifier::Username(s.to_string()))
    }
}

/// Check if a sender UUID matches the configured owner.
fn is_owner(sender: &str, owner: &RecipientIdentifier) -> bool {
    match owner {
        RecipientIdentifier::Uuid(uuid) => {
            uuid::Uuid::parse_str(sender)
                .map(|s| s == *uuid)
                .unwrap_or(false)
        }
        RecipientIdentifier::PhoneNumber(phone) => sender == phone,
        RecipientIdentifier::Username(username) => sender == username,
    }
}

// ---------------------------------------------------------------------------
// Manager loading (mirrors signal-rs-cli pattern)
// ---------------------------------------------------------------------------

fn data_dir() -> PathBuf {
    directories::ProjectDirs::from("org", "signal-rs", "signal-rs")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".signal-rs"))
}

fn load_manager(
    account: Option<&str>,
    config_dir: Option<&str>,
    db_passphrase: Option<&str>,
) -> Result<ManagerImpl> {
    let dir = config_dir.map(PathBuf::from).unwrap_or_else(data_dir);
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

    let passphrase = signal_rs_store::passphrase::resolve_passphrase(db_passphrase)
        .map_err(|e| eyre!("passphrase resolution failed: {e}"))?;

    let store = Database::open(&db_path, &passphrase)
        .map_err(|e| eyre!("failed to open database: {e}"))?;

    let uuid_str = store
        .get_kv_string(account_keys::ACI_UUID)
        .map_err(|e| eyre!("failed to read UUID: {e}"))?;
    let password = store
        .get_kv_string(account_keys::PASSWORD)
        .map_err(|e| eyre!("failed to read password: {e}"))?;
    let device_id_str = store
        .get_kv_string(account_keys::DEVICE_ID)
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

fn find_default_db(dir: &std::path::Path) -> Result<PathBuf> {
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
