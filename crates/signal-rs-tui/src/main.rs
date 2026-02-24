use std::path::PathBuf;

use clap::Parser;
use color_eyre::Result;

mod app;
mod event;
mod state;
mod ui;

/// Signal messenger TUI client.
#[derive(Parser, Debug)]
#[command(name = "signal-rs-tui", about = "A modern Signal messenger TUI client")]
struct Cli {
    /// Path to the data directory containing the account database.
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Database encryption passphrase.
    #[arg(long, env = "SIGNAL_RS_DB_PASSPHRASE", hide_env_values = true)]
    db_passphrase: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    // Use --data-dir if provided, otherwise fall back to default.
    let data_dir = cli.data_dir.or_else(|| {
        directories::ProjectDirs::from("org", "signal-rs", "signal-rs")
            .map(|dirs| dirs.data_dir().to_path_buf())
    });

    // Set up file-based tracing.
    let log_path = data_dir
        .as_ref()
        .map(|d| d.join("tui.log"))
        .unwrap_or_else(|| PathBuf::from("/tmp/signal-rs-tui.log"));

    // Create log directory if it doesn't exist.
    if let Some(parent) = log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path);

    match log_file {
        Ok(file) => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "signal_rs_tui=debug".into()),
                )
                .with_writer(file)
                .with_ansi(false)
                .init();
        }
        Err(_) => {
            // Fall back to no logging if file can't be opened.
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "signal_rs_tui=warn".into()),
                )
                .with_writer(std::io::sink)
                .init();
        }
    }

    tracing::info!(?data_dir, ?log_path, "starting signal-rs-tui");

    // Check if a database exists in the data directory.
    // The CLI names databases by phone number (e.g. "359899103121.db"),
    // so we find the first .db file rather than hardcoding a name.
    let db_path = data_dir.as_ref().and_then(|d| {
        std::fs::read_dir(d).ok().and_then(|entries| {
            entries
                .filter_map(|e| e.ok())
                .find(|e| {
                    e.path().extension().map(|ext| ext == "db").unwrap_or(false)
                        && !e.file_name().to_string_lossy().starts_with('.')
                })
                .map(|e| e.path())
        })
    });
    let db_exists = db_path.as_ref().map(|p| p.exists()).unwrap_or(false);

    // Resolve passphrase before entering TUI mode (needs terminal for prompt).
    let passphrase = if db_exists {
        let path = db_path.as_ref().unwrap();
        let pp = if !signal_rs_store::Database::is_encrypted(path)? {
            eprintln!("Unencrypted database detected. Encrypting...");
            let p = signal_rs_store::passphrase::resolve_passphrase(cli.db_passphrase.as_deref())
                .map_err(|e| color_eyre::eyre::eyre!("passphrase prompt failed: {e}"))?;
            signal_rs_store::Database::encrypt_existing(path, &p)
                .map_err(|e| color_eyre::eyre::eyre!("failed to encrypt database: {e}"))?;
            eprintln!("Database encrypted successfully.");
            p
        } else {
            signal_rs_store::passphrase::resolve_passphrase(cli.db_passphrase.as_deref())
                .map_err(|e| color_eyre::eyre::eyre!("passphrase resolution failed: {e}"))?
        };
        Some(pp)
    } else {
        None
    };

    let mut app = if db_exists {
        let path = db_path.as_ref().unwrap();
        tracing::info!(?path, "found existing database");
        app::App::with_database(path, passphrase.as_deref().unwrap()).await?
    } else {
        if let Some(ref dir) = data_dir {
            tracing::info!(?dir, "no database found, running in demo mode");
        }
        app::App::new().await?
    };

    // Set up the background event channel and spawn the WebSocket receiver task.
    if db_exists {
        let event_tx = app.setup_event_channel();
        let db_path_clone = db_path.clone().unwrap();
        let passphrase_clone = passphrase.clone().unwrap();

        // Create the outgoing message channel so the TUI can send messages
        // to the background thread where the manager lives.
        let (send_tx, send_rx) =
            tokio::sync::mpsc::unbounded_channel::<app::OutgoingMessage>();
        app.set_send_channel(send_tx);

        spawn_background_receiver(event_tx, send_rx, db_path_clone, passphrase_clone);
    }

    app.run().await
}

/// Spawn a background thread that connects to the Signal WebSocket
/// via the manager, forwards incoming messages to the TUI event channel,
/// and processes outgoing messages from the TUI send channel.
///
/// Uses a dedicated thread with its own single-threaded tokio runtime because
/// `ManagerImpl` contains `rusqlite::Connection` which is not `Sync`, so the
/// async future holding `&ManagerImpl` across `.await` points is `!Send`.
fn spawn_background_receiver(
    event_tx: tokio::sync::mpsc::UnboundedSender<event::AppEvent>,
    send_rx: tokio::sync::mpsc::UnboundedReceiver<app::OutgoingMessage>,
    db_path: PathBuf,
    passphrase: String,
) {
    std::thread::Builder::new()
        .name("ws-receiver".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("failed to create receiver runtime");

            rt.block_on(async move {
                receiver_loop(event_tx, send_rx, db_path, passphrase).await;
            });
        })
        .expect("failed to spawn receiver thread");
}

/// The actual receive loop, run on a dedicated single-threaded runtime.
/// Also processes outgoing messages from the TUI via `send_rx`.
async fn receiver_loop(
    event_tx: tokio::sync::mpsc::UnboundedSender<event::AppEvent>,
    mut send_rx: tokio::sync::mpsc::UnboundedReceiver<app::OutgoingMessage>,
    db_path: PathBuf,
    passphrase: String,
) {
    use signal_rs_manager::context::Context;
    use signal_rs_manager::manager::{ManagerImpl, SignalManager};
    use signal_rs_manager::types::RecipientIdentifier;
    use signal_rs_service::config::{ServiceConfig, ServiceEnvironment};
    use signal_rs_service::credentials::ServiceCredentials;
    use signal_rs_store::database::account_keys;

    let mut reconnect_delay = std::time::Duration::from_secs(2);
    let max_reconnect_delay = std::time::Duration::from_secs(60);

    loop {
        // Open a separate database connection for the receiver.
        let store = match signal_rs_store::Database::open(&db_path, &passphrase) {
            Ok(db) => db,
            Err(e) => {
                tracing::warn!(%e, "background receiver: failed to open database");
                tokio::time::sleep(reconnect_delay).await;
                reconnect_delay = (reconnect_delay * 2).min(max_reconnect_delay);
                continue;
            }
        };

        // Load credentials from the database.
        let uuid_str = store.get_kv_string(account_keys::ACI_UUID).ok().flatten();
        let password = store.get_kv_string(account_keys::PASSWORD).ok().flatten();
        let device_id_str = store
            .get_kv_string(account_keys::DEVICE_ID)
            .ok()
            .flatten();

        let (uuid_str, password) = match (uuid_str, password) {
            (Some(u), Some(p)) => (u, p),
            _ => {
                tracing::info!("background receiver: no credentials found, not registered yet");
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                continue;
            }
        };

        let uuid = match uuid::Uuid::parse_str(&uuid_str) {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(%e, "background receiver: invalid UUID in database");
                tokio::time::sleep(reconnect_delay).await;
                reconnect_delay = (reconnect_delay * 2).min(max_reconnect_delay);
                continue;
            }
        };

        let device_id: u32 = device_id_str
            .unwrap_or_else(|| "1".to_string())
            .parse()
            .unwrap_or(1);

        let creds = ServiceCredentials {
            uuid: Some(uuid),
            e164: None,
            password: Some(password),
            device_id: signal_rs_protocol::DeviceId(device_id),
        };

        let config = ServiceConfig::from_env(ServiceEnvironment::Production);
        let conn_mgr =
            signal_rs_service::net::connection::ConnectionManager::new(config.clone(), creds);
        let context = Context::new(config.clone(), store, conn_mgr);
        let manager = ManagerImpl::new(context);

        // Notify the TUI that we are connecting.
        let _ = event_tx.send(event::AppEvent::ConnectionChanged(
            event::ConnectionStatusEvent::Connecting,
        ));

        // Spawn pre-key refresh and storage sync on a separate thread so
        // the WebSocket receive loop starts immediately without waiting.
        // Uses a dedicated thread because Database (rusqlite) is !Sync.
        {
            let event_tx_sync = event_tx.clone();
            let db_path_sync = db_path.clone();
            let passphrase_sync = passphrase.clone();
            let config_sync = config.clone();
            let uuid_sync = uuid;
            let device_id_sync = device_id;

            std::thread::Builder::new()
                .name("post-connect-sync".into())
                .spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("failed to create sync runtime");

                    rt.block_on(async move {
                        let sync_store = match signal_rs_store::Database::open(&db_path_sync, &passphrase_sync) {
                            Ok(db) => db,
                            Err(e) => {
                                tracing::warn!(%e, "post-connect sync: failed to open database");
                                return;
                            }
                        };

                        let http_creds = ServiceCredentials {
                            uuid: Some(uuid_sync),
                            e164: None,
                            password: Some(sync_store.get_kv_string("password").ok().flatten().unwrap_or_default()),
                            device_id: signal_rs_protocol::DeviceId(device_id_sync),
                        };

                        let http = match signal_rs_service::net::http::HttpClient::new(config_sync, Some(http_creds)) {
                            Ok(h) => h,
                            Err(e) => {
                                tracing::warn!(%e, "post-connect sync: failed to create HTTP client");
                                return;
                            }
                        };

                        // Pre-key refresh (fast check, only uploads if needed).
                        let keys_api = signal_rs_service::api::keys::KeysApi::new(&http);
                        let helper = signal_rs_manager::helpers::pre_key::PreKeyHelper::new();
                        if let Err(e) = helper.refresh_pre_keys_if_needed(&sync_store, &keys_api).await {
                            tracing::warn!(%e, "post-connect sync: pre-key refresh failed");
                        } else {
                            tracing::info!("post-connect sync: pre-key refresh completed");
                        }

                        // Storage sync (contacts, groups, settings).
                        match signal_rs_service::api::storage::get_storage_auth(&http).await {
                            Ok(storage_creds) => {
                                let storage_api =
                                    signal_rs_service::api::storage::StorageApi::new(&http, storage_creds);
                                let storage_helper = signal_rs_manager::helpers::storage::StorageHelper::new();
                                if let Err(e) = storage_helper.sync(
                                    &sync_store,
                                    &storage_api,
                                ).await {
                                    tracing::warn!(%e, "post-connect sync: storage sync failed");
                                } else {
                                    tracing::info!("post-connect sync: storage sync completed");
                                    let _ = event_tx_sync.send(event::AppEvent::StorageSyncComplete);
                                }
                            }
                            Err(e) => {
                                tracing::warn!(%e, "post-connect sync: storage auth failed");
                            }
                        }

                        // Fetch group data for groups that don't have it cached yet.
                        // This populates the encrypted group protobuf which contains
                        // the group title and other metadata.
                        fetch_missing_group_data(&sync_store, &http).await;
                        // Reload conversations again so group names are resolved.
                        let _ = event_tx_sync.send(event::AppEvent::StorageSyncComplete);
                    });
                })
                .ok(); // Don't fail if thread spawn fails; sync is best-effort.
        }

        // Fetch group data for any groups that don't have it cached yet.
        // This runs before the WebSocket loop so group names are resolved
        // on the very first conversation list load.
        if let Ok(http) = manager.context().service.get_http() {
            fetch_missing_group_data(&manager.context().store, &http).await;
            // Tell the TUI to reload conversations with resolved group names.
            let _ = event_tx.send(event::AppEvent::StorageSyncComplete);
        }

        tracing::info!("background receiver: opening persistent WebSocket");

        // Open a persistent WebSocket connection.  The SignalWebSocket has
        // built-in keepalive and automatic reconnection, so a single pipe
        // stays alive for the lifetime of the session — no need to
        // reconnect every few seconds.
        let ws = match manager.connect_message_pipe().await {
            Ok(ws) => ws,
            Err(e) => {
                tracing::warn!(%e, "background receiver: failed to open message pipe");
                let _ = event_tx.send(event::AppEvent::ConnectionChanged(
                    event::ConnectionStatusEvent::Disconnected,
                ));
                tokio::time::sleep(reconnect_delay).await;
                reconnect_delay = (reconnect_delay * 2).min(max_reconnect_delay);
                continue;
            }
        };

        // The WebSocket is connected — show the green dot immediately.
        let _ = event_tx.send(event::AppEvent::ConnectionChanged(
            event::ConnectionStatusEvent::Connected,
        ));
        reconnect_delay = std::time::Duration::from_secs(2);

        tracing::info!("background receiver: persistent WebSocket connected, entering receive loop");

        // Receive loop: wait for incoming requests from the persistent
        // WebSocket, or outgoing messages from the TUI.
        loop {
            tokio::select! {
                request = ws.receive_request() => {
                    match request {
                        Ok(req) => {
                            match manager.process_incoming_ws_request(&ws, req).await {
                                Ok(messages) => {
                                    for msg in messages {
                                        let conversation_partner = msg.sender.as_ref()
                                            .or(msg.destination.as_ref());
                                        let db = &manager.context().store;
                                        let resolved = conversation_partner
                                            .and_then(|partner_uuid| {
                                                let recip = db.get_or_create_recipient(partner_uuid).ok()?;
                                                let thread =
                                                    db.get_or_create_thread_for_recipient(recip.id).ok()?;
                                                Some((thread.id, recip.display_name()))
                                            });

                                        let (thread_id, partner_name) = match resolved {
                                            Some((tid, name)) => (tid, name),
                                            None => {
                                                tracing::debug!(?msg, "no thread found for incoming message");
                                                continue;
                                            }
                                        };

                                        // Resolve sender display name (for incoming messages).
                                        let sender_display = if msg.sender.is_some() {
                                            msg.sender.as_ref()
                                                .and_then(|uuid| db.get_recipient_by_aci(uuid).ok().flatten())
                                                .map(|r| r.display_name())
                                                .unwrap_or(partner_name)
                                        } else {
                                            "You".to_string()
                                        };

                                        let chat_msg = crate::state::app_state::ChatMessage {
                                            id: uuid::Uuid::new_v4().to_string(),
                                            sender: sender_display,
                                            body: msg.text.clone().unwrap_or_default(),
                                            timestamp: format_timestamp_millis(msg.timestamp),
                                            timestamp_millis: msg.timestamp as i64,
                                            is_outgoing: msg.sender.is_none(),
                                            is_read: false,
                                            db_id: None,
                                            attachments: Vec::new(),
                                            reply_preview: None,
                                            reply_sender: None,
                                            reactions: std::collections::HashMap::new(),
                                            view_once: false,
                                        };

                                        if event_tx
                                            .send(event::AppEvent::IncomingMessage {
                                                thread_id,
                                                message: Box::new(chat_msg),
                                            })
                                            .is_err()
                                        {
                                            tracing::info!(
                                                "background receiver: event channel closed, shutting down"
                                            );
                                            return;
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(%e, "background receiver: failed to process request");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(%e, "background receiver: WebSocket pipe broken");
                            let _ = event_tx.send(event::AppEvent::ConnectionChanged(
                                event::ConnectionStatusEvent::Disconnected,
                            ));
                            tokio::time::sleep(reconnect_delay).await;
                            reconnect_delay = (reconnect_delay * 2).min(max_reconnect_delay);
                            // Break inner loop to re-create the manager with fresh connection.
                            break;
                        }
                    }
                }
                outgoing = send_rx.recv() => {
                    let Some(msg) = outgoing else {
                        tracing::info!("background sender: send channel closed, shutting down");
                        return;
                    };
                    let recipient = match msg.recipient_uuid.parse::<uuid::Uuid>() {
                        Ok(uuid) => RecipientIdentifier::Uuid(uuid),
                        Err(e) => {
                            tracing::error!(%e, uuid = %msg.recipient_uuid, "invalid recipient UUID for send");
                            continue;
                        }
                    };
                    if let Err(e) = manager.send_message(
                        &[recipient],
                        &msg.body,
                        &msg.attachments,
                        msg.quote_timestamp,
                        &[],
                    ).await {
                        tracing::error!(%e, "failed to send message via manager");
                    } else {
                        tracing::info!("message sent successfully to {}", msg.recipient_uuid);
                    }
                }
            }
        }
    }
}

/// Fetch group data from the server for groups that don't have it cached yet.
///
/// After storage sync creates group records (with master_key but no group_data),
/// this function fills in the group_data blob which contains the encrypted
/// title, avatar, members, etc.
async fn fetch_missing_group_data(
    db: &signal_rs_store::Database,
    http: &signal_rs_service::net::http::HttpClient,
) {
    use prost::Message as ProstMessage;

    let groups = match db.list_all_groups() {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(%e, "group data fetch: failed to list groups");
            return;
        }
    };

    let groups_api = signal_rs_service::api::groups_v2::GroupsV2Api::new(http);
    let mut fetched = 0u32;

    for group in &groups {
        // Skip groups that already have cached data.
        if group.group_data.is_some() {
            continue;
        }

        let master_key = match signal_rs_service::groups::GroupMasterKey::from_bytes(&group.master_key)
        {
            Ok(mk) => mk,
            Err(e) => {
                tracing::debug!(%e, group_id = group.id, "skipping group with invalid master key");
                continue;
            }
        };

        let secret_params = master_key.derive_secret_params();
        let secret_params_bytes = zkgroup::serialize(&secret_params);

        match groups_api.get_group(&secret_params_bytes).await {
            Ok(data) => {
                // Verify we can decode it and extract a title.
                if let Ok(proto) = signal_rs_protos::Group::decode(data.as_slice()) {
                    let title = proto
                        .title
                        .as_ref()
                        .and_then(|t| master_key.decrypt_title(t).ok())
                        .unwrap_or_default();
                    tracing::info!(
                        group_id = group.id,
                        title = %title,
                        "fetched group data from server"
                    );
                }
                if let Err(e) = db.update_group_data(&group.group_id, &data) {
                    tracing::warn!(%e, group_id = group.id, "failed to cache group data");
                } else {
                    fetched += 1;
                }
            }
            Err(e) => {
                tracing::debug!(%e, group_id = group.id, "failed to fetch group data (will retry next sync)");
            }
        }
    }

    if fetched > 0 {
        tracing::info!(fetched, "group data fetch complete");
    }
}

/// Format a millisecond-epoch timestamp for display in the TUI.
fn format_timestamp_millis(ts_millis: u64) -> String {
    let total_secs = (ts_millis / 1000) % 86400;
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    format!("{hours:02}:{minutes:02}")
}
