use color_eyre::Result;
use tokio::io::AsyncWriteExt;
use tokio::sync::broadcast;

#[derive(clap::Args)]
pub struct DaemonArgs {
    #[arg(long, help = "Listen on a TCP socket (host:port)")]
    pub tcp: Option<String>,

    #[arg(long, help = "Listen on a Unix socket path")]
    pub socket: Option<String>,

    #[arg(long, help = "Output messages as JSON")]
    pub json: bool,

    #[arg(long, help = "Send read receipts for received messages")]
    pub send_read_receipts: bool,

    #[arg(long, help = "Ignore incoming messages from untrusted identities")]
    pub ignore_stories: bool,
}

pub async fn execute(args: DaemonArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    eprintln!("Starting daemon mode... (press Ctrl+C to stop)");

    if args.send_read_receipts {
        eprintln!("Read receipts: enabled");
    }

    if args.ignore_stories {
        eprintln!("Story messages: ignored");
    }

    // Broadcast channel for forwarding JSON messages to connected socket clients.
    // Capacity of 256 keeps recent messages for slow readers while bounding memory.
    let (broadcast_tx, _) = broadcast::channel::<String>(256);

    // Start TCP listener if requested.
    if let Some(ref addr) = args.tcp {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        eprintln!("TCP listener: {addr}");
        let tx = broadcast_tx.clone();
        tokio::spawn(tcp_accept_loop(listener, tx));
    }

    // Start Unix socket listener if requested.
    #[cfg(unix)]
    if let Some(ref path) = args.socket {
        // Remove stale socket file if it exists.
        let _ = std::fs::remove_file(path);
        let listener = tokio::net::UnixListener::bind(path)?;
        eprintln!("Unix socket listener: {path}");
        let tx = broadcast_tx.clone();
        tokio::spawn(unix_accept_loop(listener, tx));
    }

    #[cfg(not(unix))]
    if args.socket.is_some() {
        eprintln!("Warning: Unix sockets are not supported on this platform");
    }

    let send_receipts = args.send_read_receipts;
    let ignore_stories = args.ignore_stories;
    let has_socket_clients = args.tcp.is_some() || args.socket.is_some();

    // Continuous receive loop
    loop {
        let messages = match manager.receive_messages(30).await {
            Ok(msgs) => msgs,
            Err(e) => {
                tracing::warn!("error receiving messages: {e}");
                continue;
            }
        };

        for msg in &messages {
            // Skip story messages when ignore_stories is set
            if ignore_stories && msg.is_view_once {
                continue;
            }

            if args.json {
                if let Ok(json) = serde_json::to_string(msg) {
                    println!("{json}");

                    // Forward to connected socket clients
                    if has_socket_clients {
                        let _ = broadcast_tx.send(json);
                    }
                }
            } else {
                let sender = msg.sender.as_deref().unwrap_or("unknown");
                let group_prefix = msg.group_id.as_ref()
                    .map(|g| format!("[group:{g}] "))
                    .unwrap_or_default();
                let text = msg.text.as_deref().unwrap_or("");
                let line = format!("{group_prefix}{sender} ({}): {text}", msg.timestamp);
                println!("{line}");

                // Forward JSON version to socket clients even in non-JSON mode
                if has_socket_clients
                    && let Ok(json) = serde_json::to_string(msg) {
                        let _ = broadcast_tx.send(json);
                    }
            }

            // Send read receipts if enabled
            if send_receipts
                && let Some(ref sender_aci) = msg.sender {
                    if let Ok(uuid) = uuid::Uuid::parse_str(sender_aci) {
                        let recipient = signal_rs_manager::types::RecipientIdentifier::Uuid(uuid);
                        if let Err(e) = manager.send_read_receipt(&recipient, &[msg.timestamp]).await {
                            tracing::warn!(
                                timestamp = msg.timestamp,
                                error = %e,
                                "failed to send read receipt (non-fatal)"
                            );
                        }
                    } else {
                        tracing::debug!(
                            sender = %sender_aci,
                            "cannot send read receipt: sender is not a valid UUID"
                        );
                    }
                }
        }
    }
}

/// Accept TCP connections and forward broadcast messages to each client.
async fn tcp_accept_loop(listener: tokio::net::TcpListener, tx: broadcast::Sender<String>) {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tracing::info!(%addr, "TCP client connected");
                let rx = tx.subscribe();
                tokio::spawn(handle_tcp_client(stream, rx, addr));
            }
            Err(e) => {
                tracing::warn!("TCP accept error: {e}");
            }
        }
    }
}

/// Stream JSON messages to a single TCP client until it disconnects.
async fn handle_tcp_client(
    mut stream: tokio::net::TcpStream,
    mut rx: broadcast::Receiver<String>,
    addr: std::net::SocketAddr,
) {
    loop {
        match rx.recv().await {
            Ok(json) => {
                let line = format!("{json}\n");
                if stream.write_all(line.as_bytes()).await.is_err() {
                    tracing::debug!(%addr, "TCP client disconnected");
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(%addr, skipped = n, "TCP client lagging, skipped messages");
            }
            Err(broadcast::error::RecvError::Closed) => {
                break;
            }
        }
    }
}

/// Accept Unix socket connections and forward broadcast messages to each client.
#[cfg(unix)]
async fn unix_accept_loop(listener: tokio::net::UnixListener, tx: broadcast::Sender<String>) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                tracing::info!("Unix socket client connected");
                let rx = tx.subscribe();
                tokio::spawn(handle_unix_client(stream, rx));
            }
            Err(e) => {
                tracing::warn!("Unix socket accept error: {e}");
            }
        }
    }
}

/// Stream JSON messages to a single Unix socket client until it disconnects.
#[cfg(unix)]
async fn handle_unix_client(
    mut stream: tokio::net::UnixStream,
    mut rx: broadcast::Receiver<String>,
) {
    loop {
        match rx.recv().await {
            Ok(json) => {
                let line = format!("{json}\n");
                if stream.write_all(line.as_bytes()).await.is_err() {
                    tracing::debug!("Unix socket client disconnected");
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(skipped = n, "Unix socket client lagging, skipped messages");
            }
            Err(broadcast::error::RecvError::Closed) => {
                break;
            }
        }
    }
}
