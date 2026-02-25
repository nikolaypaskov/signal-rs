//! WebSocket client for the Signal message pipe.
//!
//! Signal uses a WebSocket connection for real-time message delivery.
//! The client sends and receives `WebSocketMessage` protobufs over
//! binary WebSocket frames.
//!
//! Endpoints:
//! - Authenticated:   `wss://chat.signal.org/v1/websocket/?login=<uuid.device>&password=<pw>`
//! - Unauthenticated: `wss://chat.signal.org/v1/websocket/`
//! - Provisioning:    `wss://chat.signal.org/v1/websocket/provisioning/`

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use prost::Message;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::{debug, info, trace, warn};

use signal_rs_protos::{
    WebSocketMessage, WebSocketRequestMessage, WebSocketResponseMessage as ProtoResponse,
    web_socket_message,
};

use crate::credentials::ServiceCredentials;
use crate::error::{Result, ServiceError};

/// Keepalive ping interval.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Timeout for waiting on a correlated response.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for the initial WebSocket connection attempt.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for receiving a pong response to a keepalive ping.
const PONG_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of reconnection attempts before returning a fatal error.
const MAX_RECONNECT_ATTEMPTS: u32 = 10;

/// Base delay for exponential backoff (doubles each attempt).
const RECONNECT_BASE_DELAY: Duration = Duration::from_secs(1);

/// Maximum delay between reconnection attempts (cap for exponential backoff).
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(60);

type WsSink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, WsMessage>;
type WsStream = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

/// A response received over the WebSocket.
#[derive(Debug, Clone)]
pub struct WebSocketResponseMessage {
    /// The HTTP-like status code of the response.
    pub status: u32,
    /// The response body (protobuf-encoded or empty).
    pub body: Option<Vec<u8>>,
    /// Headers attached to the response.
    pub headers: Vec<String>,
    /// The request ID this response corresponds to.
    pub request_id: Option<u64>,
}

/// A request received from the server (server-push).
#[derive(Debug, Clone)]
pub struct WebSocketIncomingRequest {
    /// The request ID (used for sending acknowledgment).
    pub id: u64,
    /// The HTTP verb.
    pub verb: String,
    /// The request path.
    pub path: String,
    /// The request body.
    pub body: Option<Vec<u8>>,
    /// Request headers.
    pub headers: Vec<String>,
}

/// The state of a WebSocket connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketState {
    /// The connection is being established.
    Connecting,
    /// The connection is open and ready for messages.
    Connected,
    /// The connection is being gracefully closed.
    Disconnecting,
    /// The connection is closed.
    Disconnected,
}

/// Pending response map: maps request IDs to oneshot senders.
type PendingMap = Arc<Mutex<HashMap<u64, oneshot::Sender<WebSocketResponseMessage>>>>;

/// A WebSocket connection to the Signal service.
///
/// Uses a background task for reading/writing frames and correlating
/// request/response messages by ID. Supports automatic reconnection
/// with exponential backoff when the connection drops.
pub struct SignalWebSocket {
    /// Channel for sending outgoing frames.
    write_tx: mpsc::Sender<Vec<u8>>,
    /// Pending request/response correlation map.
    pending: PendingMap,
    /// Channel for receiving server-push requests.
    incoming_rx: Mutex<mpsc::Receiver<WebSocketIncomingRequest>>,
    /// Atomic counter for generating request IDs.
    next_id: AtomicU64,
    /// Background task handle.
    _task: JoinHandle<()>,
    /// Current connection state, shared with the background task.
    state: Arc<std::sync::atomic::AtomicU8>,
}

/// Map `WebSocketState` to a u8 for atomic storage.
impl WebSocketState {
    fn as_u8(self) -> u8 {
        match self {
            WebSocketState::Connecting => 0,
            WebSocketState::Connected => 1,
            WebSocketState::Disconnecting => 2,
            WebSocketState::Disconnected => 3,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            0 => WebSocketState::Connecting,
            1 => WebSocketState::Connected,
            2 => WebSocketState::Disconnecting,
            _ => WebSocketState::Disconnected,
        }
    }
}

/// Signal Messenger's self-signed root CA certificate (PEM).
/// Source: https://github.com/signalapp/libsignal/blob/main/rust/net/res/signal.cer
/// Valid: 2022-01-26 to 2032-01-24
/// Issuer: C=US, ST=California, L=Mountain View, O=Signal Messenger, LLC, CN=Signal Messenger
pub(crate) const SIGNAL_ROOT_CA_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIF2zCCA8OgAwIBAgIUAMHz4g60cIDBpPr1gyZ/JDaaPpcwDQYJKoZIhvcNAQEL
BQAwdTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcT
DU1vdW50YWluIFZpZXcxHjAcBgNVBAoTFVNpZ25hbCBNZXNzZW5nZXIsIExMQzEZ
MBcGA1UEAxMQU2lnbmFsIE1lc3NlbmdlcjAeFw0yMjAxMjYwMDQ1NTFaFw0zMjAx
MjQwMDQ1NTBaMHUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYw
FAYDVQQHEw1Nb3VudGFpbiBWaWV3MR4wHAYDVQQKExVTaWduYWwgTWVzc2VuZ2Vy
LCBMTEMxGTAXBgNVBAMTEFNpZ25hbCBNZXNzZW5nZXIwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQDEecifxMHHlDhxbERVdErOhGsLO08PUdNkATjZ1kT5
1uPf5JPiRbus9F4J/GgBQ4ANSAjIDZuFY0WOvG/i0qvxthpW70ocp8IjkiWTNiA8
1zQNQdCiWbGDU4B1sLi2o4JgJMweSkQFiyDynqWgHpw+KmvytCzRWnvrrptIfE4G
PxNOsAtXFbVH++8JO42IaKRVlbfpe/lUHbjiYmIpQroZPGPY4Oql8KM3o39ObPnT
o1WoM4moyOOZpU3lV1awftvWBx1sbTBL02sQWfHRxgNVF+Pj0fdDMMFdFJobArrL
VfK2Ua+dYN4pV5XIxzVarSRW73CXqQ+2qloPW/ynpa3gRtYeGWV4jl7eD0PmeHpK
OY78idP4H1jfAv0TAVeKpuB5ZFZ2szcySxrQa8d7FIf0kNJe9gIRjbQ+XrvnN+ZZ
vj6d+8uBJq8LfQaFhlVfI0/aIdggScapR7w8oLpvdflUWqcTLeXVNLVrg15cEDwd
lV8PVscT/KT0bfNzKI80qBq8LyRmauAqP0CDjayYGb2UAabnhefgmRY6aBE5mXxd
byAEzzCS3vDxjeTD8v8nbDq+SD6lJi0i7jgwEfNDhe9XK50baK15Udc8Cr/ZlhGM
jNmWqBd0jIpaZm1rzWA0k4VwXtDwpBXSz8oBFshiXs3FD6jHY2IhOR3ppbyd4qRU
pwIDAQABo2MwYTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQUtfNLxuXWS9DlgGuMUMNnW7yx83EwHwYDVR0jBBgwFoAUtfNLxuXWS9Dl
gGuMUMNnW7yx83EwDQYJKoZIhvcNAQELBQADggIBABUeiryS0qjykBN75aoHO9bV
PrrX+DSJIB9V2YzkFVyh/io65QJMG8naWVGOSpVRwUwhZVKh3JVp/miPgzTGAo7z
hrDIoXc+ih7orAMb19qol/2Ha8OZLa75LojJNRbZoCR5C+gM8C+spMLjFf9k3JVx
dajhtRUcR0zYhwsBS7qZ5Me0d6gRXD0ZiSbadMMxSw6KfKk3ePmPb9gX+MRTS63c
8mLzVYB/3fe/bkpq4RUwzUHvoZf+SUD7NzSQRQQMfvAHlxk11TVNxScYPtxXDyiy
3Cssl9gWrrWqQ/omuHipoH62J7h8KAYbr6oEIq+Czuenc3eCIBGBBfvCpuFOgckA
XXE4MlBasEU0MO66GrTCgMt9bAmSw3TrRP12+ZUFxYNtqWluRU8JWQ4FCCPcz9pg
MRBOgn4lTxDZG+I47OKNuSRjFEP94cdgxd3H/5BK7WHUz1tAGQ4BgepSXgmjzifF
T5FVTDTl3ZnWUVBXiHYtbOBgLiSIkbqGMCLtrBtFIeQ7RRTb3L+IE9R0UB0cJB3A
Xbf1lVkOcmrdu2h8A32aCwtr5S1fBF1unlG7imPmqJfpOMWa8yIF/KWVm29JAPq8
Lrsybb0z5gg8w7ZblEuB9zOW9M3l60DXuJO6l7g+deV6P96rv2unHS8UlvWiVWDy
9qfgAJizyy3kqM4lOwBH
-----END CERTIFICATE-----";

/// Build a TLS connector that trusts Signal's root CA and the system's native certificates.
fn make_tls_connector() -> tokio_tungstenite::Connector {
    use std::sync::Arc;

    // Ensure a crypto provider is installed (ring).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = rustls::RootCertStore::empty();

    // Add Signal's self-signed root CA.
    let mut reader = std::io::BufReader::new(SIGNAL_ROOT_CA_PEM);
    for cert in rustls_pemfile::certs(&mut reader).flatten() {
        roots.add(cert).ok();
    }

    // Also add system native certs for CDN/other endpoints.
    for cert in rustls_native_certs::load_native_certs().expect("could not load native certs") {
        roots.add(cert).ok();
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    tokio_tungstenite::Connector::Rustls(Arc::new(config))
}

/// Perform a single WebSocket connection attempt with a timeout.
///
/// Accepts either a plain URL string or a URL with an `Authorization` header
/// already attached (via `IntoClientRequest`).
async fn connect_once(
    request: impl tokio_tungstenite::tungstenite::client::IntoClientRequest + Unpin,
) -> std::result::Result<WebSocketStream<MaybeTlsStream<TcpStream>>, ServiceError> {
    let connector = make_tls_connector();
    let result = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector)),
    )
    .await;

    match result {
        Ok(Ok((ws_stream, response))) => {
            debug!(
                status = %response.status(),
                "WebSocket upgrade response"
            );
            Ok(ws_stream)
        }
        Ok(Err(e)) => Err(ServiceError::WebSocket(format!("connection failed: {e}"))),
        Err(_) => Err(ServiceError::WebSocket(
            "connection timed out".to_string(),
        )),
    }
}

/// Calculate the backoff delay for a given attempt number.
fn backoff_delay(attempt: u32) -> Duration {
    let delay = RECONNECT_BASE_DELAY
        .saturating_mul(1u32.checked_shl(attempt).unwrap_or(u32::MAX));
    delay.min(RECONNECT_MAX_DELAY)
}

/// Reason why the connection loop exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisconnectReason {
    /// Server sent close code 4409 "Connected elsewhere".
    ConnectedElsewhere,
    /// Any other disconnect (error, normal close, pong timeout, etc.).
    Other,
}

impl SignalWebSocket {
    /// Connect to the Signal WebSocket at the given URL.
    ///
    /// If credentials are provided, an `Authorization: Basic` header is included
    /// in the WebSocket upgrade request (this is how Signal-Server authenticates).
    /// The initial connection uses a 30-second timeout.
    pub async fn connect(
        url: &str,
        credentials: Option<&ServiceCredentials>,
    ) -> Result<Self> {
        let authenticated = credentials.is_some();
        debug!(url = %url, authenticated, "connecting WebSocket");

        let request = Self::build_request(url, credentials)?;
        let reconnect_url = url.to_string();
        let reconnect_creds = credentials.cloned();

        let ws_stream = connect_once(request).await?;

        debug!("WebSocket connected");

        let (write, read) = ws_stream.split();

        let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>(64);
        let (incoming_tx, incoming_rx) = mpsc::channel::<WebSocketIncomingRequest>(64);
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let state = Arc::new(std::sync::atomic::AtomicU8::new(
            WebSocketState::Connected.as_u8(),
        ));

        let task = tokio::spawn(Self::background_loop(
            write,
            read,
            write_rx,
            incoming_tx,
            Arc::clone(&pending),
            Arc::clone(&state),
            reconnect_url,
            reconnect_creds,
        ));

        Ok(Self {
            write_tx,
            pending,
            incoming_rx: Mutex::new(incoming_rx),
            next_id: AtomicU64::new(1),
            _task: task,
            state,
        })
    }

    /// Return the current connection state.
    pub fn state(&self) -> WebSocketState {
        WebSocketState::from_u8(self.state.load(Ordering::SeqCst))
    }

    /// Send a request over the WebSocket and wait for the matching response.
    pub async fn send_request(
        &self,
        verb: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<WebSocketResponseMessage> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().await;
            pending.insert(id, tx);
        }

        let request = WebSocketRequestMessage {
            verb: Some(verb.to_string()),
            path: Some(path.to_string()),
            body,
            headers: Vec::new(),
            id: Some(id),
        };

        let msg = WebSocketMessage {
            r#type: Some(web_socket_message::Type::Request as i32),
            request: Some(request),
            response: None,
        };

        let encoded = msg.encode_to_vec();
        self.write_tx
            .send(encoded)
            .await
            .map_err(|_| ServiceError::WebSocket("write channel closed".into()))?;

        let response = tokio::time::timeout(REQUEST_TIMEOUT, rx)
            .await
            .map_err(|_| ServiceError::Timeout)?
            .map_err(|_| ServiceError::WebSocket("response channel dropped".into()))?;

        Ok(response)
    }

    /// Receive a server-push request (e.g., provisioning UUID or envelope).
    pub async fn receive_request(&self) -> Result<WebSocketIncomingRequest> {
        let mut rx = self.incoming_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| ServiceError::WebSocket("incoming channel closed".into()))
    }

    /// Send a response to a server-push request (acknowledgment).
    pub async fn send_response(&self, request_id: u64, status: u32) -> Result<()> {
        let response = ProtoResponse {
            id: Some(request_id),
            status: Some(status),
            message: Some("OK".to_string()),
            headers: Vec::new(),
            body: None,
        };

        let msg = WebSocketMessage {
            r#type: Some(web_socket_message::Type::Response as i32),
            request: None,
            response: Some(response),
        };

        let encoded = msg.encode_to_vec();
        self.write_tx
            .send(encoded)
            .await
            .map_err(|_| ServiceError::WebSocket("write channel closed".into()))?;

        Ok(())
    }

    /// Gracefully close the WebSocket connection.
    pub async fn close(&self) -> Result<()> {
        self.state.store(
            WebSocketState::Disconnecting.as_u8(),
            Ordering::SeqCst,
        );
        // Drop the write channel; the background task will detect this and shut down
        drop(self.write_tx.clone());
        Ok(())
    }

    /// Build an authenticated WebSocket request for (re)connection.
    fn build_request(
        url: &str,
        credentials: Option<&ServiceCredentials>,
    ) -> std::result::Result<
        tokio_tungstenite::tungstenite::http::Request<()>,
        ServiceError,
    > {
        use base64::Engine as _;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::http::HeaderValue;

        let mut request = url
            .into_client_request()
            .map_err(|e| ServiceError::WebSocket(format!("failed to build request: {e}")))?;

        if let Some(creds) = credentials
            && let (Some(username), Some(password)) = (creds.username(), creds.password.as_ref())
        {
            let auth_value = base64::engine::general_purpose::STANDARD
                .encode(format!("{username}:{password}"));
            request.headers_mut().insert(
                "Authorization",
                HeaderValue::from_str(&format!("Basic {auth_value}"))
                    .map_err(|e| ServiceError::WebSocket(format!("invalid auth header: {e}")))?,
            );
        }

        Ok(request)
    }

    /// Background loop: handles reading, writing, keepalive, pong timeout
    /// detection, and automatic reconnection with exponential backoff.
    #[allow(clippy::too_many_arguments)]
    async fn background_loop(
        mut write: WsSink,
        mut read: WsStream,
        mut write_rx: mpsc::Receiver<Vec<u8>>,
        incoming_tx: mpsc::Sender<WebSocketIncomingRequest>,
        pending: PendingMap,
        state: Arc<std::sync::atomic::AtomicU8>,
        url: String,
        credentials: Option<ServiceCredentials>,
    ) {
        // Track consecutive 4409 "Connected elsewhere" kicks to apply
        // increasing backoff.  Reset to 0 whenever the connection stays
        // alive long enough to receive a real message.
        let mut consecutive_4409: u32 = 0;

        loop {
            state.store(WebSocketState::Connected.as_u8(), Ordering::SeqCst);

            // Run the connection loop; returns when the connection drops.
            let disconnect_reason = Self::connection_loop(
                &mut write, &mut read, &mut write_rx, &incoming_tx, &pending,
            ).await;

            // Clean up the old write side.
            let _ = write.close().await;

            // Check if we are intentionally disconnecting.
            let current_state = WebSocketState::from_u8(state.load(Ordering::SeqCst));
            if current_state == WebSocketState::Disconnecting {
                state.store(WebSocketState::Disconnected.as_u8(), Ordering::SeqCst);
                debug!("WebSocket intentionally disconnected, not reconnecting");
                break;
            }

            // Check if the write channel (from the caller) is closed -- no point reconnecting.
            if write_rx.is_closed() {
                state.store(WebSocketState::Disconnected.as_u8(), Ordering::SeqCst);
                debug!("write channel closed, not reconnecting");
                break;
            }

            // Track consecutive 4409 errors for increasing backoff.
            if disconnect_reason == DisconnectReason::ConnectedElsewhere {
                consecutive_4409 += 1;
                let delay = backoff_delay(consecutive_4409.min(6)); // cap at ~64s
                warn!(
                    consecutive = consecutive_4409,
                    delay_ms = delay.as_millis() as u64,
                    "server says another client is connected as this device \
                     (4409 \"Connected elsewhere\"). Waiting before retry..."
                );
                tokio::time::sleep(delay).await;
            } else {
                consecutive_4409 = 0;
            }

            // Attempt reconnection with exponential backoff.
            let mut reconnect_attempts: u32 = 0;
            let mut reconnected = false;
            while reconnect_attempts < MAX_RECONNECT_ATTEMPTS {
                state.store(WebSocketState::Connecting.as_u8(), Ordering::SeqCst);

                // Skip delay for first attempt after a normal disconnect
                // (4409 already waited above).
                if reconnect_attempts > 0 {
                    let delay = backoff_delay(reconnect_attempts);
                    info!(
                        attempt = reconnect_attempts + 1,
                        max = MAX_RECONNECT_ATTEMPTS,
                        delay_ms = delay.as_millis() as u64,
                        "reconnecting WebSocket"
                    );
                    tokio::time::sleep(delay).await;
                } else {
                    info!(
                        attempt = 1,
                        max = MAX_RECONNECT_ATTEMPTS,
                        "reconnecting WebSocket"
                    );
                }

                let request = match Self::build_request(&url, credentials.as_ref()) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("failed to build reconnect request: {e}");
                        reconnect_attempts += 1;
                        continue;
                    }
                };

                match connect_once(request).await {
                    Ok(ws_stream) => {
                        let (new_write, new_read) = ws_stream.split();
                        write = new_write;
                        read = new_read;
                        info!("WebSocket reconnected successfully");
                        reconnected = true;
                        break;
                    }
                    Err(e) => {
                        warn!(
                            attempt = reconnect_attempts + 1,
                            error = %e,
                            "reconnection attempt failed"
                        );
                        reconnect_attempts += 1;
                    }
                }
            }

            if !reconnected {
                warn!("exhausted all {} reconnection attempts", MAX_RECONNECT_ATTEMPTS);
                state.store(WebSocketState::Disconnected.as_u8(), Ordering::SeqCst);
                break;
            }
        }
    }

    /// Inner connection loop that runs while the WebSocket is connected.
    /// Returns when the connection drops for any reason (error, close frame,
    /// pong timeout, or write channel closure).
    async fn connection_loop(
        write: &mut WsSink,
        read: &mut WsStream,
        write_rx: &mut mpsc::Receiver<Vec<u8>>,
        incoming_tx: &mpsc::Sender<WebSocketIncomingRequest>,
        pending: &PendingMap,
    ) -> DisconnectReason {
        let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut awaiting_pong = false;
        let mut pong_deadline: Option<tokio::time::Instant> = None;
        let mut disconnect_reason = DisconnectReason::Other;

        loop {
            // If we are waiting for a pong, enforce the timeout.
            let pong_sleep = if let Some(deadline) = pong_deadline {
                tokio::time::sleep_until(deadline)
            } else {
                // Sleep forever (never fires).
                tokio::time::sleep(Duration::from_secs(86400))
            };
            tokio::pin!(pong_sleep);

            tokio::select! {
                // Read incoming frames
                frame = read.next() => {
                    match frame {
                        Some(Ok(WsMessage::Binary(data))) => {
                            debug!(len = data.len(), "WS received binary frame");
                            Self::handle_frame(&data, pending, incoming_tx).await;
                        }
                        Some(Ok(WsMessage::Text(text))) => {
                            debug!(len = text.len(), "WS received text frame (ignored)");
                        }
                        Some(Ok(WsMessage::Ping(data))) => {
                            if let Err(e) = write.send(WsMessage::Pong(data)).await {
                                warn!("failed to send pong: {e}");
                                break;
                            }
                        }
                        Some(Ok(WsMessage::Pong(_))) => {
                            trace!("received pong");
                            awaiting_pong = false;
                            pong_deadline = None;
                        }
                        Some(Ok(WsMessage::Close(frame))) => {
                            if let Some(ref cf) = frame
                                && cf.code == tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Library(4409)
                            {
                                disconnect_reason = DisconnectReason::ConnectedElsewhere;
                            }
                            debug!(?frame, "WebSocket closed by server");
                            break;
                        }
                        Some(Ok(_)) => {
                            // Other frame types, ignore
                        }
                        Some(Err(e)) => {
                            warn!("WebSocket read error: {e}");
                            break;
                        }
                        None => {
                            debug!("WebSocket stream ended");
                            break;
                        }
                    }
                }

                // Write outgoing frames
                data = write_rx.recv() => {
                    match data {
                        Some(data) => {
                            if let Err(e) = write.send(WsMessage::Binary(data)).await {
                                warn!("WebSocket write error: {e}");
                                break;
                            }
                        }
                        None => {
                            debug!("write channel closed");
                            break;
                        }
                    }
                }

                // Keepalive ping
                _ = keepalive.tick() => {
                    trace!("sending keepalive ping");
                    if let Err(e) = write.send(WsMessage::Ping(vec![])).await {
                        warn!("keepalive ping failed: {e}");
                        break;
                    }
                    awaiting_pong = true;
                    pong_deadline = Some(tokio::time::Instant::now() + PONG_TIMEOUT);
                }

                // Pong timeout detection
                _ = &mut pong_sleep, if awaiting_pong => {
                    warn!("pong timeout: no response within {}s, reconnecting", PONG_TIMEOUT.as_secs());
                    break;
                }
            }
        }

        disconnect_reason
    }

    /// Handle a binary WebSocket frame containing a protobuf WebSocketMessage.
    async fn handle_frame(
        data: &[u8],
        pending: &PendingMap,
        incoming_tx: &mpsc::Sender<WebSocketIncomingRequest>,
    ) {
        let ws_msg = match WebSocketMessage::decode(data) {
            Ok(msg) => msg,
            Err(e) => {
                warn!("failed to decode WebSocketMessage: {e}");
                return;
            }
        };

        let msg_type = ws_msg
            .r#type
            .and_then(|t| web_socket_message::Type::try_from(t).ok());

        match msg_type {
            Some(web_socket_message::Type::Response) => {
                if let Some(response) = ws_msg.response {
                    let id = response.id.unwrap_or(0);
                    let ws_response = WebSocketResponseMessage {
                        status: response.status.unwrap_or(0),
                        body: response.body,
                        headers: response.headers,
                        request_id: Some(id),
                    };

                    let mut map = pending.lock().await;
                    if let Some(tx) = map.remove(&id) {
                        let _ = tx.send(ws_response);
                    } else {
                        debug!(id, "received response for unknown request ID");
                    }
                }
            }
            Some(web_socket_message::Type::Request) => {
                if let Some(request) = ws_msg.request {
                    debug!(
                        verb = request.verb.as_deref().unwrap_or("?"),
                        path = request.path.as_deref().unwrap_or("?"),
                        body_len = request.body.as_ref().map(|b| b.len()).unwrap_or(0),
                        "WS incoming server-push request"
                    );
                    let incoming = WebSocketIncomingRequest {
                        id: request.id.unwrap_or(0),
                        verb: request.verb.unwrap_or_default(),
                        path: request.path.unwrap_or_default(),
                        body: request.body,
                        headers: request.headers,
                    };
                    if incoming_tx.send(incoming).await.is_err() {
                        debug!("incoming channel full or closed");
                    }
                }
            }
            _ => {
                debug!("received unknown WebSocket message type");
            }
        }
    }
}
