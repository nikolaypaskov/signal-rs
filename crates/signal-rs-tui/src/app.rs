use std::io;
use std::path::Path;
use std::time::Instant;

use color_eyre::Result;
use crossterm::{
    event as crossterm_event,
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

use crate::event::{Action, AppEvent, ConnectionStatusEvent};
use crate::state::app_state::{
    ChatMessage, CommandId, ConfirmAction, ConnectionStatus, ConversationSummary, ReplyContext,
    SearchResult,
};
use crate::state::AppState;
use crate::ui;

/// A message to be sent over the network via the manager background task.
pub struct OutgoingMessage {
    pub recipient_uuid: String,
    pub body: String,
    pub attachments: Vec<String>,
    pub quote_timestamp: Option<u64>,
}

/// Main application struct implementing the TEA (The Elm Architecture) event loop.
pub struct App {
    state: AppState,
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    should_quit: bool,
    /// Optional database connection for persistent storage.
    database: Option<signal_rs_store::Database>,
    /// Receiver for background app events (incoming messages, typing, etc.).
    event_rx: Option<tokio::sync::mpsc::UnboundedReceiver<AppEvent>>,
    /// Channel sender for outgoing messages to be sent via manager.
    send_tx: Option<tokio::sync::mpsc::UnboundedSender<OutgoingMessage>>,
}

impl App {
    /// Create a new App instance and initialize terminal state.
    pub async fn new() -> Result<Self> {
        let backend = CrosstermBackend::new(io::stdout());
        let terminal = Terminal::new(backend)?;
        let state = AppState::new();

        Ok(Self {
            state,
            terminal,
            should_quit: false,
            database: None,
            event_rx: None,
            send_tx: None,
        })
    }

    /// Create a new App with a database at the given path.
    pub async fn with_database(db_path: &Path, passphrase: &str) -> Result<Self> {
        let backend = CrosstermBackend::new(io::stdout());
        let terminal = Terminal::new(backend)?;
        let mut state = AppState::new();

        let db = match signal_rs_store::Database::open(db_path, passphrase) {
            Ok(db) => {
                tracing::info!(?db_path, "opened database");
                Some(db)
            }
            Err(e) => {
                tracing::warn!(?db_path, %e, "failed to open database, running without store");
                None
            }
        };

        if db.is_some() {
            state.connection_status = ConnectionStatus::Connected;
            state.has_database = true;
        }

        // Ensure threads exist for all synced contacts/groups so they
        // appear in the conversation list even before any messages arrive.
        if let Some(ref db) = db {
            match db.ensure_threads_for_all_contacts_and_groups() {
                Ok(n) if n > 0 => tracing::info!(created = n, "created threads for synced contacts/groups"),
                Ok(_) => {}
                Err(e) => tracing::warn!(%e, "failed to ensure threads for contacts/groups"),
            }
        }

        let mut app = Self {
            state,
            terminal,
            should_quit: false,
            database: db,
            event_rx: None,
            send_tx: None,
        };

        app.load_conversations_from_store();
        app.load_settings_from_store();
        Ok(app)
    }

    /// Set up a background event channel and return the sender.
    pub fn setup_event_channel(&mut self) -> tokio::sync::mpsc::UnboundedSender<AppEvent> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.event_rx = Some(rx);
        tx
    }

    /// Set the channel for sending outgoing messages via the manager.
    pub fn set_send_channel(&mut self, tx: tokio::sync::mpsc::UnboundedSender<OutgoingMessage>) {
        self.send_tx = Some(tx);
    }

    /// Load settings from the database.
    fn load_settings_from_store(&mut self) {
        let db = match &self.database {
            Some(db) => db,
            None => return,
        };

        if let Ok(Some(val)) = db.get_kv_string("setting_notifications") {
            self.state.settings.notifications_enabled = val == "1";
        }
        if let Ok(Some(val)) = db.get_kv_string("setting_typing_indicators") {
            self.state.settings.typing_indicators_enabled = val == "1";
        }
        if let Ok(Some(val)) = db.get_kv_string("setting_read_receipts") {
            self.state.settings.read_receipts_enabled = val == "1";
        }
        if let Ok(Some(phone)) = db.get_kv_string(signal_rs_store::database::account_keys::PHONE_NUMBER) {
            self.state.settings.phone_number = Some(phone);
        }
    }

    /// Save a single setting to the database.
    fn save_setting(&self, key: &str, enabled: bool) {
        if let Some(db) = &self.database {
            let val = if enabled { "1" } else { "0" };
            if let Err(e) = db.set_kv_string(key, val) {
                tracing::error!(%e, key, "failed to save setting");
            }
        }
    }

    /// Load conversations from the store into state.
    pub fn load_conversations_from_store(&mut self) {
        let db = match &self.database {
            Some(db) => db,
            None => return,
        };

        let threads = match db.list_active_threads() {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(%e, "failed to list threads");
                return;
            }
        };

        let mut conversations = Vec::with_capacity(threads.len());
        for thread in &threads {
            let (name, is_group, entity_id, is_muted) = if let Some(rid) = thread.recipient_id {
                match db.get_recipient_by_id(rid) {
                    Ok(Some(r)) => {
                        let muted = r.mute_until > 0;
                        (r.display_name(), false, r.aci.clone(), muted)
                    }
                    _ => (format!("Contact #{rid}"), false, None, false),
                }
            } else if let Some(gid) = thread.group_id {
                match db.get_group_by_id(gid) {
                    Ok(Some(g)) => {
                        // Decrypt the group title from the cached group data protobuf.
                        let title = Self::decrypt_group_title(&g).unwrap_or_default();
                        let name = if title.is_empty() {
                            format!("Group #{gid}")
                        } else {
                            title
                        };
                        (name, true, None, false)
                    }
                    _ => (format!("Group #{gid}"), true, None, false),
                }
            } else {
                ("Unknown".to_string(), false, None, false)
            };

            // Get the last message preview.
            let last_message = match db.get_messages_by_thread(thread.id, 1, None) {
                Ok(msgs) => msgs
                    .last()
                    .and_then(|m| m.body.clone())
                    .unwrap_or_default(),
                Err(_) => String::new(),
            };

            let last_timestamp = thread
                .last_message_timestamp
                .map(format_timestamp)
                .unwrap_or_default();

            conversations.push(ConversationSummary {
                id: thread.id.to_string(),
                name,
                last_message,
                last_timestamp,
                last_timestamp_millis: thread.last_message_timestamp,
                unread_count: thread.unread_count as usize,
                is_group,
                thread_id: Some(thread.id),
                entity_id,
                is_pinned: thread.pinned,
                is_muted,
            });
        }

        // Sort: pinned first, then by timestamp.
        conversations.sort_by(|a, b| {
            b.is_pinned
                .cmp(&a.is_pinned)
                .then_with(|| b.last_timestamp.cmp(&a.last_timestamp))
        });

        self.state.unread_total = conversations.iter().map(|c| c.unread_count).sum();
        self.state.conversations = conversations;
    }

    /// Try to decrypt the group title from the cached `group_data` protobuf.
    fn decrypt_group_title(g: &signal_rs_store::models::group::GroupV2) -> Option<String> {
        use prost::Message as ProstMessage;
        let data = g.group_data.as_ref()?;
        let group_proto = signal_rs_protos::Group::decode(data.as_slice()).ok()?;
        let encrypted_title = group_proto.title.as_ref()?;
        let master_key =
            signal_rs_service::groups::GroupMasterKey::from_bytes(&g.master_key).ok()?;
        master_key.decrypt_title(encrypted_title).ok()
    }

    /// Convert a store Message to a ChatMessage for display.
    fn message_to_chat_message(
        db: &signal_rs_store::Database,
        m: &signal_rs_store::models::message::Message,
    ) -> ChatMessage {
        let sender = if m.sender_id.is_some() {
            m.sender_id
                .and_then(|sid| db.get_recipient_by_id(sid).ok().flatten())
                .map(|r| r.display_name())
                .unwrap_or_else(|| "Unknown".to_string())
        } else {
            "You".to_string()
        };

        let is_outgoing = m.sender_id.is_none();

        // Parse attachments JSON if present.
        let attachments = m
            .attachments_json
            .as_deref()
            .and_then(|json| {
                serde_json::from_str::<Vec<serde_json::Value>>(json).ok()
            })
            .map(|arr| {
                arr.iter()
                    .map(|v| crate::state::app_state::AttachmentInfo {
                        file_name: v["fileName"]
                            .as_str()
                            .unwrap_or("file")
                            .to_string(),
                        content_type: v["contentType"]
                            .as_str()
                            .unwrap_or("application/octet-stream")
                            .to_string(),
                        size: v["size"].as_u64(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Attempt to build a reply preview with sender name.
        let (reply_preview, reply_sender) = match m.quote_id {
            Some(qid) => match db.get_message_by_id(qid).ok().flatten() {
                Some(qm) => {
                    let qsender = if qm.sender_id.is_some() {
                        qm.sender_id
                            .and_then(|sid| db.get_recipient_by_id(sid).ok().flatten())
                            .map(|r| r.display_name())
                            .unwrap_or_else(|| "Unknown".to_string())
                    } else {
                        "You".to_string()
                    };
                    (qm.body, Some(qsender))
                }
                None => (None, None),
            },
            None => (None, None),
        };

        // Load reaction summary from database.
        let reactions = db
            .get_reaction_summary(m.id)
            .unwrap_or_default();

        // Check if this is a view-once message (expires_in set to a very short duration,
        // or we use the convention of expires_in == -1 for view-once).
        // For now, view_once is indicated by expires_in == -1.
        let view_once = m.expires_in == Some(-1);

        ChatMessage {
            id: m.id.to_string(),
            sender,
            body: m.body.clone().unwrap_or_default(),
            timestamp: format_timestamp(m.timestamp),
            timestamp_millis: m.timestamp,
            is_outgoing,
            is_read: m.read,
            db_id: Some(m.id),
            attachments,
            reply_preview,
            reply_sender,
            reactions,
            view_once,
        }
    }

    /// Load messages for a specific thread into the active chat.
    pub fn load_messages_for_chat(&mut self, thread_id: i64) {
        let db = match &self.database {
            Some(db) => db,
            None => return,
        };

        let messages = match db.get_messages_by_thread(thread_id, 100, None) {
            Ok(msgs) => msgs,
            Err(e) => {
                tracing::error!(%e, thread_id, "failed to load messages");
                return;
            }
        };

        // Track pagination state.
        let fetched_count = messages.len();
        self.state.oldest_loaded_timestamp = messages.first().map(|m| m.timestamp);
        self.state.has_more_messages = fetched_count >= 100;

        let chat_messages: Vec<ChatMessage> = messages
            .iter()
            .map(|m| Self::message_to_chat_message(db, m))
            .collect();

        if let Some(chat) = &mut self.state.active_chat {
            chat.messages = chat_messages;
        }

        // Mark all messages in this thread as read.
        if let Some(latest) = messages.last()
            && let Err(e) = db.mark_messages_read(thread_id, latest.timestamp)
        {
            tracing::error!(%e, thread_id, "failed to mark messages as read");
        }
        if let Err(e) = db.reset_thread_unread_count(thread_id) {
            tracing::error!(%e, thread_id, "failed to reset unread count");
        }

        // Update the in-memory unread count for this conversation.
        if let Some(conv) = self.state.conversations.iter_mut().find(|c| c.thread_id == Some(thread_id)) {
            conv.unread_count = 0;
        }

        // Auto-scroll to bottom.
        self.state.scroll_to_bottom();
    }

    /// Load older messages for the current thread (pagination).
    fn load_older_messages(&mut self) {
        let (thread_id, oldest_ts) = match (self.state.active_thread_id, self.state.oldest_loaded_timestamp) {
            (Some(tid), Some(ts)) => (tid, ts),
            _ => return,
        };

        let db = match &self.database {
            Some(db) => db,
            None => return,
        };

        let older = match db.get_messages_by_thread(thread_id, 100, Some(oldest_ts)) {
            Ok(msgs) => msgs,
            Err(e) => {
                tracing::error!(%e, thread_id, "failed to load older messages");
                return;
            }
        };

        if older.is_empty() {
            self.state.has_more_messages = false;
            return;
        }

        let fetched_count = older.len();
        self.state.oldest_loaded_timestamp = older.first().map(|m| m.timestamp);
        self.state.has_more_messages = fetched_count >= 100;

        let older_chat_messages: Vec<ChatMessage> = older
            .iter()
            .map(|m| Self::message_to_chat_message(db, m))
            .collect();

        let prepended_count = older_chat_messages.len();
        if let Some(chat) = &mut self.state.active_chat {
            let mut merged = older_chat_messages;
            merged.append(&mut chat.messages);
            chat.messages = merged;
        }

        // Adjust scroll and selection to keep the same messages in view.
        self.state.selected_message_index += prepended_count;
        self.state.message_scroll_offset += prepended_count;

        self.state.show_notification(
            format!("Loaded {prepended_count} older messages"),
            crate::state::app_state::NotificationLevel::Info,
        );
    }

    /// Run the main event loop.
    pub async fn run(&mut self) -> Result<()> {
        // Setup terminal
        crossterm::terminal::enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        self.terminal.clear()?;

        let result = self.event_loop().await;

        // Cleanup terminal (always runs)
        crossterm::terminal::disable_raw_mode()?;
        execute!(io::stdout(), LeaveAlternateScreen)?;
        self.terminal.show_cursor()?;

        result
    }

    async fn event_loop(&mut self) -> Result<()> {
        loop {
            // Clear expired notifications
            self.state.clear_expired_notifications();

            // Clean stale typing indicators (5 second timeout).
            self.state
                .clean_stale_typing_indicators(std::time::Duration::from_secs(5));

            // View: render UI from state
            self.terminal
                .draw(|frame| ui::render(frame, &self.state))?;

            // Read the next terminal event using spawn_blocking.
            let term_event_future = tokio::task::spawn_blocking(crossterm_event::read);

            // Check if we have a background event receiver.
            if let Some(rx) = &mut self.event_rx {
                tokio::select! {
                    event = term_event_future => {
                        match event {
                            Ok(Ok(ev)) => {
                                if let Some(action) = crate::event::handle_event(ev, &self.state) {
                                    self.handle_action(action).await?;
                                }
                            }
                            Ok(Err(e)) => {
                                tracing::error!("Error reading event: {e}");
                            }
                            Err(e) => {
                                tracing::error!("Event task panicked: {e}");
                            }
                        }
                    }
                    app_event = rx.recv() => {
                        if let Some(app_event) = app_event {
                            self.handle_app_event(app_event);
                        }
                    }
                }
            } else {
                // No background event channel; just wait for terminal events.
                match term_event_future.await {
                    Ok(Ok(ev)) => {
                        if let Some(action) = crate::event::handle_event(ev, &self.state) {
                            self.handle_action(action).await?;
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::error!("Error reading event: {e}");
                    }
                    Err(e) => {
                        tracing::error!("Event task panicked: {e}");
                    }
                }
            }

            if self.should_quit {
                break;
            }
        }

        Ok(())
    }

    /// Handle a background application event.
    fn handle_app_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::IncomingMessage { thread_id, message } => {
                // System bell notification for incoming messages.
                if self.state.settings.notifications_enabled {
                    print!("\x07");
                }

                // If this thread is currently open, add the message and mark read.
                let is_active = self.state.active_thread_id == Some(thread_id);
                if is_active {
                    if let Some(chat) = &mut self.state.active_chat {
                        chat.messages.push((*message).clone());
                        // Auto-scroll if already at bottom.
                        let msg_count = chat.messages.len();
                        if self.state.message_scroll_offset >= msg_count.saturating_sub(2) {
                            self.state.message_scroll_offset = msg_count.saturating_sub(1);
                        }
                    }
                    // Mark as read immediately since the user is viewing this chat.
                    if let Some(db) = &self.database {
                        let _ = db.mark_messages_read(thread_id, message.timestamp_millis);
                        let _ = db.reset_thread_unread_count(thread_id);
                    }
                }

                // Update sidebar preview.
                if let Some(conv) = self.state.conversations.iter_mut().find(|c| {
                    c.thread_id == Some(thread_id)
                }) {
                    conv.last_message = message.body.clone();
                    conv.last_timestamp = message.timestamp.clone();
                    conv.last_timestamp_millis = Some(message.timestamp_millis);
                    if !is_active {
                        conv.unread_count += 1;
                        self.state.unread_total += 1;
                    }
                }
            }
            AppEvent::TypingIndicator {
                thread_id: _,
                sender,
                is_typing,
            } => {
                if is_typing {
                    self.state
                        .typing_indicators
                        .insert(sender, Instant::now());
                } else {
                    self.state.typing_indicators.remove(&sender);
                }
            }
            AppEvent::ConnectionChanged(status) => {
                self.state.connection_status = match status {
                    ConnectionStatusEvent::Connected => ConnectionStatus::Connected,
                    ConnectionStatusEvent::Connecting => ConnectionStatus::Connecting,
                    ConnectionStatusEvent::Disconnected => ConnectionStatus::Disconnected,
                };
            }
            AppEvent::ReadReceipt {
                thread_id,
                timestamp: _,
            } => {
                // Mark messages as read in the active chat.
                if self.state.active_thread_id == Some(thread_id)
                    && let Some(chat) = &mut self.state.active_chat {
                        for msg in &mut chat.messages {
                            if msg.is_outgoing {
                                msg.is_read = true;
                            }
                        }
                    }
            }
            AppEvent::StorageSyncComplete => {
                tracing::info!("storage sync complete, reloading conversations");
                self.load_conversations_from_store();
            }
        }
    }

    /// Handle a dispatched action by updating state.
    async fn handle_action(&mut self, action: Action) -> Result<()> {
        match action {
            Action::Quit => {
                self.should_quit = true;
            }
            Action::NavigateUp => {
                if self.state.navigation == crate::state::NavigationState::Settings {
                    self.state.settings_navigate_up();
                } else {
                    self.state.navigate_up();
                }
            }
            Action::NavigateDown => {
                if self.state.navigation == crate::state::NavigationState::Settings {
                    self.state.settings_navigate_down();
                } else {
                    self.state.navigate_down();
                }
            }
            Action::SelectConversation => {
                if self.state.navigation == crate::state::NavigationState::Search {
                    self.select_search_result();
                } else {
                    self.state.select_conversation();
                    // Load messages from store if available.
                    if let Some(thread_id) = self.state.active_thread_id {
                        self.load_messages_for_chat(thread_id);
                    }
                }
            }
            Action::GoBack => {
                self.state.go_back();
            }
            Action::SendMessage => {
                // Check if we are in edit mode.
                if self.state.edit_message.is_some() {
                    if let Some((edit_ctx, new_body)) = self.state.finish_edit() {
                        // Persist edit to database.
                        if let Some(db) = &self.database
                            && edit_ctx.message_id > 0
                                && let Err(e) = db.update_message_body(edit_ctx.message_id, &new_body) {
                                    tracing::error!(%e, "failed to update message in store");
                                }
                        self.state.show_notification(
                            "Message edited".to_string(),
                            crate::state::app_state::NotificationLevel::Info,
                        );
                    }
                } else {
                    let thread_id = self.state.active_thread_id;
                    let body = self.state.input_buffer.clone();
                    let quote_id = self.state.reply_to.as_ref().map(|r| r.message_id);

                    // Build attachments JSON if there are pending attachments.
                    let attachments_json = if self.state.pending_attachments.is_empty() {
                        None
                    } else {
                        let att_arr: Vec<serde_json::Value> = self
                            .state
                            .pending_attachments
                            .iter()
                            .map(|p| {
                                let name = p
                                    .file_name()
                                    .map(|n| n.to_string_lossy().to_string())
                                    .unwrap_or_else(|| "file".to_string());
                                let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                                serde_json::json!({
                                    "fileName": name,
                                    "contentType": "application/octet-stream",
                                    "size": size,
                                })
                            })
                            .collect();
                        serde_json::to_string(&att_arr).ok()
                    };

                    // Capture attachment file paths before clearing state.
                    let attachment_paths: Vec<String> = self
                        .state
                        .pending_attachments
                        .iter()
                        .map(|p| p.to_string_lossy().to_string())
                        .collect();

                    self.state.send_message();
                    self.state.clear_attachments();

                    // Persist to database if available.
                    if let (Some(db), Some(tid)) = (&self.database, thread_id)
                        && (!body.trim().is_empty() || attachments_json.is_some()) {
                            let ts = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as i64;

                            if let Err(e) = db.insert_message(
                                tid,
                                None, // sender_id None = outgoing
                                ts,
                                None,
                                Some(&body),
                                signal_rs_store::models::message::MessageType::Normal,
                                quote_id,
                                None,
                                attachments_json.as_deref(),
                            ) {
                                tracing::error!(%e, "failed to insert message into store");
                            }

                            if let Err(e) = db.update_thread_on_message(tid, ts, false) {
                                tracing::error!(%e, "failed to update thread timestamp");
                            }
                        }

                    // Send via the manager channel for actual network transmission.
                    if let Some(ref tx) = self.send_tx
                        && let Some(tid) = thread_id
                        && let Some(ref db) = self.database
                        && let Ok(Some(thread)) = db.get_thread_by_id(tid)
                        && let Some(recipient_id) = thread.recipient_id
                        && let Ok(Some(recipient)) = db.get_recipient_by_id(recipient_id)
                        && let Some(ref aci) = recipient.aci
                    {
                        let _ = tx.send(OutgoingMessage {
                            recipient_uuid: aci.clone(),
                            body: body.clone(),
                            attachments: attachment_paths,
                            quote_timestamp: None,
                        });
                    }
                }
            }
            Action::StartSearch => {
                self.state.start_search();
                self.update_search_results();
            }
            Action::CloseSearch => {
                self.state.close_search();
            }
            Action::InsertChar(c) => {
                self.state.insert_char(c);
                if self.state.navigation == crate::state::NavigationState::Search {
                    self.update_search_results();
                }
                self.state.update_command_palette();
            }
            Action::DeleteChar => {
                self.state.delete_char();
                if self.state.navigation == crate::state::NavigationState::Search {
                    self.update_search_results();
                }
                self.state.update_command_palette();
            }
            Action::DeleteCharForward => {
                self.state.delete_char_forward();
            }
            Action::ToggleHelp => {
                self.state.toggle_help();
            }
            Action::ScrollMessagesUp => {
                self.state.scroll_messages_up(10);
            }
            Action::ScrollMessagesDown => {
                self.state.scroll_messages_down(10);
            }
            Action::ScrollToBottom => {
                self.state.scroll_to_bottom();
            }
            Action::PinConversation => {
                // Toggle pin and persist to database.
                self.state.toggle_pin_conversation();
                if let Some(conv) = self.state.conversations.get(self.state.selected_index)
                    && let (Some(db), Some(tid)) = (&self.database, conv.thread_id)
                        && let Err(e) = db.set_thread_pinned(tid, conv.is_pinned) {
                            tracing::error!(%e, "failed to persist pin state");
                        }
            }
            Action::ArchiveConversation => {
                // Show confirmation before archiving.
                let idx = self.state.selected_index;
                if idx < self.state.conversations.len() {
                    let name = self.state.conversations[idx].name.clone();
                    self.state.show_confirm(
                        format!("Archive conversation \"{name}\"?"),
                        ConfirmAction::ArchiveConversation(idx),
                    );
                }
            }
            Action::CopyMessage => {
                // Copy the selected message to the internal clipboard and system clipboard.
                if let Some(chat) = &self.state.active_chat {
                    let idx = self.state.selected_message_index;
                    if let Some(msg) = chat.messages.get(idx) {
                        // Always store in the internal clipboard buffer.
                        self.state.clipboard = Some(msg.body.clone());

                        // Also try the system clipboard.
                        match arboard::Clipboard::new() {
                            Ok(mut clipboard) => {
                                if let Err(e) = clipboard.set_text(&msg.body) {
                                    tracing::error!(%e, "failed to copy to system clipboard");
                                }
                            }
                            Err(e) => {
                                tracing::error!(%e, "failed to access system clipboard");
                            }
                        }
                        self.state.show_notification(
                            "Copied to clipboard".to_string(),
                            crate::state::app_state::NotificationLevel::Info,
                        );
                    }
                }
            }
            Action::ReplyToMessage => {
                if let Some(chat) = &self.state.active_chat {
                    let idx = self.state.selected_message_index;
                    if let Some(msg) = chat.messages.get(idx) {
                        let preview = if msg.body.len() > 50 {
                            format!("{}...", &msg.body[..47])
                        } else {
                            msg.body.clone()
                        };
                        self.state.set_reply_to(ReplyContext {
                            message_id: msg.db_id.unwrap_or(0),
                            sender_name: msg.sender.clone(),
                            preview_text: preview,
                        });
                        self.state.enter_composing_mode();
                    }
                }
            }
            Action::DeleteMessage => {
                // Show confirmation before deleting.
                if let Some(chat) = &self.state.active_chat {
                    let idx = self.state.selected_message_index;
                    if idx < chat.messages.len() {
                        let preview = &chat.messages[idx].body;
                        let short = if preview.len() > 40 {
                            format!("{}...", &preview[..37])
                        } else {
                            preview.clone()
                        };
                        self.state.show_confirm(
                            format!("Delete message \"{short}\"?"),
                            ConfirmAction::DeleteMessage(idx),
                        );
                    }
                }
            }
            Action::CancelReply => {
                self.state.clear_reply();
            }
            Action::PasteFromClipboard => {
                match arboard::Clipboard::new() {
                    Ok(mut clipboard) => {
                        if let Ok(text) = clipboard.get_text() {
                            for c in text.chars() {
                                self.state.insert_char_at_cursor(c);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(%e, "failed to access clipboard for paste");
                    }
                }
            }
            Action::RefreshConversations => {
                self.load_conversations_from_store();
                self.state.show_notification(
                    "Conversations refreshed".to_string(),
                    crate::state::app_state::NotificationLevel::Info,
                );
            }
            Action::MoveCursorLeft => {
                self.state.move_cursor_left();
            }
            Action::MoveCursorRight => {
                self.state.move_cursor_right();
            }
            Action::MoveCursorHome => {
                self.state.move_cursor_home();
            }
            Action::MoveCursorEnd => {
                self.state.move_cursor_end();
            }
            Action::OpenSettings => {
                self.state.open_settings();
            }
            Action::ToggleSetting => {
                self.state.toggle_selected_setting();
                // Persist the toggled setting.
                match self.state.settings.selected_index {
                    0 => self.save_setting(
                        "setting_notifications",
                        self.state.settings.notifications_enabled,
                    ),
                    1 => self.save_setting(
                        "setting_typing_indicators",
                        self.state.settings.typing_indicators_enabled,
                    ),
                    2 => self.save_setting(
                        "setting_read_receipts",
                        self.state.settings.read_receipts_enabled,
                    ),
                    _ => {}
                }
            }
            Action::ConfirmYes => {
                if let Some(action) = self.state.accept_confirm() {
                    self.execute_confirmed_action(action);
                }
            }
            Action::ConfirmNo => {
                self.state.dismiss_confirm();
            }
            // -- File picker actions --
            Action::OpenFilePicker => {
                self.state.open_file_picker();
            }
            Action::FilePickerUp => {
                if let Some(fp) = &mut self.state.file_picker {
                    fp.navigate_up();
                }
            }
            Action::FilePickerDown => {
                if let Some(fp) = &mut self.state.file_picker {
                    fp.navigate_down();
                }
            }
            Action::FilePickerSelect => {
                let selected = self
                    .state
                    .file_picker
                    .as_mut()
                    .and_then(|fp| fp.select());
                if let Some(path) = selected {
                    let name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "file".to_string());
                    self.state.add_attachment(path);
                    self.state.close_file_picker();
                    self.state.show_notification(
                        format!("Attached: {name}"),
                        crate::state::app_state::NotificationLevel::Info,
                    );
                }
            }
            Action::FilePickerParent => {
                if let Some(fp) = &mut self.state.file_picker {
                    fp.go_parent();
                }
            }
            Action::FilePickerClose => {
                self.state.close_file_picker();
            }
            // -- Edit message --
            Action::EditMessage => {
                let idx = self.state.selected_message_index;
                // Only allow editing own messages.
                let is_own = self
                    .state
                    .active_chat
                    .as_ref()
                    .and_then(|chat| chat.messages.get(idx))
                    .map(|m| m.is_outgoing)
                    .unwrap_or(false);

                if is_own {
                    self.state.start_edit(idx);
                } else {
                    self.state.show_notification(
                        "Can only edit your own messages".to_string(),
                        crate::state::app_state::NotificationLevel::Warning,
                    );
                }
            }
            Action::CancelEdit => {
                self.state.cancel_edit();
            }
            // -- Emoji reaction --
            Action::StartEmojiReaction => {
                self.state.emoji_input_mode = true;
            }
            Action::EmojiInput(c) => {
                self.state.emoji_input_mode = false;
                // Show the reaction as a notification (actual reaction storage
                // requires the reactions table from the data layer).
                if let Some(chat) = &self.state.active_chat {
                    let idx = self.state.selected_message_index;
                    if let Some(msg) = chat.messages.get(idx) {
                        let preview = if msg.body.len() > 20 {
                            format!("{}...", &msg.body[..17])
                        } else {
                            msg.body.clone()
                        };
                        self.state.show_notification(
                            format!("Reacted {c} to \"{preview}\""),
                            crate::state::app_state::NotificationLevel::Info,
                        );
                    }
                }
            }
            Action::CancelEmojiInput => {
                self.state.emoji_input_mode = false;
            }
            Action::LoadOlderMessages => {
                self.load_older_messages();
            }
            Action::ViewOnceMessage => {
                if let Some(chat) = &self.state.active_chat {
                    let idx = self.state.selected_message_index;
                    if let Some(msg) = chat.messages.get(idx)
                        && msg.view_once
                            && let Some(db_id) = msg.db_id
                                && !self.state.viewed_once_messages.contains(&db_id) {
                                    self.state.viewed_once_messages.insert(db_id);
                                    self.state.show_notification(
                                        "View-once message viewed".to_string(),
                                        crate::state::app_state::NotificationLevel::Info,
                                    );
                                }
                }
            }
            // -- Chat mode switching --
            Action::EnterNavigationMode => {
                self.state.enter_navigation_mode();
            }
            Action::EnterComposingMode => {
                self.state.enter_composing_mode();
            }
            Action::EnterComposingWithChar(c) => {
                self.state.enter_composing_with_char(c);
            }
            // -- Panel focus --
            Action::FocusSidebar => {
                self.state.focus_sidebar();
                self.state.navigation = crate::state::NavigationState::ConversationList;
            }
            Action::FocusChat => {
                self.state.focus_chat();
            }
            // -- Command palette --
            Action::ExecuteCommand => {
                // Inline command dispatch to avoid async recursion.
                if let Some(cmd_id) = self.state.execute_selected_command() {
                    match cmd_id {
                        CommandId::Reply => {
                            if let Some(chat) = &self.state.active_chat {
                                let idx = self.state.selected_message_index;
                                if let Some(msg) = chat.messages.get(idx) {
                                    let preview = if msg.body.len() > 50 {
                                        format!("{}...", &msg.body[..47])
                                    } else {
                                        msg.body.clone()
                                    };
                                    self.state.set_reply_to(ReplyContext {
                                        message_id: msg.db_id.unwrap_or(0),
                                        sender_name: msg.sender.clone(),
                                        preview_text: preview,
                                    });
                                    self.state.enter_composing_mode();
                                }
                            }
                        }
                        CommandId::Edit => {
                            let idx = self.state.selected_message_index;
                            let is_own = self.state.active_chat.as_ref()
                                .and_then(|chat| chat.messages.get(idx))
                                .map(|m| m.is_outgoing)
                                .unwrap_or(false);
                            if is_own {
                                self.state.start_edit(idx);
                            } else {
                                self.state.show_notification(
                                    "Can only edit your own messages".to_string(),
                                    crate::state::app_state::NotificationLevel::Warning,
                                );
                            }
                        }
                        CommandId::Delete => {
                            if let Some(chat) = &self.state.active_chat {
                                let idx = self.state.selected_message_index;
                                if idx < chat.messages.len() {
                                    let preview = &chat.messages[idx].body;
                                    let short = if preview.len() > 40 {
                                        format!("{}...", &preview[..37])
                                    } else {
                                        preview.clone()
                                    };
                                    self.state.show_confirm(
                                        format!("Delete message \"{short}\"?"),
                                        ConfirmAction::DeleteMessage(idx),
                                    );
                                }
                            }
                        }
                        CommandId::Attach => {
                            self.state.open_file_picker();
                        }
                        CommandId::Search => {
                            self.state.start_search();
                            self.update_search_results();
                        }
                        CommandId::React => {
                            self.state.emoji_input_mode = true;
                        }
                        CommandId::Pin => {
                            self.state.toggle_pin_conversation();
                        }
                        CommandId::Mute => {
                            self.state.show_notification(
                                "Mute not yet implemented".to_string(),
                                crate::state::app_state::NotificationLevel::Warning,
                            );
                        }
                        CommandId::Settings => {
                            self.state.open_settings();
                        }
                        CommandId::Help => {
                            self.state.toggle_help();
                        }
                        CommandId::Quit => {
                            self.should_quit = true;
                        }
                    }
                }
            }
            Action::CommandPaletteUp => {
                self.state.command_palette_up();
            }
            Action::CommandPaletteDown => {
                self.state.command_palette_down();
            }
        }
        Ok(())
    }

    /// Execute an action that was confirmed by the user.
    fn execute_confirmed_action(&mut self, action: ConfirmAction) {
        match action {
            ConfirmAction::ArchiveConversation(idx) => {
                if idx < self.state.conversations.len() {
                    let conv = &self.state.conversations[idx];
                    // Persist archive to database.
                    if let (Some(db), Some(tid)) = (&self.database, conv.thread_id)
                        && let Err(e) = db.set_thread_archived(tid, true) {
                            tracing::error!(%e, "failed to persist archive state");
                        }
                    self.state.conversations.remove(idx);
                    if self.state.selected_index > 0
                        && self.state.selected_index >= self.state.conversations.len()
                    {
                        self.state.selected_index =
                            self.state.conversations.len().saturating_sub(1);
                    }
                    self.state.show_notification(
                        "Conversation archived".to_string(),
                        crate::state::app_state::NotificationLevel::Info,
                    );
                }
            }
            ConfirmAction::DeleteMessage(idx) => {
                if let Some(chat) = &mut self.state.active_chat
                    && idx < chat.messages.len() {
                        let msg = &chat.messages[idx];
                        if let (Some(db), Some(db_id)) = (&self.database, msg.db_id)
                            && let Err(e) = db.delete_message(db_id) {
                                tracing::error!(%e, "failed to delete message from store");
                            }
                        chat.messages.remove(idx);
                        if self.state.selected_message_index > 0
                            && self.state.selected_message_index >= chat.messages.len()
                        {
                            self.state.selected_message_index =
                                chat.messages.len().saturating_sub(1);
                        }
                        self.state.show_notification(
                            "Message deleted".to_string(),
                            crate::state::app_state::NotificationLevel::Info,
                        );
                    }
            }
        }
    }

    /// Update search results based on the current search query.
    fn update_search_results(&mut self) {
        let query = self.state.search_query.clone();
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();

        if query.is_empty() {
            // Show all conversations when query is empty.
            for (i, _conv) in self.state.conversations.iter().enumerate() {
                results.push(SearchResult::Conversation { index: i });
            }
        } else {
            // Search conversation names.
            for (i, conv) in self.state.conversations.iter().enumerate() {
                if conv.name.to_lowercase().contains(&query_lower) {
                    results.push(SearchResult::Conversation { index: i });
                }
            }

            // Full-text message search from database.
            if let Some(db) = &self.database
                && query.len() >= 2 {
                    match db.search_messages(&query) {
                        Ok(messages) => {
                            for msg in messages.iter().take(20) {
                                // Find the conversation name for this thread.
                                let conv_name = self
                                    .state
                                    .conversations
                                    .iter()
                                    .find(|c| c.thread_id == Some(msg.thread_id))
                                    .map(|c| c.name.clone())
                                    .unwrap_or_else(|| format!("Thread #{}", msg.thread_id));

                                let sender = if msg.sender_id.is_some() {
                                    msg.sender_id
                                        .and_then(|sid| {
                                            db.get_recipient_by_id(sid).ok().flatten()
                                        })
                                        .map(|r| r.display_name())
                                        .unwrap_or_else(|| "Unknown".to_string())
                                } else {
                                    "You".to_string()
                                };

                                let body = msg.body.clone().unwrap_or_default();
                                let preview = if body.len() > 60 {
                                    format!("{}...", &body[..57])
                                } else {
                                    body
                                };

                                results.push(SearchResult::Message {
                                    thread_id: msg.thread_id,
                                    message_id: msg.id,
                                    conversation_name: conv_name,
                                    sender,
                                    body_preview: preview,
                                });
                            }
                        }
                        Err(e) => {
                            tracing::error!(%e, "message search failed");
                        }
                    }
                }
        }

        self.state.search_results = results;
        self.state.selected_index = 0;
    }

    /// Handle selecting a search result.
    fn select_search_result(&mut self) {
        let idx = self.state.selected_index;
        if idx >= self.state.search_results.len() {
            return;
        }

        match self.state.search_results[idx].clone() {
            SearchResult::Conversation { index } => {
                // Select this conversation as if navigating to it.
                self.state.selected_index = index;
                self.state.is_searching = false;
                self.state.search_query.clear();
                self.state.search_results.clear();
                self.state.select_conversation();
                if let Some(thread_id) = self.state.active_thread_id {
                    self.load_messages_for_chat(thread_id);
                }
            }
            SearchResult::Message {
                thread_id,
                message_id,
                ..
            } => {
                // Find and select the conversation for this thread.
                let conv_idx = self
                    .state
                    .conversations
                    .iter()
                    .position(|c| c.thread_id == Some(thread_id));

                if let Some(idx) = conv_idx {
                    self.state.selected_index = idx;
                    self.state.is_searching = false;
                    self.state.search_query.clear();
                    self.state.search_results.clear();
                    self.state.select_conversation();
                    self.load_messages_for_chat(thread_id);

                    // Scroll to the matching message.
                    if let Some(chat) = &self.state.active_chat
                        && let Some(pos) = chat
                            .messages
                            .iter()
                            .position(|m| m.db_id == Some(message_id))
                        {
                            self.state.message_scroll_offset = pos;
                            self.state.selected_message_index = pos;
                        }
                }
            }
        }
    }
}

/// Format a millisecond-epoch timestamp for display.
fn format_timestamp(ts_millis: i64) -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let msg_time = UNIX_EPOCH + Duration::from_millis(ts_millis as u64);
    let now = SystemTime::now();

    let elapsed = now.duration_since(msg_time).unwrap_or_default();

    if elapsed.as_secs() < 86400 {
        // Today: show HH:MM
        let total_secs = (ts_millis / 1000) % 86400;
        let hours = total_secs / 3600;
        let minutes = (total_secs % 3600) / 60;
        format!("{hours:02}:{minutes:02}")
    } else if elapsed.as_secs() < 7 * 86400 {
        // This week: show day abbreviation
        let days = elapsed.as_secs() / 86400;
        match days {
            1 => "Yesterday".to_string(),
            _ => {
                // Simple day name approximation based on days ago
                let day_names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
                // Just show "N days ago" as a simpler fallback
                let now_secs = now
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let day_of_week = ((now_secs / 86400 + 4) % 7) as usize; // Thursday = epoch day
                let target_day = (day_of_week + 7 - (days as usize % 7)) % 7;
                day_names[target_day].to_string()
            }
        }
    } else {
        // Older: show "Mon DD" approximation
        let days_since_epoch = ts_millis / 1000 / 86400;
        let month_names = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        // Simple approximation: day of year
        let day_in_year = (days_since_epoch % 365) as usize;
        let month_idx = (day_in_year / 30).min(11);
        let day = (day_in_year % 30) + 1;
        format!("{} {day}", month_names[month_idx])
    }
}
