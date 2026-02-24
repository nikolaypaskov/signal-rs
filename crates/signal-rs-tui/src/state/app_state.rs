use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Instant;

use super::NavigationState;
use crate::ui::file_picker::FilePickerState;

/// Whether the user is composing a message or navigating messages in the chat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChatMode {
    #[default]
    Composing,
    Navigating,
}

/// Which panel currently has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FocusedPanel {
    #[default]
    Sidebar,
    Chat,
}

/// Identifier for a slash command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandId {
    Reply,
    Edit,
    Delete,
    Attach,
    Search,
    React,
    Pin,
    Mute,
    Settings,
    Help,
    Quit,
}

/// A command definition for the command palette.
pub struct CommandDef {
    pub id: CommandId,
    pub name: &'static str,
    pub description: &'static str,
}

/// All available slash commands.
pub const COMMANDS: &[CommandDef] = &[
    CommandDef { id: CommandId::Reply, name: "reply", description: "Reply to selected message" },
    CommandDef { id: CommandId::Edit, name: "edit", description: "Edit your last message" },
    CommandDef { id: CommandId::Delete, name: "delete", description: "Delete selected message" },
    CommandDef { id: CommandId::Attach, name: "attach", description: "Attach a file" },
    CommandDef { id: CommandId::Search, name: "search", description: "Search conversations" },
    CommandDef { id: CommandId::React, name: "react", description: "React with emoji" },
    CommandDef { id: CommandId::Pin, name: "pin", description: "Pin/unpin conversation" },
    CommandDef { id: CommandId::Mute, name: "mute", description: "Mute/unmute conversation" },
    CommandDef { id: CommandId::Settings, name: "settings", description: "Open settings" },
    CommandDef { id: CommandId::Help, name: "help", description: "Show keyboard shortcuts" },
    CommandDef { id: CommandId::Quit, name: "quit", description: "Quit application" },
];

/// State for the command palette popup.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct CommandPaletteState {
    pub active: bool,
    pub query: String,
    pub filtered: Vec<usize>,
    pub selected_index: usize,
}

/// The entire application state, maintained as a single source of truth.
pub struct AppState {
    /// Current navigation / view state.
    pub navigation: NavigationState,

    /// Previous navigation state (for going back).
    pub previous_navigation: NavigationState,

    /// List of conversation summaries shown in the sidebar.
    pub conversations: Vec<ConversationSummary>,

    /// Index of the currently selected conversation in the list.
    pub selected_index: usize,

    /// The currently active chat, if any.
    pub active_chat: Option<ActiveChat>,

    /// Currently selected thread's DB id.
    pub active_thread_id: Option<i64>,

    /// WebSocket / connection status.
    pub connection_status: ConnectionStatus,

    /// Current search query.
    pub search_query: String,

    /// Whether search mode is active.
    pub is_searching: bool,

    /// Current text input buffer (for composing messages).
    pub input_buffer: String,

    /// Whether the input area is focused for text entry.
    pub is_input_focused: bool,

    /// Active typing indicators from other users (sender name -> when started).
    pub typing_indicators: HashMap<String, Instant>,

    /// Total unread message count across all conversations.
    pub unread_total: usize,

    /// Whether the help overlay is visible.
    pub show_help: bool,

    /// Scroll offset for the message list.
    pub message_scroll_offset: usize,

    /// Index of the currently selected message (for message selection/scrolling).
    pub selected_message_index: usize,

    /// Message being replied to, if any.
    pub reply_to: Option<ReplyContext>,

    /// Toast notification to show, if any.
    pub notification: Option<Notification>,

    /// Cursor position within the input_buffer.
    pub cursor_position: usize,

    /// Settings state.
    pub settings: SettingsState,

    /// Confirmation dialog state, if one is active.
    pub confirm_dialog: Option<ConfirmDialog>,

    /// Search results from full-text message search.
    pub search_results: Vec<SearchResult>,

    /// Whether a database is connected (false means demo/unregistered mode).
    pub has_database: bool,

    /// File picker state, if the file picker is open.
    pub file_picker: Option<FilePickerState>,

    /// Pending attachment paths to send with the next message.
    pub pending_attachments: Vec<PathBuf>,

    /// Edit mode: when Some, the user is editing an existing message.
    pub edit_message: Option<EditContext>,

    /// Emoji reaction input mode: when true, the next character is treated as a reaction.
    pub emoji_input_mode: bool,

    /// Oldest loaded message timestamp for pagination (load-more-on-scroll-up).
    pub oldest_loaded_timestamp: Option<i64>,

    /// Whether there are potentially more messages to load (pagination).
    pub has_more_messages: bool,

    /// Set of view-once message IDs that have been viewed in this session.
    pub viewed_once_messages: HashSet<i64>,

    /// Internal clipboard buffer for copied message text.
    pub clipboard: Option<String>,

    /// Whether the user is composing or navigating messages in the chat.
    pub chat_mode: ChatMode,

    /// Which panel currently has keyboard focus.
    pub focused_panel: FocusedPanel,

    /// Command palette state.
    pub command_palette: CommandPaletteState,
}

/// Context for a message being replied to.
#[derive(Debug, Clone)]
pub struct ReplyContext {
    pub message_id: i64,
    pub sender_name: String,
    pub preview_text: String,
}

/// Context for editing an existing message.
#[derive(Debug, Clone)]
pub struct EditContext {
    /// Database ID of the message being edited.
    pub message_id: i64,
    /// Index of the message in the chat messages list.
    pub message_index: usize,
    /// The original message text (for cancellation).
    pub original_text: String,
}

/// A toast notification.
#[derive(Debug, Clone)]
pub struct Notification {
    pub message: String,
    pub level: NotificationLevel,
    pub expires_at: Instant,
}

/// Severity level for a notification toast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum NotificationLevel {
    Info,
    Warning,
    Error,
}

/// A summary of a conversation for display in the sidebar.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ConversationSummary {
    /// Unique identifier for the conversation.
    pub id: String,
    /// Display name (contact name or group name).
    pub name: String,
    /// Last message preview text.
    pub last_message: String,
    /// Timestamp of the last message as a formatted string.
    pub last_timestamp: String,
    /// Raw timestamp in milliseconds since epoch (for relative formatting).
    pub last_timestamp_millis: Option<i64>,
    /// Number of unread messages.
    pub unread_count: usize,
    /// Whether this is a group conversation.
    pub is_group: bool,
    /// Thread database ID, if backed by a database.
    pub thread_id: Option<i64>,
    /// Entity identifier (ACI or group ID hex).
    pub entity_id: Option<String>,
    /// Whether this conversation is pinned.
    pub is_pinned: bool,
    /// Whether this conversation is muted.
    pub is_muted: bool,
}

/// State for an active chat view.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ActiveChat {
    /// Conversation identifier.
    pub conversation_id: String,
    /// Display name of the conversation.
    pub name: String,
    /// Messages loaded in this chat.
    pub messages: Vec<ChatMessage>,
    /// Whether this is a group chat.
    pub is_group: bool,
}

/// A single chat message.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ChatMessage {
    /// Unique message identifier.
    pub id: String,
    /// Sender display name.
    pub sender: String,
    /// Message body text.
    pub body: String,
    /// Formatted timestamp.
    pub timestamp: String,
    /// Raw timestamp in milliseconds since epoch (for grouping/sorting).
    pub timestamp_millis: i64,
    /// Whether this message was sent by the local user.
    pub is_outgoing: bool,
    /// Whether this message has been read.
    pub is_read: bool,
    /// Database ID, if backed by a database.
    pub db_id: Option<i64>,
    /// Attachment info for this message.
    pub attachments: Vec<AttachmentInfo>,
    /// Reply/quote preview text, if this message is a reply.
    pub reply_preview: Option<String>,
    /// Reply/quote sender name, if this message is a reply.
    pub reply_sender: Option<String>,
    /// Reaction summary: emoji -> count.
    pub reactions: HashMap<String, u32>,
    /// Whether this is a view-once message.
    pub view_once: bool,
}

/// Information about a message attachment.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AttachmentInfo {
    pub file_name: String,
    pub content_type: String,
    pub size: Option<u64>,
}

/// Connection status indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionStatus {
    Connected,
    Connecting,
    #[default]
    Disconnected,
}

/// Settings state for the settings view.
#[derive(Debug, Clone)]
pub struct SettingsState {
    /// Currently selected setting index.
    pub selected_index: usize,
    /// Whether notifications are enabled.
    pub notifications_enabled: bool,
    /// Whether typing indicators are sent.
    pub typing_indicators_enabled: bool,
    /// Whether read receipts are sent.
    pub read_receipts_enabled: bool,
    /// The linked phone number, if available.
    pub phone_number: Option<String>,
}

impl Default for SettingsState {
    fn default() -> Self {
        Self {
            selected_index: 0,
            notifications_enabled: true,
            typing_indicators_enabled: true,
            read_receipts_enabled: true,
            phone_number: None,
        }
    }
}

/// A confirmation dialog shown as an overlay.
#[derive(Debug, Clone)]
pub struct ConfirmDialog {
    /// The message to display.
    pub message: String,
    /// The action to execute on confirmation.
    pub action: ConfirmAction,
}

/// Actions that can be triggered by a confirmation dialog.
#[derive(Debug, Clone)]
pub enum ConfirmAction {
    /// Archive the conversation at the given index.
    ArchiveConversation(usize),
    /// Delete the message at the given index.
    DeleteMessage(usize),
}

/// A search result entry, either a conversation match or a message match.
#[derive(Debug, Clone)]
pub enum SearchResult {
    /// A conversation name matched the query.
    Conversation {
        /// Index into the conversations list.
        index: usize,
    },
    /// A message body matched the query.
    Message {
        /// Thread ID the message belongs to.
        thread_id: i64,
        /// Message database ID.
        message_id: i64,
        /// Conversation name for display.
        conversation_name: String,
        /// The sender of the message.
        sender: String,
        /// Preview of the message body.
        body_preview: String,
    },
}

impl AppState {
    /// Create a new default AppState.
    pub fn new() -> Self {
        Self {
            navigation: NavigationState::default(),
            previous_navigation: NavigationState::default(),
            conversations: Vec::new(),
            selected_index: 0,
            active_chat: None,
            active_thread_id: None,
            connection_status: ConnectionStatus::default(),
            search_query: String::new(),
            is_searching: false,
            input_buffer: String::new(),
            is_input_focused: false,
            typing_indicators: HashMap::new(),
            unread_total: 0,
            show_help: false,
            message_scroll_offset: 0,
            selected_message_index: 0,
            reply_to: None,
            notification: None,
            cursor_position: 0,
            settings: SettingsState::default(),
            confirm_dialog: None,
            search_results: Vec::new(),
            has_database: false,
            file_picker: None,
            pending_attachments: Vec::new(),
            edit_message: None,
            emoji_input_mode: false,
            oldest_loaded_timestamp: None,
            has_more_messages: false,
            viewed_once_messages: HashSet::new(),
            clipboard: None,
            chat_mode: ChatMode::default(),
            focused_panel: FocusedPanel::default(),
            command_palette: CommandPaletteState::default(),
        }
    }

    /// Move selection up in the current list.
    pub fn navigate_up(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    /// Move selection down in the current list.
    pub fn navigate_down(&mut self) {
        let max = match self.navigation {
            NavigationState::ConversationList => {
                self.conversations.len().saturating_sub(1)
            }
            NavigationState::Search => {
                self.search_results.len().saturating_sub(1)
            }
            NavigationState::Chat => {
                if let Some(chat) = &self.active_chat {
                    chat.messages.len().saturating_sub(1)
                } else {
                    0
                }
            }
            NavigationState::Settings => {
                // 3 toggleable settings (0, 1, 2)
                2
            }
            _ => 0,
        };
        if self.selected_index < max {
            self.selected_index += 1;
        }
    }

    /// Select the currently highlighted conversation and open it.
    pub fn select_conversation(&mut self) {
        if self.conversations.is_empty() {
            return;
        }

        let conv = &self.conversations[self.selected_index];
        self.active_thread_id = conv.thread_id;
        self.active_chat = Some(ActiveChat {
            conversation_id: conv.id.clone(),
            name: conv.name.clone(),
            messages: Vec::new(),
            is_group: conv.is_group,
        });
        self.previous_navigation = self.navigation;
        self.navigation = NavigationState::Chat;
        self.is_input_focused = true;
        self.chat_mode = ChatMode::Composing;
        self.focused_panel = FocusedPanel::Chat;
        self.message_scroll_offset = 0;
        self.selected_message_index = 0;
        self.cursor_position = 0;
    }

    /// Go back to the previous view.
    pub fn go_back(&mut self) {
        self.is_input_focused = false;
        self.chat_mode = ChatMode::default();
        self.focused_panel = FocusedPanel::Sidebar;
        self.command_palette = CommandPaletteState::default();
        self.navigation = self.navigation.parent();
        if self.navigation == NavigationState::ConversationList {
            self.active_chat = None;
            self.active_thread_id = None;
            self.reply_to = None;
            self.oldest_loaded_timestamp = None;
            self.has_more_messages = false;
        }
    }

    /// Attempt to send the current input buffer as a message.
    pub fn send_message(&mut self) {
        if self.input_buffer.trim().is_empty() {
            return;
        }

        let reply_preview = self.reply_to.as_ref().map(|r| {
            format!("{}: {}", r.sender_name, r.preview_text)
        });

        if let Some(chat) = &mut self.active_chat {
            let now_millis = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            let msg = ChatMessage {
                id: uuid::Uuid::new_v4().to_string(),
                sender: "You".to_string(),
                body: self.input_buffer.clone(),
                timestamp: "now".to_string(),
                timestamp_millis: now_millis,
                is_outgoing: true,
                is_read: false,
                db_id: None,
                attachments: Vec::new(),
                reply_preview,
                reply_sender: None,
                reactions: HashMap::new(),
                view_once: false,
            };
            chat.messages.push(msg);
        }
        self.input_buffer.clear();
        self.cursor_position = 0;
        self.reply_to = None;
    }

    /// Enter search mode.
    pub fn start_search(&mut self) {
        self.previous_navigation = self.navigation;
        self.navigation = NavigationState::Search;
        self.is_searching = true;
        self.search_query.clear();
    }

    /// Exit search mode.
    pub fn close_search(&mut self) {
        self.is_searching = false;
        self.search_query.clear();
        self.navigation = self.previous_navigation;
    }

    /// Insert a character into the active input buffer.
    pub fn insert_char(&mut self, c: char) {
        // Special case: '\0' is used to signal "focus input"
        if c == '\0' {
            self.is_input_focused = true;
            return;
        }

        match self.navigation {
            NavigationState::Search => {
                self.search_query.push(c);
            }
            NavigationState::Chat => {
                self.is_input_focused = true;
                self.insert_char_at_cursor(c);
            }
            _ => {}
        }
    }

    /// Delete the last character from the active input buffer.
    pub fn delete_char(&mut self) {
        match self.navigation {
            NavigationState::Search => {
                self.search_query.pop();
            }
            NavigationState::Chat => {
                self.delete_char_at_cursor();
            }
            _ => {}
        }
    }

    /// Toggle the help overlay.
    pub fn toggle_help(&mut self) {
        if self.navigation == NavigationState::Help {
            self.navigation = self.previous_navigation;
            self.show_help = false;
        } else {
            self.previous_navigation = self.navigation;
            self.navigation = NavigationState::Help;
            self.show_help = true;
        }
    }

    // -- Reply management --

    /// Set the reply context.
    pub fn set_reply_to(&mut self, ctx: ReplyContext) {
        self.reply_to = Some(ctx);
    }

    /// Clear the reply context.
    pub fn clear_reply(&mut self) {
        self.reply_to = None;
    }

    // -- Notification management --

    /// Show a notification toast.
    pub fn show_notification(&mut self, message: String, level: NotificationLevel) {
        self.notification = Some(Notification {
            message,
            level,
            expires_at: Instant::now() + std::time::Duration::from_secs(3),
        });
    }

    /// Clear expired notifications.
    pub fn clear_expired_notifications(&mut self) {
        if let Some(n) = &self.notification
            && Instant::now() >= n.expires_at {
                self.notification = None;
            }
    }

    // -- Cursor-aware input methods --

    /// Insert a character at the current cursor position.
    pub fn insert_char_at_cursor(&mut self, c: char) {
        let byte_pos = self.cursor_byte_position();
        self.input_buffer.insert(byte_pos, c);
        self.cursor_position += 1;
    }

    /// Delete the character before the cursor.
    pub fn delete_char_at_cursor(&mut self) {
        if self.cursor_position > 0 {
            let byte_pos = self.cursor_byte_position();
            // Find the start of the previous character.
            let prev_char_start = self.input_buffer[..byte_pos]
                .char_indices()
                .next_back()
                .map(|(i, _)| i)
                .unwrap_or(0);
            self.input_buffer.remove(prev_char_start);
            self.cursor_position -= 1;
        }
    }

    /// Delete the character at the cursor (forward delete).
    pub fn delete_char_forward(&mut self) {
        let char_count = self.input_buffer.chars().count();
        if self.cursor_position < char_count {
            let byte_pos = self.cursor_byte_position();
            self.input_buffer.remove(byte_pos);
        }
    }

    /// Move cursor left by one character.
    pub fn move_cursor_left(&mut self) {
        if self.cursor_position > 0 {
            self.cursor_position -= 1;
        }
    }

    /// Move cursor right by one character.
    pub fn move_cursor_right(&mut self) {
        let char_count = self.input_buffer.chars().count();
        if self.cursor_position < char_count {
            self.cursor_position += 1;
        }
    }

    /// Move cursor to the beginning of the input buffer.
    pub fn move_cursor_home(&mut self) {
        self.cursor_position = 0;
    }

    /// Move cursor to the end of the input buffer.
    pub fn move_cursor_end(&mut self) {
        self.cursor_position = self.input_buffer.chars().count();
    }

    /// Convert the character-based cursor_position to a byte offset in input_buffer.
    fn cursor_byte_position(&self) -> usize {
        self.input_buffer
            .char_indices()
            .nth(self.cursor_position)
            .map(|(i, _)| i)
            .unwrap_or(self.input_buffer.len())
    }

    // -- Scroll helpers --

    /// Scroll messages up by one page.
    pub fn scroll_messages_up(&mut self, page_size: usize) {
        self.message_scroll_offset = self.message_scroll_offset.saturating_sub(page_size);
    }

    /// Scroll messages down by one page.
    pub fn scroll_messages_down(&mut self, page_size: usize) {
        if let Some(chat) = &self.active_chat {
            let max_offset = chat.messages.len().saturating_sub(1);
            self.message_scroll_offset = (self.message_scroll_offset + page_size).min(max_offset);
        }
    }

    /// Scroll to the bottom of messages.
    pub fn scroll_to_bottom(&mut self) {
        if let Some(chat) = &self.active_chat {
            self.message_scroll_offset = chat.messages.len().saturating_sub(1);
        }
    }

    // -- Pin/Archive/Mute helpers --

    /// Toggle pinned state for the currently selected conversation.
    pub fn toggle_pin_conversation(&mut self) {
        if let Some(conv) = self.conversations.get_mut(self.selected_index) {
            conv.is_pinned = !conv.is_pinned;
        }
        self.sort_conversations();
    }

    /// Toggle archive (remove from list) for the currently selected conversation.
    #[allow(dead_code)]
    pub fn archive_conversation(&mut self) {
        if self.selected_index < self.conversations.len() {
            self.conversations.remove(self.selected_index);
            if self.selected_index > 0 && self.selected_index >= self.conversations.len() {
                self.selected_index = self.conversations.len().saturating_sub(1);
            }
        }
    }

    /// Sort conversations: pinned first, then by last timestamp descending.
    fn sort_conversations(&mut self) {
        self.conversations.sort_by(|a, b| {
            b.is_pinned
                .cmp(&a.is_pinned)
                .then_with(|| b.last_timestamp.cmp(&a.last_timestamp))
        });
    }

    // -- Settings navigation --

    /// Open the settings view.
    pub fn open_settings(&mut self) {
        self.previous_navigation = self.navigation;
        self.navigation = NavigationState::Settings;
        self.settings.selected_index = 0;
    }

    /// Toggle the currently selected setting.
    pub fn toggle_selected_setting(&mut self) {
        match self.settings.selected_index {
            0 => self.settings.notifications_enabled = !self.settings.notifications_enabled,
            1 => self.settings.typing_indicators_enabled = !self.settings.typing_indicators_enabled,
            2 => self.settings.read_receipts_enabled = !self.settings.read_receipts_enabled,
            _ => {}
        }
    }

    // -- Confirmation dialog --

    /// Show a confirmation dialog.
    pub fn show_confirm(&mut self, message: String, action: ConfirmAction) {
        self.confirm_dialog = Some(ConfirmDialog { message, action });
    }

    /// Dismiss the confirmation dialog without executing the action.
    pub fn dismiss_confirm(&mut self) {
        self.confirm_dialog = None;
    }

    /// Accept the confirmation dialog and return the action to execute.
    pub fn accept_confirm(&mut self) -> Option<ConfirmAction> {
        self.confirm_dialog.take().map(|d| d.action)
    }

    // -- Typing indicator cleanup --

    /// Remove typing indicators older than the given duration.
    pub fn clean_stale_typing_indicators(&mut self, timeout: std::time::Duration) {
        let now = Instant::now();
        self.typing_indicators
            .retain(|_, started| now.duration_since(*started) < timeout);
    }

    // -- Search results navigation --

    /// Navigate up in settings.
    pub fn settings_navigate_up(&mut self) {
        if self.settings.selected_index > 0 {
            self.settings.selected_index -= 1;
        }
    }

    /// Navigate down in settings.
    pub fn settings_navigate_down(&mut self) {
        if self.settings.selected_index < 2 {
            self.settings.selected_index += 1;
        }
    }

    // -- File picker management --

    /// Open the file picker dialog.
    pub fn open_file_picker(&mut self) {
        let start_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        self.file_picker = Some(FilePickerState::new(start_dir));
    }

    /// Close the file picker dialog.
    pub fn close_file_picker(&mut self) {
        self.file_picker = None;
    }

    /// Add a pending attachment.
    pub fn add_attachment(&mut self, path: PathBuf) {
        self.pending_attachments.push(path);
    }

    /// Clear all pending attachments.
    pub fn clear_attachments(&mut self) {
        self.pending_attachments.clear();
    }

    // -- Edit mode management --

    /// Enter edit mode for a message at the given index.
    pub fn start_edit(&mut self, index: usize) {
        if let Some(chat) = &self.active_chat
            && let Some(msg) = chat.messages.get(index)
                && msg.is_outgoing {
                    self.edit_message = Some(EditContext {
                        message_id: msg.db_id.unwrap_or(0),
                        message_index: index,
                        original_text: msg.body.clone(),
                    });
                    self.input_buffer = msg.body.clone();
                    self.cursor_position = self.input_buffer.chars().count();
                    self.is_input_focused = true;
                }
    }

    /// Cancel edit mode and restore the original text.
    pub fn cancel_edit(&mut self) {
        self.edit_message = None;
        self.input_buffer.clear();
        self.cursor_position = 0;
    }

    /// Complete editing: update the message body in the chat and return the edit context.
    pub fn finish_edit(&mut self) -> Option<(EditContext, String)> {
        if let Some(edit_ctx) = self.edit_message.take() {
            let new_body = self.input_buffer.clone();
            if !new_body.trim().is_empty() && new_body != edit_ctx.original_text {
                // Update the message in the local chat state.
                if let Some(chat) = &mut self.active_chat
                    && let Some(msg) = chat.messages.get_mut(edit_ctx.message_index) {
                        msg.body = new_body.clone();
                    }
                self.input_buffer.clear();
                self.cursor_position = 0;
                return Some((edit_ctx, new_body));
            }
            self.input_buffer.clear();
            self.cursor_position = 0;
        }
        None
    }

    // -- Chat mode management --

    /// Enter navigation mode (browse messages with j/k).
    pub fn enter_navigation_mode(&mut self) {
        self.chat_mode = ChatMode::Navigating;
        self.is_input_focused = false;
        self.command_palette = CommandPaletteState::default();
    }

    /// Enter composing mode (typing goes to input buffer).
    pub fn enter_composing_mode(&mut self) {
        self.chat_mode = ChatMode::Composing;
        self.is_input_focused = true;
    }

    /// Enter composing mode and insert a character.
    pub fn enter_composing_with_char(&mut self, c: char) {
        self.enter_composing_mode();
        self.insert_char_at_cursor(c);
    }

    // -- Panel focus management --

    /// Focus the sidebar panel.
    pub fn focus_sidebar(&mut self) {
        self.focused_panel = FocusedPanel::Sidebar;
        self.is_input_focused = false;
        if self.navigation == NavigationState::Chat {
            self.chat_mode = ChatMode::Navigating;
        }
    }

    /// Focus the chat panel.
    pub fn focus_chat(&mut self) {
        if self.active_chat.is_some() {
            self.focused_panel = FocusedPanel::Chat;
            self.navigation = NavigationState::Chat;
            self.enter_composing_mode();
        }
    }

    // -- Command palette management --

    /// Update the command palette state based on current input buffer.
    pub fn update_command_palette(&mut self) {
        if self.input_buffer.starts_with('/') {
            let query = self.input_buffer[1..].to_lowercase();
            let filtered: Vec<usize> = COMMANDS
                .iter()
                .enumerate()
                .filter(|(_, cmd)| {
                    query.is_empty()
                        || cmd.name.contains(&query)
                        || cmd.description.to_lowercase().contains(&query)
                })
                .map(|(i, _)| i)
                .collect();
            self.command_palette = CommandPaletteState {
                active: true,
                query,
                selected_index: self.command_palette.selected_index.min(
                    filtered.len().saturating_sub(1),
                ),
                filtered,
            };
        } else {
            self.command_palette = CommandPaletteState::default();
        }
    }

    /// Move the command palette selection up.
    pub fn command_palette_up(&mut self) {
        if self.command_palette.selected_index > 0 {
            self.command_palette.selected_index -= 1;
        }
    }

    /// Move the command palette selection down.
    pub fn command_palette_down(&mut self) {
        let max = self.command_palette.filtered.len().saturating_sub(1);
        if self.command_palette.selected_index < max {
            self.command_palette.selected_index += 1;
        }
    }

    /// Execute the currently selected command and return its CommandId.
    pub fn execute_selected_command(&mut self) -> Option<CommandId> {
        let idx = self.command_palette.selected_index;
        let cmd_idx = self.command_palette.filtered.get(idx).copied()?;
        let id = COMMANDS[cmd_idx].id;
        // Clear input and palette.
        self.input_buffer.clear();
        self.cursor_position = 0;
        self.command_palette = CommandPaletteState::default();
        Some(id)
    }
}
