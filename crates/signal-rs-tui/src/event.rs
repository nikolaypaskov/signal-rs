use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use crate::state::app_state::ChatMode;
use crate::state::{AppState, NavigationState};
use crate::state::app_state::ChatMessage;

/// Actions that can be dispatched from events.
#[derive(Debug, Clone)]
pub enum Action {
    Quit,
    NavigateUp,
    NavigateDown,
    SelectConversation,
    GoBack,
    SendMessage,
    StartSearch,
    CloseSearch,
    InsertChar(char),
    DeleteChar,
    ToggleHelp,
    // Message scrolling
    ScrollMessagesUp,
    ScrollMessagesDown,
    ScrollToBottom,
    // Conversation management
    ArchiveConversation,
    PinConversation,
    // Message actions
    CopyMessage,
    ReplyToMessage,
    DeleteMessage,
    CancelReply,
    // Clipboard
    PasteFromClipboard,
    // Refresh
    RefreshConversations,
    // Cursor movement
    MoveCursorLeft,
    MoveCursorRight,
    MoveCursorHome,
    MoveCursorEnd,
    // Forward delete
    DeleteCharForward,
    // Settings
    OpenSettings,
    ToggleSetting,
    // Confirmation dialog
    ConfirmYes,
    ConfirmNo,
    // File picker
    OpenFilePicker,
    FilePickerUp,
    FilePickerDown,
    FilePickerSelect,
    FilePickerParent,
    FilePickerClose,
    // Edit message
    EditMessage,
    CancelEdit,
    // Emoji reaction
    StartEmojiReaction,
    EmojiInput(char),
    CancelEmojiInput,
    // Pagination
    LoadOlderMessages,
    // View-once
    ViewOnceMessage,
    // Chat mode switching
    EnterNavigationMode,
    EnterComposingMode,
    EnterComposingWithChar(char),
    // Panel focus
    FocusSidebar,
    FocusChat,
    // Command palette
    ExecuteCommand,
    CommandPaletteUp,
    CommandPaletteDown,
}

/// Events that arrive asynchronously from background tasks.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum AppEvent {
    IncomingMessage {
        thread_id: i64,
        message: Box<ChatMessage>,
    },
    TypingIndicator {
        thread_id: i64,
        sender: String,
        is_typing: bool,
    },
    ConnectionChanged(ConnectionStatusEvent),
    ReadReceipt {
        thread_id: i64,
        timestamp: i64,
    },
    /// Storage sync completed -- reload conversations from database.
    StorageSyncComplete,
}

/// Connection status for background events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ConnectionStatusEvent {
    Connected,
    Connecting,
    Disconnected,
}

/// Map terminal events to actions based on the current application state.
pub fn handle_event(event: Event, state: &AppState) -> Option<Action> {
    match event {
        Event::Key(key) => handle_key_event(key, state),
        _ => None,
    }
}

fn handle_key_event(key: KeyEvent, state: &AppState) -> Option<Action> {
    // Global keybindings (work in any view)
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('c') | KeyCode::Char('q') => return Some(Action::Quit),
            KeyCode::Char('v') => return Some(Action::PasteFromClipboard),
            _ => {}
        }
    }

    // If the file picker is open, intercept all keys for it.
    if state.file_picker.is_some() {
        return handle_file_picker_key(key);
    }

    // If emoji input mode is active, intercept the next key.
    if state.emoji_input_mode {
        return handle_emoji_input_key(key);
    }

    // If a confirmation dialog is active, intercept all keys.
    if state.confirm_dialog.is_some() {
        return handle_confirm_key(key);
    }

    // Tab for panel switching (works in ConversationList and Chat).
    if key.code == KeyCode::Tab {
        match state.navigation {
            NavigationState::ConversationList => {
                if state.active_chat.is_some() {
                    return Some(Action::FocusChat);
                }
            }
            NavigationState::Chat => {
                return Some(Action::FocusSidebar);
            }
            _ => {}
        }
    }

    // View-specific keybindings
    match state.navigation {
        NavigationState::ConversationList => handle_conversation_list_key(key),
        NavigationState::Chat => handle_chat_key(key, state),
        NavigationState::Search => handle_search_key(key),
        NavigationState::Settings => handle_settings_key(key),
        NavigationState::Help => handle_help_key(key),
    }
}

fn handle_conversation_list_key(key: KeyEvent) -> Option<Action> {
    match key.code {
        KeyCode::Char('q') => Some(Action::Quit),
        KeyCode::Char('j') | KeyCode::Down => Some(Action::NavigateDown),
        KeyCode::Char('k') | KeyCode::Up => Some(Action::NavigateUp),
        KeyCode::Enter => Some(Action::SelectConversation),
        KeyCode::Char('/') => Some(Action::StartSearch),
        KeyCode::Char('?') => Some(Action::ToggleHelp),
        KeyCode::Char('p') => Some(Action::PinConversation),
        KeyCode::Char('a') => Some(Action::ArchiveConversation),
        KeyCode::Char('r') => Some(Action::RefreshConversations),
        KeyCode::Char('s') => Some(Action::OpenSettings),
        _ => None,
    }
}

fn handle_chat_key(key: KeyEvent, state: &AppState) -> Option<Action> {
    // If command palette is active, intercept navigation keys.
    if state.command_palette.active {
        match key.code {
            KeyCode::Up => return Some(Action::CommandPaletteUp),
            KeyCode::Down => return Some(Action::CommandPaletteDown),
            KeyCode::Enter => return Some(Action::ExecuteCommand),
            KeyCode::Esc => {
                // Close palette by clearing input
                return Some(Action::EnterNavigationMode);
            }
            // Let other keys (Backspace, Char) fall through to composing handler
            _ => {}
        }
    }

    match state.chat_mode {
        ChatMode::Composing => handle_chat_composing_key(key, state),
        ChatMode::Navigating => handle_chat_navigating_key(key, state),
    }
}

fn handle_chat_composing_key(key: KeyEvent, state: &AppState) -> Option<Action> {
    match key.code {
        KeyCode::Esc => {
            if state.edit_message.is_some() {
                Some(Action::CancelEdit)
            } else if state.reply_to.is_some() {
                Some(Action::CancelReply)
            } else {
                Some(Action::EnterNavigationMode)
            }
        }
        KeyCode::Enter => {
            if state.command_palette.active {
                Some(Action::ExecuteCommand)
            } else {
                Some(Action::SendMessage)
            }
        }
        KeyCode::Backspace => Some(Action::DeleteChar),
        KeyCode::Delete => Some(Action::DeleteCharForward),
        KeyCode::Left => Some(Action::MoveCursorLeft),
        KeyCode::Right => Some(Action::MoveCursorRight),
        KeyCode::Home => Some(Action::MoveCursorHome),
        KeyCode::End => Some(Action::MoveCursorEnd),
        KeyCode::Up => {
            if state.command_palette.active {
                Some(Action::CommandPaletteUp)
            } else {
                None
            }
        }
        KeyCode::Down => {
            if state.command_palette.active {
                Some(Action::CommandPaletteDown)
            } else {
                None
            }
        }
        KeyCode::Char(c) => Some(Action::InsertChar(c)),
        _ => None,
    }
}

fn handle_chat_navigating_key(key: KeyEvent, state: &AppState) -> Option<Action> {
    match key.code {
        KeyCode::Esc => Some(Action::GoBack),
        KeyCode::Char('j') | KeyCode::Down => Some(Action::NavigateDown),
        KeyCode::Char('k') | KeyCode::Up => {
            if state.selected_message_index == 0 && state.has_more_messages {
                Some(Action::LoadOlderMessages)
            } else {
                Some(Action::NavigateUp)
            }
        }
        KeyCode::PageUp => Some(Action::ScrollMessagesUp),
        KeyCode::PageDown => Some(Action::ScrollMessagesDown),
        KeyCode::End => Some(Action::ScrollToBottom),
        KeyCode::Char('r') => Some(Action::ReplyToMessage),
        KeyCode::Char('d') => Some(Action::DeleteMessage),
        KeyCode::Char('y') | KeyCode::Char('c') => Some(Action::CopyMessage),
        KeyCode::Char('e') => Some(Action::EditMessage),
        KeyCode::Char('a') => Some(Action::OpenFilePicker),
        KeyCode::Char('x') => Some(Action::StartEmojiReaction),
        KeyCode::Char('?') => Some(Action::ToggleHelp),
        KeyCode::Enter => {
            let is_view_once = state
                .active_chat
                .as_ref()
                .and_then(|chat| chat.messages.get(state.selected_message_index))
                .map(|m| m.view_once)
                .unwrap_or(false);
            if is_view_once {
                Some(Action::ViewOnceMessage)
            } else {
                Some(Action::EnterComposingMode)
            }
        }
        // Any other printable character: auto-switch to composing and insert it.
        KeyCode::Char(c) => Some(Action::EnterComposingWithChar(c)),
        _ => None,
    }
}

fn handle_search_key(key: KeyEvent) -> Option<Action> {
    match key.code {
        KeyCode::Esc => Some(Action::CloseSearch),
        KeyCode::Enter => Some(Action::SelectConversation),
        KeyCode::Backspace => Some(Action::DeleteChar),
        KeyCode::Char(c) => Some(Action::InsertChar(c)),
        KeyCode::Down => Some(Action::NavigateDown),
        KeyCode::Up => Some(Action::NavigateUp),
        _ => None,
    }
}

fn handle_settings_key(key: KeyEvent) -> Option<Action> {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => Some(Action::GoBack),
        KeyCode::Char('j') | KeyCode::Down => Some(Action::NavigateDown),
        KeyCode::Char('k') | KeyCode::Up => Some(Action::NavigateUp),
        KeyCode::Enter | KeyCode::Char(' ') => Some(Action::ToggleSetting),
        _ => None,
    }
}

fn handle_confirm_key(key: KeyEvent) -> Option<Action> {
    match key.code {
        KeyCode::Char('y') | KeyCode::Enter => Some(Action::ConfirmYes),
        KeyCode::Char('n') | KeyCode::Esc => Some(Action::ConfirmNo),
        _ => None,
    }
}

fn handle_help_key(key: KeyEvent) -> Option<Action> {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('?') => Some(Action::ToggleHelp),
        _ => None,
    }
}

fn handle_file_picker_key(key: KeyEvent) -> Option<Action> {
    match key.code {
        KeyCode::Esc => Some(Action::FilePickerClose),
        KeyCode::Up | KeyCode::Char('k') => Some(Action::FilePickerUp),
        KeyCode::Down | KeyCode::Char('j') => Some(Action::FilePickerDown),
        KeyCode::Enter => Some(Action::FilePickerSelect),
        KeyCode::Backspace => Some(Action::FilePickerParent),
        _ => None,
    }
}

fn handle_emoji_input_key(key: KeyEvent) -> Option<Action> {
    match key.code {
        KeyCode::Esc => Some(Action::CancelEmojiInput),
        KeyCode::Char(c) => Some(Action::EmojiInput(c)),
        _ => None,
    }
}
