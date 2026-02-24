pub mod chat;
pub mod command_palette;
pub mod dialog;
pub mod file_picker;
pub mod input;
pub mod notification;
pub mod search;
pub mod sidebar;
pub mod status_bar;
pub mod theme;

use ratatui::{
    layout::{Constraint, Direction, Layout},
    Frame,
};

use crate::state::{AppState, NavigationState};

/// Render the entire UI based on the current application state.
pub fn render(frame: &mut Frame, state: &AppState) {
    // Main layout: sidebar | content area, with 2-line status bar at the bottom
    let outer_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(2)])
        .split(frame.area());

    let main_area = outer_chunks[0];
    let status_area = outer_chunks[1];

    // Render status bar
    status_bar::render(frame, status_area, state);

    // Split main area into sidebar and content
    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(main_area);

    let sidebar_area = content_chunks[0];
    let chat_area = content_chunks[1];

    // Always render the sidebar
    sidebar::render(frame, sidebar_area, state);

    // Render the main content area based on navigation state
    match state.navigation {
        NavigationState::Chat => {
            // Determine input height: base 3 + context lines
            let context_lines = state.reply_to.is_some() as u16
                + state.edit_message.is_some() as u16
                + (!state.pending_attachments.is_empty()) as u16;
            let input_height = 2 + context_lines;

            let chat_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(input_height)])
                .split(chat_area);

            chat::render(frame, chat_chunks[0], state);
            input::render(frame, chat_chunks[1], state);

            // Render command palette overlay above input if active.
            if state.command_palette.active {
                command_palette::render(frame, chat_chunks[0], state);
            }
        }
        NavigationState::Search => {
            search::render(frame, chat_area, state);
        }
        NavigationState::Help => {
            dialog::render_help(frame, chat_area, state);
        }
        NavigationState::Settings => {
            dialog::render_settings(frame, chat_area, state);
        }
        NavigationState::ConversationList => {
            // Show a welcome / placeholder in the content area
            dialog::render_welcome(frame, chat_area, state);
        }
    }

    // Render file picker overlay (on top of content).
    if state.file_picker.is_some() {
        file_picker::render(frame, state);
    }

    // Render confirmation dialog overlay (on top of content, below notification).
    if state.confirm_dialog.is_some() {
        dialog::render_confirm(frame, state);
    }

    // Render notification toast last (on top of everything).
    notification::render(frame, frame.area(), state);
}
