use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

use super::theme;
use crate::state::app_state::{ChatMode, ConnectionStatus};
use crate::state::{AppState, NavigationState};

/// Render the 2-line bottom status bar.
pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(area);

    render_status_line(frame, chunks[0], state);
    render_hints_line(frame, chunks[1], state);
}

/// Line 1: connection dot + view name + unread count.
fn render_status_line(frame: &mut Frame, area: Rect, state: &AppState) {
    let connection_dot = match state.connection_status {
        ConnectionStatus::Connected => Span::styled(" ● ", theme::success()),
        ConnectionStatus::Connecting => Span::styled(" ● ", theme::warning()),
        ConnectionStatus::Disconnected => Span::styled(" ● ", theme::error()),
    };

    let view_name = match state.navigation {
        NavigationState::ConversationList => "Conversations",
        NavigationState::Chat => "Chat",
        NavigationState::Search => "Search",
        NavigationState::Settings => "Settings",
        NavigationState::Help => "Help",
    };

    let unread = if state.unread_total > 0 {
        Span::styled(
            format!(" {} unread ", state.unread_total),
            theme::accent(),
        )
    } else {
        Span::raw("")
    };

    let sep = Span::styled("│", theme::separator_style());

    // Show chat mode indicator when in chat.
    let mode_span = if state.navigation == NavigationState::Chat {
        let (label, style) = match state.chat_mode {
            ChatMode::Composing => ("composing", theme::accent()),
            ChatMode::Navigating => ("navigating", theme::warning()),
        };
        vec![
            sep.clone(),
            Span::styled(format!(" {label} "), style),
        ]
    } else {
        vec![]
    };

    let mut spans = vec![
        connection_dot,
        sep.clone(),
        Span::styled(format!(" {view_name} "), theme::secondary()),
    ];
    spans.extend(mode_span);
    spans.push(sep);
    spans.push(unread);

    let status_line = Line::from(spans);
    let widget = Paragraph::new(status_line).style(Style::default().bg(theme::STATUS_BAR_BG));
    frame.render_widget(widget, area);
}

/// Line 2: context-sensitive keybinding hints.
fn render_hints_line(frame: &mut Frame, area: Rect, state: &AppState) {
    let hints = build_hints(state);
    let mut spans: Vec<Span> = Vec::new();

    for (i, (key, desc)) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("  ", theme::dim()));
        }
        spans.push(Span::styled(*key, theme::accent()));
        spans.push(Span::styled(format!(" {desc}"), theme::dim()));
    }

    let line = Line::from(vec![Span::raw(" ")].into_iter().chain(spans).collect::<Vec<_>>());
    let widget = Paragraph::new(line).style(Style::default().bg(theme::STATUS_BAR_BG));
    frame.render_widget(widget, area);
}

fn build_hints(state: &AppState) -> Vec<(&'static str, &'static str)> {
    // Confirmation dialog takes priority.
    if state.confirm_dialog.is_some() {
        return vec![("Y", "Confirm"), ("N", "Cancel")];
    }

    // File picker.
    if state.file_picker.is_some() {
        return vec![
            ("Enter", "Select"),
            ("Backspace", "Parent"),
            ("Esc", "Cancel"),
        ];
    }

    // Emoji input.
    if state.emoji_input_mode {
        return vec![("Any key", "React"), ("Esc", "Cancel")];
    }

    match state.navigation {
        NavigationState::ConversationList => {
            vec![
                ("\u{2191}\u{2193}", "Navigate"),
                ("Enter", "Open"),
                ("/", "Search"),
                ("Tab", "Chat"),
                ("s", "Settings"),
                ("q", "Quit"),
            ]
        }
        NavigationState::Chat => match state.chat_mode {
            ChatMode::Composing => {
                if state.command_palette.active {
                    vec![
                        ("\u{2191}\u{2193}", "Navigate"),
                        ("Enter", "Select"),
                        ("Esc", "Close"),
                    ]
                } else {
                    vec![
                        ("Enter", "Send"),
                        ("Esc", "Navigate"),
                        ("/cmd", "Commands"),
                        ("Tab", "Sidebar"),
                    ]
                }
            }
            ChatMode::Navigating => {
                vec![
                    ("r", "Reply"),
                    ("e", "Edit"),
                    ("d", "Delete"),
                    ("c", "Copy"),
                    ("x", "React"),
                    ("Tab", "Sidebar"),
                    ("Esc", "Back"),
                ]
            }
        },
        NavigationState::Search => {
            vec![
                ("\u{2191}\u{2193}", "Navigate"),
                ("Enter", "Select"),
                ("Esc", "Close"),
            ]
        }
        NavigationState::Settings => {
            vec![
                ("\u{2191}\u{2193}", "Navigate"),
                ("Enter", "Toggle"),
                ("Esc", "Back"),
            ]
        }
        NavigationState::Help => {
            vec![("Esc", "Close"), ("?", "Close")]
        }
    }
}
