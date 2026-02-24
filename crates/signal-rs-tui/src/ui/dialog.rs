use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap},
    Frame,
};

use super::theme;
use crate::state::AppState;

/// Render the help dialog overlay.
pub fn render_help(frame: &mut Frame, area: Rect, _state: &AppState) {
    let help_text = vec![
        Line::from(Span::styled("Keyboard Shortcuts", theme::primary_bold())),
        Line::from(""),
        Line::from(Span::styled("  General", theme::primary_bold())),
        Line::from(vec![
            Span::styled("  Tab       ", theme::accent()),
            Span::raw("Switch between sidebar and chat"),
        ]),
        Line::from(vec![
            Span::styled("  Esc       ", theme::accent()),
            Span::raw("Navigate mode / Go back / Cancel"),
        ]),
        Line::from(vec![
            Span::styled("  /command  ", theme::accent()),
            Span::raw("Open command palette (type / in chat)"),
        ]),
        Line::from(vec![
            Span::styled("  ?         ", theme::accent()),
            Span::raw("Toggle this help"),
        ]),
        Line::from(""),
        Line::from(Span::styled("  Conversation List", theme::primary_bold())),
        Line::from(vec![
            Span::styled("  j/k       ", theme::accent()),
            Span::raw("Navigate up/down"),
        ]),
        Line::from(vec![
            Span::styled("  Enter     ", theme::accent()),
            Span::raw("Open conversation"),
        ]),
        Line::from(vec![
            Span::styled("  /         ", theme::accent()),
            Span::raw("Search conversations"),
        ]),
        Line::from(vec![
            Span::styled("  p         ", theme::accent()),
            Span::raw("Pin/unpin conversation"),
        ]),
        Line::from(vec![
            Span::styled("  s         ", theme::accent()),
            Span::raw("Open settings"),
        ]),
        Line::from(vec![
            Span::styled("  q         ", theme::accent()),
            Span::raw("Quit"),
        ]),
        Line::from(""),
        Line::from(Span::styled("  Chat - Composing Mode", theme::primary_bold())),
        Line::from(vec![
            Span::styled("  Enter     ", theme::accent()),
            Span::raw("Send message"),
        ]),
        Line::from(vec![
            Span::styled("  Esc       ", theme::accent()),
            Span::raw("Switch to navigate mode"),
        ]),
        Line::from(vec![
            Span::styled("  /cmd      ", theme::accent()),
            Span::raw("Open command palette"),
        ]),
        Line::from(""),
        Line::from(Span::styled("  Chat - Navigating Mode", theme::primary_bold())),
        Line::from(vec![
            Span::styled("  j/k       ", theme::accent()),
            Span::raw("Select messages"),
        ]),
        Line::from(vec![
            Span::styled("  r         ", theme::accent()),
            Span::raw("Reply to message"),
        ]),
        Line::from(vec![
            Span::styled("  e         ", theme::accent()),
            Span::raw("Edit own message"),
        ]),
        Line::from(vec![
            Span::styled("  d         ", theme::accent()),
            Span::raw("Delete message"),
        ]),
        Line::from(vec![
            Span::styled("  c         ", theme::accent()),
            Span::raw("Copy message"),
        ]),
        Line::from(vec![
            Span::styled("  x         ", theme::accent()),
            Span::raw("React with emoji"),
        ]),
        Line::from(vec![
            Span::styled("  a         ", theme::accent()),
            Span::raw("Attach file"),
        ]),
        Line::from(vec![
            Span::styled("  Any char  ", theme::accent()),
            Span::raw("Start typing (auto-switch to composing)"),
        ]),
        Line::from(vec![
            Span::styled("  Esc       ", theme::accent()),
            Span::raw("Go back to conversation list"),
        ]),
        Line::from(vec![
            Span::styled("  Ctrl+V    ", theme::accent()),
            Span::raw("Paste from clipboard"),
        ]),
        Line::from(""),
        Line::from(Span::styled("Press ? or Esc to close", theme::dim())),
    ];

    let help = Paragraph::new(help_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" Help ")
                .border_style(theme::separator_style()),
        )
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: false });

    frame.render_widget(help, area);
}

/// Render the settings view with actual toggles.
pub fn render_settings(frame: &mut Frame, area: Rect, state: &AppState) {
    let settings = &state.settings;
    let sel = settings.selected_index;

    let toggle_str = |enabled: bool| -> &str {
        if enabled { "◉" } else { "○" }
    };

    let item_style = |idx: usize| -> Style {
        if idx == sel {
            theme::accent_bold()
        } else {
            theme::primary()
        }
    };

    let mut lines = vec![
        Line::from(Span::styled("Settings", theme::primary_bold())),
        Line::from(""),
        Line::from(Span::styled("  Preferences", theme::primary_bold())),
        Line::from(""),
        Line::from(vec![Span::styled(
            format!(
                "  {} Notifications",
                toggle_str(settings.notifications_enabled)
            ),
            item_style(0),
        )]),
        Line::from(Span::styled(
            "      Enable desktop notifications for new messages",
            theme::secondary(),
        )),
        Line::from(""),
        Line::from(vec![Span::styled(
            format!(
                "  {} Typing Indicators",
                toggle_str(settings.typing_indicators_enabled)
            ),
            item_style(1),
        )]),
        Line::from(Span::styled(
            "      Send and receive typing indicators",
            theme::secondary(),
        )),
        Line::from(""),
        Line::from(vec![Span::styled(
            format!(
                "  {} Read Receipts",
                toggle_str(settings.read_receipts_enabled)
            ),
            item_style(2),
        )]),
        Line::from(Span::styled(
            "      Send read receipts to message senders",
            theme::secondary(),
        )),
    ];

    // Account info section.
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("  Account", theme::primary_bold())));
    lines.push(Line::from(""));

    let phone = settings
        .phone_number
        .as_deref()
        .unwrap_or("Not linked");
    lines.push(Line::from(vec![
        Span::styled("  Phone: ", theme::accent()),
        Span::raw(phone),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  j/k: navigate  Enter/Space: toggle  q/Esc: back",
        theme::dim(),
    )));

    let widget = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" Settings ")
                .border_style(theme::separator_style()),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(widget, area);
}

/// Render a welcome screen when no conversation is selected.
pub fn render_welcome(frame: &mut Frame, area: Rect, state: &AppState) {
    let mut welcome_text = vec![
        Line::from(""),
        Line::from(Span::styled("signal-rs", theme::accent_bold())),
        Line::from(""),
        Line::from("A modern Signal messenger TUI client"),
        Line::from("Built with Rust for performance and reliability."),
        Line::from(""),
    ];

    if !state.has_database {
        welcome_text.push(Line::from(Span::styled(
            "Not registered",
            theme::warning_bold(),
        )));
        welcome_text.push(Line::from(""));
        welcome_text.push(Line::from(Span::styled(
            "No database found. Run signal-rs-cli to register first,",
            theme::secondary(),
        )));
        welcome_text.push(Line::from(Span::styled(
            "or use --data-dir to point to an existing data directory.",
            theme::secondary(),
        )));
    } else if state.conversations.is_empty() {
        welcome_text.push(Line::from(Span::styled(
            "No conversations yet",
            theme::secondary(),
        )));
    } else {
        welcome_text.push(Line::from(Span::styled(
            "Select a conversation to start chatting",
            theme::secondary(),
        )));
    }

    welcome_text.push(Line::from(""));
    welcome_text.push(Line::from(Span::styled("Quick Start", theme::primary_bold())));
    welcome_text.push(Line::from(vec![
        Span::styled("  Enter  ", theme::accent()),
        Span::raw("Open conversation, start typing immediately"),
    ]));
    welcome_text.push(Line::from(vec![
        Span::styled("  Esc    ", theme::accent()),
        Span::raw("Navigate messages (reply, delete, copy)"),
    ]));
    welcome_text.push(Line::from(vec![
        Span::styled("  Tab    ", theme::accent()),
        Span::raw("Switch between sidebar and chat"),
    ]));
    welcome_text.push(Line::from(vec![
        Span::styled("  /cmd   ", theme::accent()),
        Span::raw("Command palette (type / in chat)"),
    ]));
    welcome_text.push(Line::from(vec![
        Span::styled("  ?      ", theme::accent()),
        Span::raw("Full keyboard shortcuts"),
    ]));

    let welcome = Paragraph::new(welcome_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(theme::separator_style()),
        )
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: false });

    frame.render_widget(welcome, area);
}

/// Render a confirmation dialog as a centered overlay.
pub fn render_confirm(frame: &mut Frame, state: &AppState) {
    let dialog = match &state.confirm_dialog {
        Some(d) => d,
        None => return,
    };

    let full_area = frame.area();

    // Center a dialog box (50 wide, 7 tall).
    let dialog_width = 50u16.min(full_area.width.saturating_sub(4));
    let dialog_height = 7u16.min(full_area.height.saturating_sub(2));

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length((full_area.height.saturating_sub(dialog_height)) / 2),
            Constraint::Length(dialog_height),
            Constraint::Min(0),
        ])
        .split(full_area);

    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length((full_area.width.saturating_sub(dialog_width)) / 2),
            Constraint::Length(dialog_width),
            Constraint::Min(0),
        ])
        .split(vertical[1]);

    let area = horizontal[1];

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            dialog.message.as_str(),
            theme::primary(),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  [Y]", theme::success_bold()),
            Span::raw(" Yes    "),
            Span::styled("[N]", theme::error_bold()),
            Span::raw(" No"),
        ]),
    ];

    let paragraph = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" Confirm ")
                .border_style(theme::separator_style()),
        )
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: false });

    // Clear the area behind the dialog.
    frame.render_widget(Clear, area);
    frame.render_widget(paragraph, area);
}
