use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
    Frame,
};

use super::theme;
use crate::state::app_state::{ChatMode, FocusedPanel};
use crate::state::AppState;

/// Render the chat message view.
pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    let chat = match &state.active_chat {
        Some(chat) => chat,
        None => {
            let placeholder = Paragraph::new(Span::styled("No chat selected", theme::secondary()))
                .alignment(ratatui::layout::Alignment::Center)
                .wrap(Wrap { trim: false });
            frame.render_widget(placeholder, area);
            return;
        }
    };

    // Split area into 2-line header + message area
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(1)])
        .split(area);

    let header_area = chunks[0];
    let message_area = chunks[1];

    // Render header: chat name + mode badge + horizontal separator
    let header_style = if state.focused_panel == FocusedPanel::Chat {
        theme::primary_bold()
    } else {
        theme::secondary()
    };

    let mode_badge = match state.chat_mode {
        ChatMode::Composing => Span::styled(" [composing]", theme::accent()),
        ChatMode::Navigating => Span::styled(" [navigating]", theme::warning()),
    };

    let header_lines = vec![
        Line::from(vec![
            Span::styled(format!(" {}", chat.name), header_style),
            mode_badge,
        ]),
        theme::horizontal_separator(header_area.width),
    ];
    let header_widget = Paragraph::new(header_lines);
    frame.render_widget(header_widget, header_area);

    // Build message lines
    let mut lines: Vec<Line> = Vec::new();
    let mut prev_sender: Option<&str> = None;
    let mut prev_timestamp_millis: i64 = 0;
    let mut prev_date: Option<String> = None;

    // Show a loading indicator at the top if more messages can be loaded.
    if state.has_more_messages {
        lines.push(Line::from(Span::styled(
            "--- Scroll up to load older messages ---",
            theme::dim_italic(),
        )));
        lines.push(Line::from(""));
    }

    for (i, msg) in chat.messages.iter().enumerate() {
        // Date separator: insert a separator line when the date changes.
        let date_str = extract_date_portion(&msg.timestamp);
        if prev_date.as_deref() != Some(&date_str) && !date_str.is_empty() {
            if !lines.is_empty() {
                lines.push(Line::from(""));
            }
            let separator = format!("── {} ──", date_str);
            lines.push(Line::from(Span::styled(separator, theme::dim_italic())));
            lines.push(Line::from(""));
            prev_date = Some(date_str);
            prev_sender = None; // Reset grouping after date separator.
        }

        let is_selected = i == state.selected_message_index
            && state.chat_mode == ChatMode::Navigating;

        // Quote/reply preview above the message.
        if let Some(ref reply_body) = msg.reply_preview {
            let sender_name = msg.reply_sender.as_deref().unwrap_or("Unknown");
            let preview_text = truncate_str(reply_body, 50);
            let reply_text = format!("\u{2502} {}: {}", sender_name, preview_text);
            lines.push(Line::from(Span::styled(
                reply_text,
                Style::default()
                    .fg(theme::SECONDARY)
                    .add_modifier(Modifier::ITALIC),
            )));
        } else if msg.reply_preview.is_none() && msg.reply_sender.is_some() {
            // Quote exists but original message not found.
            lines.push(Line::from(Span::styled(
                "\u{2502} [Original message not found]",
                Style::default()
                    .fg(theme::SECONDARY)
                    .add_modifier(Modifier::ITALIC),
            )));
        }

        // Message grouping: only show sender name if it's different from the previous,
        // or if more than 5 minutes have elapsed since the previous message.
        let same_sender = prev_sender == Some(&msg.sender);
        let within_5min = (msg.timestamp_millis - prev_timestamp_millis).abs() < 5 * 60 * 1000;
        let show_sender = !same_sender || !within_5min;

        if show_sender {
            let sender_style = if msg.is_outgoing {
                theme::accent_bold()
            } else {
                theme::success_bold()
            };

            lines.push(Line::from(vec![
                Span::styled(&msg.sender, sender_style),
                Span::styled(format!("  {}", msg.timestamp), theme::secondary()),
            ]));
        }

        // Message body -- highlight if selected.
        let body_style = if is_selected {
            Style::default().bg(theme::SELECTED_BG)
        } else {
            Style::default()
        };

        // Read receipt indicator for outgoing messages.
        let read_indicator = if msg.is_outgoing {
            if msg.is_read {
                format!(" {}", theme::CHECK_DOUBLE)
            } else {
                format!(" {}", theme::CHECK_SINGLE)
            }
        } else {
            String::new()
        };

        // View-once message handling.
        if msg.view_once {
            let db_id = msg.db_id.unwrap_or(0);
            let body_text = if state.viewed_once_messages.contains(&db_id) {
                "[Message viewed]".to_string()
            } else {
                "[View-once message - press Enter to view]".to_string()
            };
            lines.push(Line::from(vec![
                Span::styled(
                    body_text,
                    body_style
                        .fg(theme::WARNING)
                        .add_modifier(Modifier::ITALIC),
                ),
                Span::styled(read_indicator.clone(), theme::dim()),
            ]));
        } else {
            lines.push(Line::from(vec![
                Span::styled(&msg.body, body_style),
                Span::styled(read_indicator.clone(), theme::dim()),
            ]));
        }

        // Attachment indicators.
        for att in &msg.attachments {
            let size_str = att.size.map(format_size).unwrap_or_default();
            let att_text = if size_str.is_empty() {
                format!("[Attachment: {}]", att.file_name)
            } else {
                format!("[Attachment: {} ({})]", att.file_name, size_str)
            };
            lines.push(Line::from(Span::styled(att_text, theme::accent())));
        }

        // Reactions display below the message body.
        if !msg.reactions.is_empty() {
            let mut reaction_parts: Vec<String> = Vec::new();
            // Sort reactions by count descending for consistent display.
            let mut sorted_reactions: Vec<(&String, &u32)> = msg.reactions.iter().collect();
            sorted_reactions.sort_by(|a, b| b.1.cmp(a.1));
            for (emoji, count) in sorted_reactions {
                reaction_parts.push(format!("{} {}", emoji, count));
            }
            let reaction_text = reaction_parts.join("  ");
            lines.push(Line::from(Span::styled(reaction_text, theme::secondary())));
        }

        if show_sender {
            // Add spacing after a new-sender block
            lines.push(Line::from(""));
        }

        prev_sender = Some(&msg.sender);
        prev_timestamp_millis = msg.timestamp_millis;
    }

    // Typing indicator at bottom.
    if !state.typing_indicators.is_empty() {
        lines.push(Line::from(""));
        let typers: Vec<&str> = state
            .typing_indicators
            .keys()
            .map(|s| s.as_str())
            .collect();
        let typing_text = if typers.len() == 1 {
            format!("{} is typing...", typers[0])
        } else {
            format!("{} are typing...", typers.join(", "))
        };
        lines.push(Line::from(Span::styled(typing_text, theme::dim_italic())));
    }

    // Apply scroll offset.
    let visible_height = message_area.height as usize;
    let total_lines = lines.len();
    let scroll_offset = if total_lines > visible_height {
        let max_scroll = total_lines.saturating_sub(visible_height);
        state.message_scroll_offset.min(max_scroll)
    } else {
        0
    };

    let chat_widget = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((scroll_offset as u16, 0));

    frame.render_widget(chat_widget, message_area);
}

/// Extract a date portion from a timestamp string for date separators.
/// For timestamps like "12:34" (today), return "Today".
/// For "Yesterday", return "Yesterday".
/// For day names like "Mon", return the day name.
/// For "Jan 5" style, return as-is.
fn extract_date_portion(ts: &str) -> String {
    if ts.contains(':') && ts.len() <= 5 {
        "Today".to_string()
    } else {
        ts.to_string()
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_len.saturating_sub(3)).collect();
        format!("{truncated}...")
    }
}

/// Format a byte size into a human-readable string.
fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
