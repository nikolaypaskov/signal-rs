use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};
use unicode_width::UnicodeWidthStr;

use super::theme;
use crate::state::app_state::ChatMode;
use crate::state::AppState;

/// Render the message input area.
pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    // Count how many context lines we need above the input.
    let has_reply = state.reply_to.is_some();
    let has_edit = state.edit_message.is_some();
    let has_attachments = !state.pending_attachments.is_empty();
    let context_lines = has_reply as u16 + has_edit as u16 + has_attachments as u16;

    let (context_area, input_area) = if context_lines > 0 {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(context_lines), Constraint::Min(2)])
            .split(area);
        (Some(chunks[0]), chunks[1])
    } else {
        (None, area)
    };

    // Render context indicators above the input.
    if let Some(ctx_area) = context_area {
        let mut lines: Vec<Line> = Vec::new();

        // Edit mode indicator.
        if let Some(edit_ctx) = &state.edit_message {
            let edit_text = format!(
                " Editing message: {}  [Esc to cancel]",
                truncate_str(&edit_ctx.original_text, 40),
            );
            lines.push(Line::from(Span::styled(
                edit_text,
                Style::default()
                    .fg(theme::WARNING)
                    .add_modifier(Modifier::ITALIC),
            )));
        }

        // Reply indicator.
        if let Some(reply_ctx) = &state.reply_to {
            let reply_text = format!(
                " Replying to {}: {}  [Esc to cancel]",
                reply_ctx.sender_name,
                truncate_str(&reply_ctx.preview_text, 40),
            );
            lines.push(Line::from(Span::styled(
                reply_text,
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::ITALIC),
            )));
        }

        // Attachment indicator.
        if !state.pending_attachments.is_empty() {
            let names: Vec<String> = state
                .pending_attachments
                .iter()
                .map(|p| {
                    p.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "file".to_string())
                })
                .collect();
            let att_text = format!(" [Attached: {}]", names.join(", "));
            lines.push(Line::from(Span::styled(att_text, theme::accent())));
        }

        let context_widget =
            Paragraph::new(lines).style(Style::default().bg(theme::CONTEXT_BG));
        frame.render_widget(context_widget, ctx_area);
    }

    // Separator line + prompt + input text
    let is_empty = state.input_buffer.is_empty();
    let is_navigating = state.chat_mode == ChatMode::Navigating;

    let prompt_style = if state.is_input_focused {
        theme::accent()
    } else {
        theme::separator_style()
    };

    let input_text = if is_navigating && is_empty {
        "Press any key to start typing...".to_string()
    } else if is_empty && !state.is_input_focused {
        "Type a message...".to_string()
    } else {
        state.input_buffer.clone()
    };

    let text_style = if is_empty && (is_navigating || !state.is_input_focused) {
        theme::dim()
    } else {
        theme::primary()
    };

    // Character counter
    let char_count = state.input_buffer.chars().count();
    let max_chars: usize = 2000;
    let counter_text = format!("{char_count}/{max_chars}");
    let counter_style = if char_count > max_chars {
        theme::error()
    } else {
        theme::dim()
    };

    // Calculate right-aligned counter position
    let counter_width = counter_text.len();
    let prompt_width = 2; // "❯ "
    let text_display_width = UnicodeWidthStr::width(input_text.as_str());
    let available = input_area.width.saturating_sub(1) as usize; // 1 for safety
    let padding_count = available
        .saturating_sub(prompt_width)
        .saturating_sub(text_display_width)
        .saturating_sub(counter_width);
    let padding = " ".repeat(padding_count);

    let separator_line = theme::horizontal_separator(input_area.width);

    let input_line = Line::from(vec![
        Span::styled(theme::PROMPT, prompt_style),
        Span::styled(input_text, text_style),
        Span::raw(padding),
        Span::styled(counter_text, counter_style),
    ]);

    let input_widget = Paragraph::new(vec![separator_line, input_line]);
    frame.render_widget(input_widget, input_area);

    // Place cursor at the correct position when focused.
    if state.is_input_focused {
        // Calculate display width up to cursor position.
        let text_before_cursor: String = state
            .input_buffer
            .chars()
            .take(state.cursor_position)
            .collect();
        let display_width = UnicodeWidthStr::width(text_before_cursor.as_str()) as u16;

        let cursor_x = input_area.x + 2 + display_width; // 2 for prompt "❯ "
        let cursor_y = input_area.y + 1; // after separator line
        frame.set_cursor_position((cursor_x.min(input_area.right() - 2), cursor_y));
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
