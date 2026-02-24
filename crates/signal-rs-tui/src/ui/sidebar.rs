use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState},
    Frame,
};

use super::theme;
use crate::state::app_state::FocusedPanel;
use crate::state::AppState;

/// Render the conversation sidebar.
pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    let items: Vec<ListItem> = state
        .conversations
        .iter()
        .enumerate()
        .map(|(i, conv)| {
            let is_selected = i == state.selected_index;
            let has_unread = conv.unread_count > 0;

            // Build indicators
            let mut indicators = String::new();
            if conv.is_pinned {
                indicators.push_str("[P] ");
            }
            if conv.is_group {
                indicators.push_str("[G] ");
            }
            if conv.is_muted {
                indicators.push_str("[M] ");
            }

            // Name style: bold+primary if selected or unread, secondary otherwise
            let name_style = if is_selected || has_unread {
                theme::primary_bold()
            } else {
                theme::secondary()
            };

            // Unread dot prefix
            let unread_prefix = if has_unread && !is_selected {
                Span::styled(format!("{} ", theme::UNREAD_DOT), theme::accent())
            } else if has_unread && is_selected {
                Span::styled(format!("{} ", theme::UNREAD_DOT), theme::accent_bold())
            } else {
                Span::raw("  ")
            };

            // Build the name with indicators
            let name_part = format!("{}{}", indicators, conv.name);

            // Calculate available width: area.width minus right border (1) minus unread prefix (2)
            let available_width = area.width.saturating_sub(1) as usize;
            let inner_width = available_width.saturating_sub(2); // 2 for unread dot prefix

            // Use relative timestamp if millis are available, otherwise fall back to stored string.
            let timestamp_str = conv
                .last_timestamp_millis
                .map(format_relative_timestamp)
                .unwrap_or_else(|| conv.last_timestamp.clone());

            let name_display_width = unicode_display_width(&name_part);
            let ts_display_width = unicode_display_width(&timestamp_str);

            let padding_count = inner_width
                .saturating_sub(name_display_width)
                .saturating_sub(ts_display_width);
            let padding = " ".repeat(padding_count);

            let name_line = Line::from(vec![
                unread_prefix,
                Span::styled(name_part, name_style),
                Span::raw(padding),
                Span::styled(timestamp_str, theme::secondary()),
            ]);

            // Preview line
            let preview_span = Span::styled(
                format!("  {}", truncate_str(&conv.last_message, inner_width.saturating_sub(2))),
                theme::secondary(),
            );

            ListItem::new(vec![name_line, Line::from(preview_span)])
        })
        .collect();

    let header_line = Line::from(vec![
        Span::styled(
            format!(" Conversations ({}) ", state.conversations.len()),
            theme::secondary(),
        ),
    ]);

    let border_style = if state.focused_panel == FocusedPanel::Sidebar {
        theme::focused_border()
    } else {
        theme::unfocused_border()
    };

    let sidebar = List::new(items)
        .block(
            Block::default()
                .borders(Borders::RIGHT)
                .border_style(border_style)
                .title(header_line),
        )
        .highlight_style(
            Style::default()
                .bg(theme::SELECTED_BG)
                .add_modifier(Modifier::BOLD),
        );

    // Use ListState for proper selection tracking and scrolling.
    let mut list_state = ListState::default();
    list_state.select(Some(state.selected_index));
    frame.render_stateful_widget(sidebar, area, &mut list_state);
}

/// Format a millisecond-epoch timestamp as a short relative string for the sidebar.
///
/// Returns "now", "2m", "1h", "3d", "Yesterday", or "Jan 15" style strings.
fn format_relative_timestamp(ts_millis: i64) -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let msg_time = UNIX_EPOCH + Duration::from_millis(ts_millis as u64);
    let now = SystemTime::now();
    let elapsed = now.duration_since(msg_time).unwrap_or_default();
    let secs = elapsed.as_secs();

    if secs < 60 {
        "now".to_string()
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else if secs < 2 * 86400 {
        "Yesterday".to_string()
    } else if secs < 7 * 86400 {
        format!("{}d", secs / 86400)
    } else {
        // Older: show "Mon DD" approximation.
        let days_since_epoch = ts_millis / 1000 / 86400;
        let month_names = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let day_in_year = (days_since_epoch % 365) as usize;
        let month_idx = (day_in_year / 30).min(11);
        let day = (day_in_year % 30) + 1;
        format!("{} {day}", month_names[month_idx])
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

/// Simple display-width calculation using unicode-width.
fn unicode_display_width(s: &str) -> usize {
    use unicode_width::UnicodeWidthStr;
    UnicodeWidthStr::width(s)
}
