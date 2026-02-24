use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
    Frame,
};

use super::theme;
use crate::state::app_state::NotificationLevel;
use crate::state::AppState;

/// Render a notification toast overlay in the bottom-right corner.
pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    let notification = match &state.notification {
        Some(n) => n,
        None => return,
    };

    let (border_color, text_color) = match notification.level {
        NotificationLevel::Info => (theme::ACCENT, theme::ACCENT),
        NotificationLevel::Warning => (theme::WARNING, theme::WARNING),
        NotificationLevel::Error => (theme::ERROR, theme::ERROR),
    };

    let msg = &notification.message;
    let msg_width = msg.len() as u16 + 4; // padding + borders
    let msg_width = msg_width.min(area.width.saturating_sub(2)).max(10);
    let height: u16 = 3;

    // Position in bottom-right corner.
    let x = area.right().saturating_sub(msg_width + 1);
    let y = area.bottom().saturating_sub(height + 1);

    let toast_area = Rect::new(x, y, msg_width, height);

    // Clear the area behind the toast.
    frame.render_widget(Clear, toast_area);

    let toast = Paragraph::new(Line::from(Span::styled(
        msg.as_str(),
        Style::default().fg(text_color),
    )))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(border_color))
            .style(Style::default().bg(theme::STATUS_BAR_BG)),
    );

    frame.render_widget(toast, toast_area);
}
