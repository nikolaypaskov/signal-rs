use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
    Frame,
};

use super::theme;
use crate::state::app_state::COMMANDS;
use crate::state::AppState;

/// Render the command palette popup above the input area.
pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    let palette = &state.command_palette;
    if !palette.active || palette.filtered.is_empty() {
        return;
    }

    // Show at most 8 items.
    let visible_count = palette.filtered.len().min(8) as u16;
    let popup_height = visible_count + 2; // +2 for borders

    // Position the popup at the bottom of the chat area.
    let popup_width = area.width.min(50);
    let popup_y = area.bottom().saturating_sub(popup_height);
    let popup_x = area.x + 1;

    let popup_area = Rect::new(
        popup_x,
        popup_y,
        popup_width.min(area.width.saturating_sub(2)),
        popup_height.min(area.height),
    );

    if popup_area.width < 10 || popup_area.height < 3 {
        return;
    }

    let mut lines: Vec<Line> = Vec::new();
    for (display_idx, &cmd_idx) in palette.filtered.iter().take(8).enumerate() {
        let cmd = &COMMANDS[cmd_idx];
        let is_selected = display_idx == palette.selected_index;

        let style = if is_selected {
            Style::default()
                .bg(theme::SELECTED_BG)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };

        lines.push(Line::from(vec![
            Span::styled(format!(" /{}", cmd.name), style.fg(theme::ACCENT)),
            Span::styled(format!("  {}", cmd.description), style.fg(theme::SECONDARY)),
        ]));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(" Commands ")
        .border_style(theme::focused_border());

    let widget = Paragraph::new(lines).block(block);

    frame.render_widget(Clear, popup_area);
    frame.render_widget(widget, popup_area);
}
