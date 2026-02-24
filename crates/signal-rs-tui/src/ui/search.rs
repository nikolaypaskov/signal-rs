use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListItem, Paragraph},
    Frame,
};

use super::theme;
use crate::state::app_state::SearchResult;
use crate::state::AppState;

/// Render the search view.
pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(3)])
        .split(area);

    let search_input_area = chunks[0];
    let results_area = chunks[1];

    // Search input: separator line + prompt
    let search_text = if state.search_query.is_empty() {
        "Type to search conversations and messages...".to_string()
    } else {
        state.search_query.clone()
    };

    let text_style = if state.search_query.is_empty() {
        theme::dim()
    } else {
        theme::primary()
    };

    let search_lines = vec![
        theme::horizontal_separator(search_input_area.width),
        Line::from(vec![
            Span::styled(theme::PROMPT, theme::accent()),
            Span::styled(search_text, text_style),
        ]),
    ];

    let search_input = Paragraph::new(search_lines);
    frame.render_widget(search_input, search_input_area);

    // Place cursor in search input
    let cursor_x = search_input_area.x + 2 + state.search_query.len() as u16; // 2 for prompt
    let cursor_y = search_input_area.y + 1; // after separator
    frame.set_cursor_position((cursor_x.min(search_input_area.right() - 2), cursor_y));

    // Build list items from search_results.
    if state.search_results.is_empty() && !state.search_query.is_empty() {
        let no_results = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled("  No results found", theme::secondary())),
            Line::from(""),
            Line::from(Span::styled(
                "  Try a different search term",
                theme::secondary(),
            )),
        ]);
        frame.render_widget(no_results, results_area);
    } else {
        let items: Vec<ListItem> = state
            .search_results
            .iter()
            .enumerate()
            .map(|(i, result)| {
                let is_selected = i == state.selected_index;
                let name_style = if is_selected {
                    Style::default()
                        .fg(theme::PRIMARY)
                        .bg(theme::SELECTED_BG)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };

                match result {
                    SearchResult::Conversation { index } => {
                        let conv = &state.conversations[*index];
                        let type_indicator = if conv.is_group { "[G] " } else { "" };
                        ListItem::new(vec![
                            Line::from(vec![
                                Span::styled("[Chat] ", theme::accent()),
                                Span::styled(
                                    format!("{}{}", type_indicator, conv.name),
                                    name_style,
                                ),
                            ]),
                            Line::from(Span::styled(
                                truncate_str(&conv.last_message, 60),
                                theme::secondary(),
                            )),
                        ])
                    }
                    SearchResult::Message {
                        conversation_name,
                        sender,
                        body_preview,
                        ..
                    } => ListItem::new(vec![
                        Line::from(vec![
                            Span::styled("[Msg] ", theme::success()),
                            Span::styled(
                                format!("{} - {}", conversation_name, sender),
                                name_style,
                            ),
                        ]),
                        Line::from(Span::styled(
                            truncate_str(body_preview, 60),
                            theme::secondary(),
                        )),
                    ]),
                }
            })
            .collect();

        let results = List::new(items);
        frame.render_widget(results, results_area);
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
