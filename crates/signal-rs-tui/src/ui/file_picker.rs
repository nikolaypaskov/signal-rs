use std::path::PathBuf;

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use super::theme;
use crate::state::AppState;

/// Render the file picker overlay dialog.
pub fn render(frame: &mut Frame, state: &AppState) {
    let fp = match &state.file_picker {
        Some(fp) => fp,
        None => return,
    };

    let full_area = frame.area();

    // Center a dialog box (70% wide, 80% tall).
    let dialog_width = (full_area.width * 70 / 100)
        .max(40)
        .min(full_area.width.saturating_sub(4));
    let dialog_height = (full_area.height * 80 / 100)
        .max(10)
        .min(full_area.height.saturating_sub(2));

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

    // Split into header (current path) and file list.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(2),
        ])
        .split(area);

    let header_area = chunks[0];
    let list_area = chunks[1];
    let footer_area = chunks[2];

    // Clear the area behind the dialog.
    frame.render_widget(Clear, area);

    // Header: current directory path.
    let path_str = fp.current_dir.display().to_string();
    let header = Paragraph::new(Line::from(Span::styled(path_str, theme::accent())))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" Select File ")
                .border_style(theme::separator_style()),
        );
    frame.render_widget(header, header_area);

    // File list.
    let items: Vec<ListItem> = fp
        .entries
        .iter()
        .map(|entry| {
            let (icon, style) = if entry.is_dir {
                ("/", theme::accent_bold())
            } else {
                ("", theme::primary())
            };

            let size_str = if entry.is_dir {
                String::new()
            } else {
                format_file_size(entry.size)
            };

            let available_width = list_area.width.saturating_sub(4) as usize;
            let name_part = format!("{}{}", entry.name, icon);
            let name_width = name_part.len();
            let size_width = size_str.len();
            let padding_count = available_width
                .saturating_sub(name_width)
                .saturating_sub(size_width);
            let padding = " ".repeat(padding_count);

            ListItem::new(Line::from(vec![
                Span::styled(name_part, style),
                Span::raw(padding),
                Span::styled(size_str, theme::secondary()),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(theme::separator_style()),
        )
        .highlight_style(
            Style::default()
                .bg(theme::SELECTED_BG)
                .add_modifier(Modifier::BOLD),
        );

    let mut list_state = ListState::default();
    if !fp.entries.is_empty() {
        list_state.select(Some(fp.selected_index));
    }
    frame.render_stateful_widget(list, list_area, &mut list_state);

    // Footer: keybinding hints.
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" Enter", theme::accent()),
        Span::raw(": select  "),
        Span::styled("Backspace", theme::accent()),
        Span::raw(": parent  "),
        Span::styled("Esc", theme::accent()),
        Span::raw(": cancel"),
    ]))
    .alignment(Alignment::Center)
    .wrap(Wrap { trim: false })
    .style(Style::default().bg(theme::STATUS_BAR_BG));

    frame.render_widget(footer, footer_area);
}

/// Format a file size into a human-readable string.
fn format_file_size(bytes: u64) -> String {
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

/// A file entry in the file picker.
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// Display name.
    pub name: String,
    /// Full path.
    pub path: PathBuf,
    /// Whether this is a directory.
    pub is_dir: bool,
    /// File size in bytes (0 for directories).
    pub size: u64,
}

/// State for the file picker dialog.
#[derive(Debug, Clone)]
pub struct FilePickerState {
    /// Current directory being browsed.
    pub current_dir: PathBuf,
    /// Entries in the current directory.
    pub entries: Vec<FileEntry>,
    /// Currently selected index.
    pub selected_index: usize,
}

impl FilePickerState {
    /// Create a new file picker starting at the given directory.
    pub fn new(start_dir: PathBuf) -> Self {
        let mut state = Self {
            current_dir: start_dir,
            entries: Vec::new(),
            selected_index: 0,
        };
        state.refresh_entries();
        state
    }

    /// Refresh the list of entries from the current directory.
    pub fn refresh_entries(&mut self) {
        let mut entries = Vec::new();

        if let Ok(read_dir) = std::fs::read_dir(&self.current_dir) {
            for entry in read_dir.flatten() {
                let path = entry.path();
                let metadata = entry.metadata().ok();
                let is_dir = metadata.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
                let name = entry.file_name().to_string_lossy().to_string();

                // Skip hidden files.
                if name.starts_with('.') {
                    continue;
                }

                entries.push(FileEntry {
                    name,
                    path,
                    is_dir,
                    size,
                });
            }
        }

        // Sort: directories first, then alphabetically.
        entries.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });

        self.entries = entries;
        self.selected_index = 0;
    }

    /// Navigate up in the file list.
    pub fn navigate_up(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    /// Navigate down in the file list.
    pub fn navigate_down(&mut self) {
        if !self.entries.is_empty() && self.selected_index < self.entries.len() - 1 {
            self.selected_index += 1;
        }
    }

    /// Enter a directory or select a file. Returns Some(path) if a file was selected.
    pub fn select(&mut self) -> Option<PathBuf> {
        if self.entries.is_empty() {
            return None;
        }

        let entry = &self.entries[self.selected_index];
        if entry.is_dir {
            self.current_dir = entry.path.clone();
            self.refresh_entries();
            None
        } else {
            Some(entry.path.clone())
        }
    }

    /// Navigate to the parent directory.
    pub fn go_parent(&mut self) {
        if let Some(parent) = self.current_dir.parent() {
            self.current_dir = parent.to_path_buf();
            self.refresh_entries();
        }
    }
}
