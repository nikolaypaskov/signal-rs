use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
};

// ── Color palette ──────────────────────────────────────────────────────

pub const PRIMARY: Color = Color::White;
pub const SECONDARY: Color = Color::Rgb(120, 120, 120);
pub const ACCENT: Color = Color::Rgb(100, 180, 255);
pub const SUCCESS: Color = Color::Rgb(80, 200, 120);
pub const WARNING: Color = Color::Rgb(230, 180, 80);
pub const ERROR: Color = Color::Rgb(220, 80, 80);
pub const SELECTED_BG: Color = Color::Rgb(40, 40, 50);
pub const STATUS_BAR_BG: Color = Color::Rgb(25, 25, 30);
pub const SEPARATOR: Color = Color::Rgb(60, 60, 70);
pub const DIM: Color = Color::Rgb(80, 80, 90);
pub const CONTEXT_BG: Color = Color::Rgb(30, 30, 38);

// ── Symbols ────────────────────────────────────────────────────────────

pub const PROMPT: &str = "❯ ";
pub const UNREAD_DOT: &str = "●";
pub const CHECK_SINGLE: &str = "✓";
pub const CHECK_DOUBLE: &str = "✓✓";

// ── Pre-composed styles ────────────────────────────────────────────────

pub fn primary() -> Style {
    Style::default().fg(PRIMARY)
}

pub fn primary_bold() -> Style {
    Style::default().fg(PRIMARY).add_modifier(Modifier::BOLD)
}

pub fn secondary() -> Style {
    Style::default().fg(SECONDARY)
}

pub fn accent() -> Style {
    Style::default().fg(ACCENT)
}

pub fn accent_bold() -> Style {
    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
}

pub fn success() -> Style {
    Style::default().fg(SUCCESS)
}

pub fn success_bold() -> Style {
    Style::default().fg(SUCCESS).add_modifier(Modifier::BOLD)
}

pub fn warning() -> Style {
    Style::default().fg(WARNING)
}

pub fn warning_bold() -> Style {
    Style::default().fg(WARNING).add_modifier(Modifier::BOLD)
}

pub fn error() -> Style {
    Style::default().fg(ERROR)
}

pub fn error_bold() -> Style {
    Style::default().fg(ERROR).add_modifier(Modifier::BOLD)
}

pub fn dim() -> Style {
    Style::default().fg(DIM)
}

pub fn dim_italic() -> Style {
    Style::default().fg(DIM).add_modifier(Modifier::ITALIC)
}

pub fn separator_style() -> Style {
    Style::default().fg(SEPARATOR)
}

// ── Border styles ─────────────────────────────────────────────────────

pub fn focused_border() -> Style {
    Style::default().fg(ACCENT)
}

pub fn unfocused_border() -> Style {
    Style::default().fg(SEPARATOR)
}

// ── Helpers ────────────────────────────────────────────────────────────

pub fn horizontal_separator(width: u16) -> Line<'static> {
    Line::from(Span::styled(
        "─".repeat(width as usize),
        separator_style(),
    ))
}
