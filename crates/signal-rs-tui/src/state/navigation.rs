/// The current navigation state / active view of the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(dead_code)]
pub enum NavigationState {
    /// The sidebar listing all conversations.
    #[default]
    ConversationList,
    /// An active chat with a contact or group.
    Chat,
    /// The search overlay / view.
    Search,
    /// The settings view.
    Settings,
    /// The help overlay.
    Help,
}

impl NavigationState {
    /// Return the parent view to navigate back to.
    pub fn parent(self) -> Self {
        match self {
            Self::Chat => Self::ConversationList,
            Self::Search => Self::ConversationList,
            Self::Settings => Self::ConversationList,
            Self::Help => Self::ConversationList,
            Self::ConversationList => Self::ConversationList,
        }
    }
}
