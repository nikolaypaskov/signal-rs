//! Thread / conversation data model for TUI display.

use rusqlite::Row;
use serde::{Deserialize, Serialize};

/// A thread (conversation) record from the `thread` table.
///
/// A thread represents either a 1-on-1 conversation (identified by `recipient_id`)
/// or a group conversation (identified by `group_id`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thread {
    /// Primary key.
    pub id: i64,
    /// The recipient for 1-on-1 conversations.
    pub recipient_id: Option<i64>,
    /// The group for group conversations.
    pub group_id: Option<i64>,
    /// Timestamp of the last message in this thread.
    pub last_message_timestamp: Option<i64>,
    /// Number of unread messages.
    pub unread_count: i64,
    /// Whether this thread is pinned.
    pub pinned: bool,
    /// Whether this thread is archived.
    pub archived: bool,
    /// Draft text, if any.
    pub draft: Option<String>,
}

/// A summary of a thread for display in a thread list.
///
/// Combines thread data with recipient/group info and the latest message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadSummary {
    pub thread_id: i64,
    pub recipient_id: Option<i64>,
    pub group_id: Option<String>,
    pub display_name: String,
    pub last_message_body: Option<String>,
    pub last_message_timestamp: Option<i64>,
    pub unread_count: i64,
    pub is_pinned: bool,
    pub is_archived: bool,
    pub is_group: bool,
    pub draft: Option<String>,
}

impl Thread {
    /// Construct a `Thread` from a `rusqlite::Row`.
    ///
    /// Expects all columns from `SELECT * FROM thread`.
    pub fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("_id")?,
            recipient_id: row.get("recipient_id")?,
            group_id: row.get("group_id")?,
            last_message_timestamp: row.get("last_message_timestamp")?,
            unread_count: row.get("unread_count")?,
            pinned: row.get::<_, i64>("pinned")? != 0,
            archived: row.get::<_, i64>("archived")? != 0,
            draft: row.get("draft")?,
        })
    }
}
