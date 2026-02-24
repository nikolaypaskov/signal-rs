//! Message store — application-level CRUD for messages (TUI).

use std::collections::HashMap;
use tracing::debug;

use crate::database::Database;
use crate::error::{Result, StoreError};
use crate::models::message::{CallLogEntry, Message, MessageType, Reaction, ReactionSummary};

/// Message store operations on the database.
impl Database {
    /// Insert a new message and return its ID.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_message(
        &self,
        thread_id: i64,
        sender_id: Option<i64>,
        timestamp: i64,
        server_timestamp: Option<i64>,
        body: Option<&str>,
        message_type: MessageType,
        quote_id: Option<i64>,
        expires_in: Option<i64>,
        attachments_json: Option<&str>,
    ) -> Result<i64> {
        self.insert_message_full(
            thread_id,
            sender_id,
            timestamp,
            server_timestamp,
            body,
            message_type,
            quote_id,
            expires_in,
            attachments_json,
            None,
            None,
        )
    }

    /// Insert a new message with an optional expiration timestamp and return its ID.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_message_with_expiry(
        &self,
        thread_id: i64,
        sender_id: Option<i64>,
        timestamp: i64,
        server_timestamp: Option<i64>,
        body: Option<&str>,
        message_type: MessageType,
        quote_id: Option<i64>,
        expires_in: Option<i64>,
        attachments_json: Option<&str>,
        expires_at: Option<i64>,
    ) -> Result<i64> {
        self.insert_message_full(
            thread_id,
            sender_id,
            timestamp,
            server_timestamp,
            body,
            message_type,
            quote_id,
            expires_in,
            attachments_json,
            expires_at,
            None,
        )
    }

    /// Insert a new message with all optional fields and return its ID.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_message_full(
        &self,
        thread_id: i64,
        sender_id: Option<i64>,
        timestamp: i64,
        server_timestamp: Option<i64>,
        body: Option<&str>,
        message_type: MessageType,
        quote_id: Option<i64>,
        expires_in: Option<i64>,
        attachments_json: Option<&str>,
        expires_at: Option<i64>,
        mentions: Option<&str>,
    ) -> Result<i64> {
        debug!(thread_id, timestamp, ?expires_at, "inserting message");
        self.conn().execute(
            "INSERT INTO message (
                thread_id, sender_id, timestamp, server_timestamp, body,
                message_type, quote_id, expires_in, attachments_json, expires_at,
                mentions
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                thread_id,
                sender_id,
                timestamp,
                server_timestamp,
                body,
                message_type as i64,
                quote_id,
                expires_in,
                attachments_json,
                expires_at,
                mentions,
            ],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    /// Get messages for a thread, ordered by timestamp ascending.
    ///
    /// `limit` controls how many messages to return (most recent).
    /// `before_timestamp` can be used for pagination.
    pub fn get_messages_by_thread(
        &self,
        thread_id: i64,
        limit: u32,
        before_timestamp: Option<i64>,
    ) -> Result<Vec<Message>> {
        debug!(thread_id, limit, "loading messages for thread");

        let (sql, params): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match before_timestamp {
            Some(ts) => (
                "SELECT * FROM message
                 WHERE thread_id = ?1 AND timestamp < ?2
                 ORDER BY timestamp DESC
                 LIMIT ?3",
                vec![
                    Box::new(thread_id),
                    Box::new(ts),
                    Box::new(limit as i64),
                ],
            ),
            None => (
                "SELECT * FROM message
                 WHERE thread_id = ?1
                 ORDER BY timestamp DESC
                 LIMIT ?2",
                vec![Box::new(thread_id), Box::new(limit as i64)],
            ),
        };

        let mut stmt = self.conn().prepare(sql)?;
        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let mut messages = stmt
            .query_map(param_refs.as_slice(), Message::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        // Reverse so messages are in ascending order (oldest first).
        messages.reverse();
        Ok(messages)
    }

    /// Get the latest message for each thread (for thread list display).
    pub fn get_latest_message_per_thread(&self) -> Result<Vec<Message>> {
        debug!("loading latest message per thread");
        let mut stmt = self.conn().prepare(
            "SELECT m.* FROM message m
             INNER JOIN (
                 SELECT thread_id, MAX(timestamp) as max_ts
                 FROM message
                 GROUP BY thread_id
             ) latest ON m.thread_id = latest.thread_id AND m.timestamp = latest.max_ts",
        )?;
        let rows = stmt
            .query_map([], Message::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Mark all messages in a thread as read up to a given timestamp.
    pub fn mark_messages_read(&self, thread_id: i64, up_to_timestamp: i64) -> Result<u64> {
        debug!(thread_id, up_to_timestamp, "marking messages as read");
        let affected = self.conn().execute(
            "UPDATE message SET read = 1
             WHERE thread_id = ?1 AND timestamp <= ?2 AND read = 0",
            rusqlite::params![thread_id, up_to_timestamp],
        )?;
        Ok(affected as u64)
    }

    /// Delete a message by ID.
    pub fn delete_message(&self, id: i64) -> Result<()> {
        debug!(id, "deleting message");
        let affected = self.conn().execute(
            "DELETE FROM message WHERE _id = ?1",
            [id],
        )?;
        if affected == 0 {
            return Err(StoreError::NotFound(format!("message with id {id}")));
        }
        Ok(())
    }

    /// Get a message by ID.
    pub fn get_message_by_id(&self, id: i64) -> Result<Option<Message>> {
        debug!(id, "loading message by id");
        let result = self
            .conn()
            .query_row(
                "SELECT * FROM message WHERE _id = ?1",
                [id],
                Message::from_row,
            )
            .ok();
        Ok(result)
    }

    /// Get a message by timestamp and sender.
    pub fn get_message_by_timestamp_and_sender(
        &self,
        timestamp: i64,
        sender_id: i64,
    ) -> Result<Option<Message>> {
        debug!(timestamp, sender_id, "loading message by timestamp and sender");
        let result = self
            .conn()
            .query_row(
                "SELECT * FROM message WHERE timestamp = ?1 AND sender_id = ?2",
                rusqlite::params![timestamp, sender_id],
                Message::from_row,
            )
            .ok();
        Ok(result)
    }

    /// Get a message by timestamp (any sender).
    pub fn get_message_by_timestamp(&self, timestamp: i64) -> Result<Option<Message>> {
        debug!(timestamp, "loading message by timestamp");
        let result = self
            .conn()
            .query_row(
                "SELECT * FROM message WHERE timestamp = ?1 LIMIT 1",
                rusqlite::params![timestamp],
                Message::from_row,
            )
            .ok();
        Ok(result)
    }

    /// Update the body text of a message (for edits).
    ///
    /// If the message has not been edited before (i.e. `original_body` is NULL),
    /// the current body is preserved in `original_body` before updating.
    pub fn update_message_body(&self, id: i64, new_body: &str) -> Result<()> {
        debug!(id, "updating message body");
        self.conn().execute(
            "UPDATE message SET
                original_body = COALESCE(original_body, body),
                body = ?1
             WHERE _id = ?2",
            rusqlite::params![new_body, id],
        )?;
        Ok(())
    }

    /// Get the edit history for a message.
    ///
    /// Returns the original body if the message has been edited, or `None`
    /// if the message was never edited.
    pub fn get_edit_history(&self, id: i64) -> Result<Option<String>> {
        debug!(id, "getting edit history");
        let result = self
            .conn()
            .query_row(
                "SELECT original_body FROM message WHERE _id = ?1",
                [id],
                |row| row.get::<_, Option<String>>(0),
            );
        match result {
            Ok(val) => Ok(val),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                Err(StoreError::NotFound(format!("message with id {id}")))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Mark a message as deleted by setting its type to Delete and clearing the body.
    pub fn mark_message_deleted(&self, id: i64) -> Result<()> {
        debug!(id, "marking message as deleted");
        self.conn().execute(
            "UPDATE message SET message_type = ?1, body = NULL WHERE _id = ?2",
            rusqlite::params![MessageType::Delete as i64, id],
        )?;
        Ok(())
    }

    /// Get the total unread count across all threads.
    pub fn get_total_unread_count(&self) -> Result<i64> {
        debug!("getting total unread count");
        let count: i64 = self
            .conn()
            .query_row(
                "SELECT COALESCE(SUM(unread_count), 0) FROM thread",
                [],
                |row| row.get(0),
            )?;
        Ok(count)
    }

    /// Get the unread count for a specific thread.
    pub fn get_thread_unread_count(&self, thread_id: i64) -> Result<i64> {
        debug!(thread_id, "getting thread unread count");
        let count: i64 = self
            .conn()
            .query_row(
                "SELECT unread_count FROM thread WHERE _id = ?1",
                [thread_id],
                |row| row.get(0),
            )
            .map_err(|_| StoreError::NotFound(format!("thread with id {thread_id}")))?;
        Ok(count)
    }

    /// Search messages by body text using the FTS5 full-text index.
    ///
    /// The query supports FTS5 syntax (e.g. `"hello world"` for phrase,
    /// `hello OR world` for disjunction). Simple words are matched as prefixes
    /// when suffixed with `*`.
    pub fn search_messages(&self, query: &str) -> Result<Vec<Message>> {
        debug!(query, "searching messages");
        let mut stmt = self.conn().prepare(
            "SELECT m.* FROM message m
             JOIN message_fts ON message_fts.rowid = m._id
             WHERE message_fts MATCH ?1
             ORDER BY rank",
        )?;
        let rows = stmt
            .query_map([query], Message::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Get the number of messages in a thread.
    pub fn get_message_count_for_thread(&self, thread_id: i64) -> Result<i64> {
        debug!(thread_id, "counting messages for thread");
        let count: i64 = self
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM message WHERE thread_id = ?1",
                [thread_id],
                |row| row.get(0),
            )?;
        Ok(count)
    }

    /// Delete all messages in a thread.
    pub fn delete_all_messages_in_thread(&self, thread_id: i64) -> Result<()> {
        debug!(thread_id, "deleting all messages in thread");
        self.conn().execute(
            "DELETE FROM message WHERE thread_id = ?1",
            [thread_id],
        )?;
        Ok(())
    }

    /// Delete all expired messages (where `expires_at` <= `now_millis`).
    ///
    /// Returns the number of deleted messages.
    pub fn delete_expired_messages(&self, now_millis: i64) -> Result<u64> {
        debug!(now_millis, "deleting expired messages");
        let affected = self.conn().execute(
            "DELETE FROM message WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            [now_millis],
        )?;
        Ok(affected as u64)
    }

    // -- Thread operations --------------------------------------------------

    /// Get or create a thread for a 1-on-1 conversation.
    pub fn get_or_create_thread_for_recipient(&self, recipient_id: i64) -> Result<crate::models::thread::Thread> {
        use crate::models::thread::Thread;
        debug!(recipient_id, "get or create thread for recipient");

        if let Ok(thread) = self.conn().query_row(
            "SELECT * FROM thread WHERE recipient_id = ?1",
            [recipient_id],
            Thread::from_row,
        ) {
            return Ok(thread);
        }

        self.conn().execute(
            "INSERT INTO thread (recipient_id) VALUES (?1)",
            [recipient_id],
        )?;
        let id = self.conn().last_insert_rowid();
        self.conn()
            .query_row(
                "SELECT * FROM thread WHERE _id = ?1",
                [id],
                Thread::from_row,
            )
            .map_err(StoreError::Database)
    }

    /// Get or create a thread for a group conversation.
    pub fn get_or_create_thread_for_group(&self, group_id: i64) -> Result<crate::models::thread::Thread> {
        use crate::models::thread::Thread;
        debug!(group_id, "get or create thread for group");

        if let Ok(thread) = self.conn().query_row(
            "SELECT * FROM thread WHERE group_id = ?1",
            [group_id],
            Thread::from_row,
        ) {
            return Ok(thread);
        }

        self.conn().execute(
            "INSERT INTO thread (group_id) VALUES (?1)",
            [group_id],
        )?;
        let id = self.conn().last_insert_rowid();
        self.conn()
            .query_row(
                "SELECT * FROM thread WHERE _id = ?1",
                [id],
                Thread::from_row,
            )
            .map_err(StoreError::Database)
    }

    /// Ensure threads exist for all known contacts and groups.
    ///
    /// This is useful after a storage sync where contacts/groups were created
    /// without corresponding threads.  Returns the number of newly created threads.
    pub fn ensure_threads_for_all_contacts_and_groups(&self) -> Result<usize> {
        let mut created = 0usize;

        // Create threads for all recipients that have an ACI or phone number
        // and don't already have a thread.
        let recipient_ids: Vec<i64> = {
            let mut stmt = self.conn().prepare(
                "SELECT r._id FROM recipient r
                 LEFT JOIN thread t ON t.recipient_id = r._id
                 WHERE t._id IS NULL
                   AND (r.aci IS NOT NULL OR r.number IS NOT NULL)
                   AND r.hidden = 0",
            ).map_err(crate::error::StoreError::Database)?;
            stmt.query_map([], |row| row.get(0))
                .map_err(crate::error::StoreError::Database)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(crate::error::StoreError::Database)?
        };
        for rid in &recipient_ids {
            let _ = self.get_or_create_thread_for_recipient(*rid);
            created += 1;
        }

        // Create threads for all groups that don't already have a thread.
        let group_ids: Vec<i64> = {
            let mut stmt = self.conn().prepare(
                "SELECT g._id FROM group_v2 g
                 LEFT JOIN thread t ON t.group_id = g._id
                 WHERE t._id IS NULL",
            ).map_err(crate::error::StoreError::Database)?;
            stmt.query_map([], |row| row.get(0))
                .map_err(crate::error::StoreError::Database)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(crate::error::StoreError::Database)?
        };
        for gid in &group_ids {
            let _ = self.get_or_create_thread_for_group(*gid);
            created += 1;
        }

        Ok(created)
    }

    /// List all threads ordered by last message timestamp (most recent first).
    pub fn list_threads(&self) -> Result<Vec<crate::models::thread::Thread>> {
        use crate::models::thread::Thread;
        debug!("listing threads");
        let mut stmt = self.conn().prepare(
            "SELECT * FROM thread ORDER BY last_message_timestamp DESC NULLS LAST",
        )?;
        let rows = stmt
            .query_map([], Thread::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Update the thread's last message timestamp and unread count.
    pub fn update_thread_on_message(&self, thread_id: i64, timestamp: i64, is_incoming: bool) -> Result<()> {
        debug!(thread_id, timestamp, is_incoming, "updating thread on new message");
        if is_incoming {
            self.conn().execute(
                "UPDATE thread SET last_message_timestamp = ?1, unread_count = unread_count + 1
                 WHERE _id = ?2",
                rusqlite::params![timestamp, thread_id],
            )?;
        } else {
            self.conn().execute(
                "UPDATE thread SET last_message_timestamp = ?1
                 WHERE _id = ?2",
                rusqlite::params![timestamp, thread_id],
            )?;
        }
        Ok(())
    }

    /// Reset the unread count for a thread.
    pub fn reset_thread_unread_count(&self, thread_id: i64) -> Result<()> {
        debug!(thread_id, "resetting thread unread count");
        self.conn().execute(
            "UPDATE thread SET unread_count = 0 WHERE _id = ?1",
            [thread_id],
        )?;
        Ok(())
    }

    /// Update the draft text for a thread.
    pub fn update_thread_draft(&self, thread_id: i64, draft: Option<&str>) -> Result<()> {
        debug!(thread_id, "updating thread draft");
        self.conn().execute(
            "UPDATE thread SET draft = ?1 WHERE _id = ?2",
            rusqlite::params![draft, thread_id],
        )?;
        Ok(())
    }

    /// Set the pinned status for a thread.
    pub fn set_thread_pinned(&self, thread_id: i64, pinned: bool) -> Result<()> {
        debug!(thread_id, pinned, "setting thread pinned");
        self.conn().execute(
            "UPDATE thread SET pinned = ?1 WHERE _id = ?2",
            rusqlite::params![pinned as i64, thread_id],
        )?;
        Ok(())
    }

    /// Set the archived status for a thread.
    pub fn set_thread_archived(&self, thread_id: i64, archived: bool) -> Result<()> {
        debug!(thread_id, archived, "setting thread archived");
        self.conn().execute(
            "UPDATE thread SET archived = ?1 WHERE _id = ?2",
            rusqlite::params![archived as i64, thread_id],
        )?;
        Ok(())
    }

    /// Delete a thread and all its messages.
    pub fn delete_thread(&self, thread_id: i64) -> Result<()> {
        debug!(thread_id, "deleting thread");
        // Delete messages first.
        self.conn().execute(
            "DELETE FROM message WHERE thread_id = ?1",
            [thread_id],
        )?;
        let affected = self.conn().execute(
            "DELETE FROM thread WHERE _id = ?1",
            [thread_id],
        )?;
        if affected == 0 {
            return Err(StoreError::NotFound(format!("thread with id {thread_id}")));
        }
        Ok(())
    }

    /// Get a thread by ID.
    pub fn get_thread_by_id(&self, thread_id: i64) -> Result<Option<crate::models::thread::Thread>> {
        use crate::models::thread::Thread;
        debug!(thread_id, "loading thread by id");
        let result = self
            .conn()
            .query_row(
                "SELECT * FROM thread WHERE _id = ?1",
                [thread_id],
                Thread::from_row,
            )
            .ok();
        Ok(result)
    }

    /// List active (non-archived) threads ordered by last message timestamp.
    pub fn list_active_threads(&self) -> Result<Vec<crate::models::thread::Thread>> {
        use crate::models::thread::Thread;
        debug!("listing active threads");
        let mut stmt = self.conn().prepare(
            "SELECT * FROM thread WHERE archived = 0
             ORDER BY last_message_timestamp DESC NULLS LAST",
        )?;
        let rows = stmt
            .query_map([], Thread::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// List thread summaries with recipient/group info and the latest message.
    pub fn list_thread_summaries(&self) -> Result<Vec<crate::models::thread::ThreadSummary>> {
        use crate::models::thread::ThreadSummary;
        debug!("listing thread summaries");
        let mut stmt = self.conn().prepare(
            "SELECT
                t._id AS thread_id,
                t.recipient_id,
                t.group_id,
                t.last_message_timestamp,
                t.unread_count,
                t.pinned,
                t.archived,
                t.draft,
                COALESCE(
                    r.profile_given_name,
                    r.given_name,
                    r.number,
                    r.aci,
                    'Unknown'
                ) AS display_name,
                m.body AS last_message_body
             FROM thread t
             LEFT JOIN recipient r ON t.recipient_id = r._id
             LEFT JOIN message m ON m._id = (
                 SELECT _id FROM message WHERE thread_id = t._id ORDER BY timestamp DESC LIMIT 1
             )
             ORDER BY t.last_message_timestamp DESC NULLS LAST",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(ThreadSummary {
                    thread_id: row.get("thread_id")?,
                    recipient_id: row.get("recipient_id")?,
                    group_id: row.get::<_, Option<i64>>("group_id")?.map(|id| id.to_string()),
                    display_name: row.get("display_name")?,
                    last_message_body: row.get("last_message_body")?,
                    last_message_timestamp: row.get("last_message_timestamp")?,
                    unread_count: row.get("unread_count")?,
                    is_pinned: row.get::<_, i64>("pinned")? != 0,
                    is_archived: row.get::<_, i64>("archived")? != 0,
                    is_group: row.get::<_, Option<i64>>("group_id")?.is_some(),
                    draft: row.get("draft")?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // -- Reaction operations ------------------------------------------------

    /// Add or update a reaction on a message.
    ///
    /// If the sender already reacted to this message, the emoji and timestamp
    /// are updated (upsert via UNIQUE constraint on message_id + sender_aci).
    pub fn add_reaction(
        &self,
        message_id: i64,
        sender_aci: &str,
        emoji: &str,
        timestamp_ms: i64,
    ) -> Result<i64> {
        debug!(message_id, sender_aci, emoji, "adding reaction");
        self.conn().execute(
            "INSERT INTO reaction (message_id, sender_aci, emoji, timestamp_ms)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(message_id, sender_aci)
             DO UPDATE SET emoji = excluded.emoji, timestamp_ms = excluded.timestamp_ms",
            rusqlite::params![message_id, sender_aci, emoji, timestamp_ms],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    /// Remove a reaction from a message.
    pub fn remove_reaction(&self, message_id: i64, sender_aci: &str) -> Result<()> {
        debug!(message_id, sender_aci, "removing reaction");
        let affected = self.conn().execute(
            "DELETE FROM reaction WHERE message_id = ?1 AND sender_aci = ?2",
            rusqlite::params![message_id, sender_aci],
        )?;
        if affected == 0 {
            return Err(StoreError::NotFound(format!(
                "reaction on message {message_id} from {sender_aci}"
            )));
        }
        Ok(())
    }

    /// Get all reactions for a message, ordered by timestamp.
    pub fn get_reactions_for_message(&self, message_id: i64) -> Result<Vec<Reaction>> {
        debug!(message_id, "loading reactions for message");
        let mut stmt = self.conn().prepare(
            "SELECT * FROM reaction WHERE message_id = ?1 ORDER BY timestamp_ms",
        )?;
        let rows = stmt
            .query_map([message_id], Reaction::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Get a summary of reactions for a message (emoji -> count).
    pub fn get_reaction_summary(&self, message_id: i64) -> Result<ReactionSummary> {
        debug!(message_id, "loading reaction summary");
        let mut stmt = self.conn().prepare(
            "SELECT emoji, COUNT(*) as cnt FROM reaction
             WHERE message_id = ?1 GROUP BY emoji ORDER BY cnt DESC",
        )?;
        let mut summary = HashMap::new();
        let rows = stmt.query_map([message_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
        })?;
        for row in rows {
            let (emoji, count) = row?;
            summary.insert(emoji, count);
        }
        Ok(summary)
    }

    // -- Mention operations -------------------------------------------------

    /// Get parsed mentions for a message.
    pub fn get_mentions_for_message(
        &self,
        message_id: i64,
    ) -> Result<Vec<crate::models::message::Mention>> {
        debug!(message_id, "loading mentions for message");
        let msg = self.get_message_by_id(message_id)?
            .ok_or_else(|| StoreError::NotFound(format!("message with id {message_id}")))?;
        match msg.mentions {
            Some(json) => {
                let mentions: Vec<crate::models::message::Mention> =
                    serde_json::from_str(&json).map_err(|e| {
                        StoreError::InvalidData(format!("invalid mentions JSON: {e}"))
                    })?;
                Ok(mentions)
            }
            None => Ok(vec![]),
        }
    }

    // -- Call log operations ------------------------------------------------

    /// Insert a call log entry and return its ID.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_call(
        &self,
        call_id: &str,
        peer_aci: &str,
        call_type: &str,
        direction: &str,
        timestamp_ms: i64,
        duration_seconds: Option<i64>,
        status: &str,
    ) -> Result<i64> {
        debug!(call_id, peer_aci, status, "inserting call log entry");
        self.conn().execute(
            "INSERT INTO call_log (call_id, peer_aci, type, direction, timestamp_ms, duration_seconds, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![call_id, peer_aci, call_type, direction, timestamp_ms, duration_seconds, status],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    /// Get recent calls, ordered by timestamp descending.
    pub fn get_recent_calls(&self, limit: u32) -> Result<Vec<CallLogEntry>> {
        debug!(limit, "loading recent calls");
        let mut stmt = self.conn().prepare(
            "SELECT * FROM call_log ORDER BY timestamp_ms DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map([limit], CallLogEntry::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Get calls with a specific peer, ordered by timestamp descending.
    pub fn get_calls_with_peer(&self, peer_aci: &str) -> Result<Vec<CallLogEntry>> {
        debug!(peer_aci, "loading calls with peer");
        let mut stmt = self.conn().prepare(
            "SELECT * FROM call_log WHERE peer_aci = ?1 ORDER BY timestamp_ms DESC",
        )?;
        let rows = stmt
            .query_map([peer_aci], CallLogEntry::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_query_messages() {
        let db = Database::open_in_memory().unwrap();

        // Create a recipient and thread.
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();

        // Insert messages.
        let m1 = db.insert_message(thread.id, Some(r.id), 1000, None, Some("hello"), MessageType::Normal, None, None, None).unwrap();
        let m2 = db.insert_message(thread.id, Some(r.id), 2000, None, Some("world"), MessageType::Normal, None, None, None).unwrap();
        let _m3 = db.insert_message(thread.id, None, 3000, None, Some("reply"), MessageType::Normal, None, None, None).unwrap();

        // Get messages for thread.
        let msgs = db.get_messages_by_thread(thread.id, 10, None).unwrap();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].body.as_deref(), Some("hello"));
        assert_eq!(msgs[2].body.as_deref(), Some("reply"));

        // Pagination.
        let older = db.get_messages_by_thread(thread.id, 10, Some(2000)).unwrap();
        assert_eq!(older.len(), 1);
        assert_eq!(older[0].body.as_deref(), Some("hello"));

        // Mark read.
        let count = db.mark_messages_read(thread.id, 2000).unwrap();
        assert_eq!(count, 2);

        // Delete.
        db.delete_message(m1).unwrap();
        let msgs = db.get_messages_by_thread(thread.id, 10, None).unwrap();
        assert_eq!(msgs.len(), 2);

        // Get by ID.
        let loaded = db.get_message_by_id(m2).unwrap().expect("should exist");
        assert_eq!(loaded.body.as_deref(), Some("world"));
    }

    #[test]
    fn thread_operations() {
        let db = Database::open_in_memory().unwrap();

        let r = db.get_or_create_recipient("11111111-2222-3333-4444-555555555555").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();

        // Should return the same thread on second call.
        let thread2 = db.get_or_create_thread_for_recipient(r.id).unwrap();
        assert_eq!(thread.id, thread2.id);

        // Update on message.
        db.update_thread_on_message(thread.id, 5000, true).unwrap();
        let threads = db.list_threads().unwrap();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].unread_count, 1);
        assert_eq!(threads[0].last_message_timestamp, Some(5000));

        // Reset unread.
        db.reset_thread_unread_count(thread.id).unwrap();
        let threads = db.list_threads().unwrap();
        assert_eq!(threads[0].unread_count, 0);
    }

    #[test]
    fn get_message_by_timestamp_and_sender() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();

        let mid = db.insert_message(thread.id, Some(r.id), 1000, None, Some("hello"), MessageType::Normal, None, None, None).unwrap();

        let found = db.get_message_by_timestamp_and_sender(1000, r.id).unwrap().unwrap();
        assert_eq!(found.id, mid);
        assert!(db.get_message_by_timestamp_and_sender(9999, r.id).unwrap().is_none());
    }

    #[test]
    fn update_message_body() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();
        let mid = db.insert_message(thread.id, Some(r.id), 1000, None, Some("original"), MessageType::Normal, None, None, None).unwrap();

        db.update_message_body(mid, "edited").unwrap();
        let loaded = db.get_message_by_id(mid).unwrap().unwrap();
        assert_eq!(loaded.body.as_deref(), Some("edited"));
    }

    #[test]
    fn mark_message_deleted() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();
        let mid = db.insert_message(thread.id, Some(r.id), 1000, None, Some("hello"), MessageType::Normal, None, None, None).unwrap();

        db.mark_message_deleted(mid).unwrap();
        let loaded = db.get_message_by_id(mid).unwrap().unwrap();
        assert_eq!(loaded.message_type, MessageType::Delete);
        assert!(loaded.body.is_none());
    }

    #[test]
    fn unread_counts() {
        let db = Database::open_in_memory().unwrap();
        let r1 = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-111111111111").unwrap();
        let r2 = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-222222222222").unwrap();
        let t1 = db.get_or_create_thread_for_recipient(r1.id).unwrap();
        let t2 = db.get_or_create_thread_for_recipient(r2.id).unwrap();

        db.update_thread_on_message(t1.id, 1000, true).unwrap();
        db.update_thread_on_message(t1.id, 2000, true).unwrap();
        db.update_thread_on_message(t2.id, 3000, true).unwrap();

        assert_eq!(db.get_thread_unread_count(t1.id).unwrap(), 2);
        assert_eq!(db.get_thread_unread_count(t2.id).unwrap(), 1);
        assert_eq!(db.get_total_unread_count().unwrap(), 3);
    }

    #[test]
    fn search_messages() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();

        db.insert_message(thread.id, Some(r.id), 1000, None, Some("hello world"), MessageType::Normal, None, None, None).unwrap();
        db.insert_message(thread.id, Some(r.id), 2000, None, Some("goodbye world"), MessageType::Normal, None, None, None).unwrap();
        db.insert_message(thread.id, Some(r.id), 3000, None, Some("something else"), MessageType::Normal, None, None, None).unwrap();

        let results = db.search_messages("world").unwrap();
        assert_eq!(results.len(), 2);

        let results = db.search_messages("nonexistent").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn message_count_and_delete_all_in_thread() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();

        db.insert_message(thread.id, Some(r.id), 1000, None, Some("msg1"), MessageType::Normal, None, None, None).unwrap();
        db.insert_message(thread.id, Some(r.id), 2000, None, Some("msg2"), MessageType::Normal, None, None, None).unwrap();
        db.insert_message(thread.id, Some(r.id), 3000, None, Some("msg3"), MessageType::Normal, None, None, None).unwrap();

        assert_eq!(db.get_message_count_for_thread(thread.id).unwrap(), 3);

        db.delete_all_messages_in_thread(thread.id).unwrap();
        assert_eq!(db.get_message_count_for_thread(thread.id).unwrap(), 0);
    }

    #[test]
    fn thread_draft_pin_archive() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();

        // Draft
        db.update_thread_draft(thread.id, Some("hello draft")).unwrap();
        let loaded = db.get_thread_by_id(thread.id).unwrap().unwrap();
        assert_eq!(loaded.draft.as_deref(), Some("hello draft"));
        db.update_thread_draft(thread.id, None).unwrap();
        let loaded = db.get_thread_by_id(thread.id).unwrap().unwrap();
        assert!(loaded.draft.is_none());

        // Pin
        db.set_thread_pinned(thread.id, true).unwrap();
        let loaded = db.get_thread_by_id(thread.id).unwrap().unwrap();
        assert!(loaded.pinned);
        db.set_thread_pinned(thread.id, false).unwrap();
        let loaded = db.get_thread_by_id(thread.id).unwrap().unwrap();
        assert!(!loaded.pinned);

        // Archive
        db.set_thread_archived(thread.id, true).unwrap();
        let loaded = db.get_thread_by_id(thread.id).unwrap().unwrap();
        assert!(loaded.archived);

        // Archived thread should not appear in active threads list.
        let active = db.list_active_threads().unwrap();
        assert!(active.iter().all(|t| t.id != thread.id));

        db.set_thread_archived(thread.id, false).unwrap();
        let active = db.list_active_threads().unwrap();
        assert!(active.iter().any(|t| t.id == thread.id));
    }

    #[test]
    fn delete_thread() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();

        db.insert_message(thread.id, Some(r.id), 1000, None, Some("msg"), MessageType::Normal, None, None, None).unwrap();

        db.delete_thread(thread.id).unwrap();
        assert!(db.get_thread_by_id(thread.id).unwrap().is_none());
        assert_eq!(db.get_message_count_for_thread(thread.id).unwrap(), 0);

        // Deleting non-existent thread should error.
        assert!(db.delete_thread(9999).is_err());
    }

    #[test]
    fn list_thread_summaries() {
        let db = Database::open_in_memory().unwrap();

        let mut r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        r.profile_given_name = Some("Alice".into());
        db.update_recipient(&r).unwrap();

        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();
        db.insert_message(thread.id, Some(r.id), 1000, None, Some("hello"), MessageType::Normal, None, None, None).unwrap();
        db.update_thread_on_message(thread.id, 1000, true).unwrap();

        let summaries = db.list_thread_summaries().unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].display_name, "Alice");
        assert_eq!(summaries[0].last_message_body.as_deref(), Some("hello"));
        assert_eq!(summaries[0].unread_count, 1);
        assert!(!summaries[0].is_group);
    }

    #[test]
    fn insert_message_with_expiry_and_delete_expired() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();

        // Insert a message that expires at t=5000
        let m1 = db.insert_message_with_expiry(
            thread.id, Some(r.id), 1000, None, Some("expiring"),
            MessageType::Normal, None, Some(4), None, Some(5000),
        ).unwrap();

        // Insert a message that never expires
        let m2 = db.insert_message(
            thread.id, Some(r.id), 2000, None, Some("permanent"),
            MessageType::Normal, None, None, None,
        ).unwrap();

        // Insert another expiring message at t=10000
        let m3 = db.insert_message_with_expiry(
            thread.id, Some(r.id), 3000, None, Some("later expiry"),
            MessageType::Normal, None, Some(7), None, Some(10000),
        ).unwrap();

        // Verify the expires_at was stored
        let loaded = db.get_message_by_id(m1).unwrap().unwrap();
        assert_eq!(loaded.expires_at, Some(5000));
        let loaded = db.get_message_by_id(m2).unwrap().unwrap();
        assert_eq!(loaded.expires_at, None);

        // Delete expired at t=6000 -- only m1 should be deleted
        let deleted = db.delete_expired_messages(6000).unwrap();
        assert_eq!(deleted, 1);
        assert!(db.get_message_by_id(m1).unwrap().is_none());
        assert!(db.get_message_by_id(m2).unwrap().is_some());
        assert!(db.get_message_by_id(m3).unwrap().is_some());

        // Delete expired at t=10000 -- m3 should be deleted
        let deleted = db.delete_expired_messages(10000).unwrap();
        assert_eq!(deleted, 1);
        assert!(db.get_message_by_id(m3).unwrap().is_none());

        // m2 (no expiry) still exists
        assert!(db.get_message_by_id(m2).unwrap().is_some());

        // No more expired messages
        let deleted = db.delete_expired_messages(999999).unwrap();
        assert_eq!(deleted, 0);
    }

    // -- Reaction tests -----------------------------------------------------

    #[test]
    fn reaction_add_and_query() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();
        let mid = db.insert_message(thread.id, Some(r.id), 1000, None, Some("hello"), MessageType::Normal, None, None, None).unwrap();

        let sender1 = "11111111-1111-1111-1111-111111111111";
        let sender2 = "22222222-2222-2222-2222-222222222222";

        db.add_reaction(mid, sender1, "\u{1f44d}", 2000).unwrap();
        db.add_reaction(mid, sender2, "\u{2764}", 3000).unwrap();

        let reactions = db.get_reactions_for_message(mid).unwrap();
        assert_eq!(reactions.len(), 2);
        assert_eq!(reactions[0].emoji, "\u{1f44d}");
        assert_eq!(reactions[0].sender_aci, sender1);
        assert_eq!(reactions[1].emoji, "\u{2764}");
    }

    #[test]
    fn reaction_upsert_replaces_emoji() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();
        let mid = db.insert_message(thread.id, Some(r.id), 1000, None, Some("hello"), MessageType::Normal, None, None, None).unwrap();

        let sender = "11111111-1111-1111-1111-111111111111";
        db.add_reaction(mid, sender, "\u{1f44d}", 2000).unwrap();
        db.add_reaction(mid, sender, "\u{2764}", 3000).unwrap();

        // Should still be one reaction from this sender, now with heart emoji.
        let reactions = db.get_reactions_for_message(mid).unwrap();
        assert_eq!(reactions.len(), 1);
        assert_eq!(reactions[0].emoji, "\u{2764}");
        assert_eq!(reactions[0].timestamp_ms, 3000);
    }

    #[test]
    fn reaction_remove() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();
        let mid = db.insert_message(thread.id, Some(r.id), 1000, None, Some("hello"), MessageType::Normal, None, None, None).unwrap();

        let sender = "11111111-1111-1111-1111-111111111111";
        db.add_reaction(mid, sender, "\u{1f44d}", 2000).unwrap();
        db.remove_reaction(mid, sender).unwrap();

        let reactions = db.get_reactions_for_message(mid).unwrap();
        assert!(reactions.is_empty());

        // Removing non-existent reaction should error.
        assert!(db.remove_reaction(mid, sender).is_err());
    }

    #[test]
    fn reaction_summary() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();
        let mid = db.insert_message(thread.id, Some(r.id), 1000, None, Some("hello"), MessageType::Normal, None, None, None).unwrap();

        db.add_reaction(mid, "aci-1", "\u{1f44d}", 2000).unwrap();
        db.add_reaction(mid, "aci-2", "\u{1f44d}", 2001).unwrap();
        db.add_reaction(mid, "aci-3", "\u{2764}", 2002).unwrap();

        let summary = db.get_reaction_summary(mid).unwrap();
        assert_eq!(summary.get("\u{1f44d}"), Some(&2));
        assert_eq!(summary.get("\u{2764}"), Some(&1));
    }

    #[test]
    fn reactions_cascade_on_message_delete() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();
        let mid = db.insert_message(thread.id, Some(r.id), 1000, None, Some("hello"), MessageType::Normal, None, None, None).unwrap();

        db.add_reaction(mid, "aci-1", "\u{1f44d}", 2000).unwrap();
        db.add_reaction(mid, "aci-2", "\u{2764}", 2001).unwrap();

        db.delete_message(mid).unwrap();

        // Reactions should be cascaded away.
        let reactions = db.get_reactions_for_message(mid).unwrap();
        assert!(reactions.is_empty());
    }

    // -- Mention tests ------------------------------------------------------

    #[test]
    fn insert_and_get_mentions() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();

        let mentions_json = r#"[{"start":0,"length":5,"uuid":"11111111-1111-1111-1111-111111111111"}]"#;
        let mid = db.insert_message_full(
            thread.id, Some(r.id), 1000, None, Some("@User hello"), MessageType::Normal,
            None, None, None, None, Some(mentions_json),
        ).unwrap();

        let loaded = db.get_message_by_id(mid).unwrap().unwrap();
        assert_eq!(loaded.mentions.as_deref(), Some(mentions_json));

        let mentions = db.get_mentions_for_message(mid).unwrap();
        assert_eq!(mentions.len(), 1);
        assert_eq!(mentions[0].start, 0);
        assert_eq!(mentions[0].length, 5);
        assert_eq!(mentions[0].uuid, "11111111-1111-1111-1111-111111111111");
    }

    #[test]
    fn get_mentions_empty_for_no_mentions() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();
        let mid = db.insert_message(thread.id, Some(r.id), 1000, None, Some("hello"), MessageType::Normal, None, None, None).unwrap();

        let mentions = db.get_mentions_for_message(mid).unwrap();
        assert!(mentions.is_empty());
    }

    // -- Edit history tests -------------------------------------------------

    #[test]
    fn edit_preserves_original_body() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();
        let mid = db.insert_message(thread.id, Some(r.id), 1000, None, Some("original text"), MessageType::Normal, None, None, None).unwrap();

        // First edit.
        db.update_message_body(mid, "edited text").unwrap();
        let loaded = db.get_message_by_id(mid).unwrap().unwrap();
        assert_eq!(loaded.body.as_deref(), Some("edited text"));
        assert_eq!(loaded.original_body.as_deref(), Some("original text"));

        // Second edit should keep the original body unchanged.
        db.update_message_body(mid, "edited again").unwrap();
        let loaded = db.get_message_by_id(mid).unwrap().unwrap();
        assert_eq!(loaded.body.as_deref(), Some("edited again"));
        assert_eq!(loaded.original_body.as_deref(), Some("original text"));
    }

    #[test]
    fn get_edit_history_returns_original() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();
        let mid = db.insert_message(thread.id, Some(r.id), 1000, None, Some("v1"), MessageType::Normal, None, None, None).unwrap();

        // No edits yet.
        assert!(db.get_edit_history(mid).unwrap().is_none());

        db.update_message_body(mid, "v2").unwrap();
        assert_eq!(db.get_edit_history(mid).unwrap().as_deref(), Some("v1"));
    }

    // -- Call log tests -----------------------------------------------------

    #[test]
    fn insert_and_get_calls() {
        let db = Database::open_in_memory().unwrap();

        let peer = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        db.insert_call("call-1", peer, "AUDIO", "INCOMING", 1000, None, "MISSED").unwrap();
        db.insert_call("call-2", peer, "VIDEO", "OUTGOING", 2000, Some(120), "ANSWERED").unwrap();

        let calls = db.get_recent_calls(10).unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].call_id, "call-2"); // Most recent first.
        assert_eq!(calls[0].call_type, "VIDEO");
        assert_eq!(calls[0].direction, "OUTGOING");
        assert_eq!(calls[0].duration_seconds, Some(120));
        assert_eq!(calls[0].status, "ANSWERED");
        assert_eq!(calls[1].call_id, "call-1");
        assert_eq!(calls[1].status, "MISSED");
        assert_eq!(calls[1].duration_seconds, None);
    }

    #[test]
    fn get_calls_with_peer() {
        let db = Database::open_in_memory().unwrap();

        let peer1 = "11111111-1111-1111-1111-111111111111";
        let peer2 = "22222222-2222-2222-2222-222222222222";

        db.insert_call("call-1", peer1, "AUDIO", "INCOMING", 1000, None, "MISSED").unwrap();
        db.insert_call("call-2", peer2, "AUDIO", "OUTGOING", 2000, Some(60), "ANSWERED").unwrap();
        db.insert_call("call-3", peer1, "VIDEO", "INCOMING", 3000, Some(30), "ANSWERED").unwrap();

        let calls = db.get_calls_with_peer(peer1).unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].call_id, "call-3");
        assert_eq!(calls[1].call_id, "call-1");

        let calls = db.get_calls_with_peer(peer2).unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].call_id, "call-2");
    }

    #[test]
    fn get_recent_calls_limit() {
        let db = Database::open_in_memory().unwrap();
        let peer = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

        for i in 0..5 {
            db.insert_call(&format!("call-{i}"), peer, "AUDIO", "INCOMING", i * 1000, None, "MISSED").unwrap();
        }

        let calls = db.get_recent_calls(3).unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].call_id, "call-4"); // Most recent.
    }

    // -- FTS5 search tests --------------------------------------------------

    #[test]
    fn fts5_search_messages() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();

        db.insert_message(thread.id, Some(r.id), 1000, None, Some("hello world"), MessageType::Normal, None, None, None).unwrap();
        db.insert_message(thread.id, Some(r.id), 2000, None, Some("goodbye world"), MessageType::Normal, None, None, None).unwrap();
        db.insert_message(thread.id, Some(r.id), 3000, None, Some("something else"), MessageType::Normal, None, None, None).unwrap();

        let results = db.search_messages("world").unwrap();
        assert_eq!(results.len(), 2);

        let results = db.search_messages("hello").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].body.as_deref(), Some("hello world"));

        let results = db.search_messages("nonexistent").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn fts5_search_after_edit() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();

        let mid = db.insert_message(thread.id, Some(r.id), 1000, None, Some("original content"), MessageType::Normal, None, None, None).unwrap();

        // Should find by original.
        let results = db.search_messages("original").unwrap();
        assert_eq!(results.len(), 1);

        // Edit the message.
        db.update_message_body(mid, "edited content").unwrap();

        // Should no longer find by old body.
        let results = db.search_messages("original").unwrap();
        assert!(results.is_empty());

        // Should find by new body.
        let results = db.search_messages("edited").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn fts5_search_after_delete() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let thread = db.get_or_create_thread_for_recipient(r.id).unwrap();

        let mid = db.insert_message(thread.id, Some(r.id), 1000, None, Some("find me"), MessageType::Normal, None, None, None).unwrap();

        let results = db.search_messages("find").unwrap();
        assert_eq!(results.len(), 1);

        db.delete_message(mid).unwrap();

        let results = db.search_messages("find").unwrap();
        assert!(results.is_empty());
    }
}
