//! Recipient store — application-level CRUD for contacts.
//!
//! This is not a protocol store trait but provides higher-level operations
//! for managing Signal contacts.

use tracing::debug;

use crate::database::Database;
use crate::error::{Result, StoreError};
use crate::models::recipient::Recipient;

/// Recipient store operations on the database.
impl Database {
    /// Get a recipient by primary key.
    pub fn get_recipient_by_id(&self, id: i64) -> Result<Option<Recipient>> {
        debug!(id, "loading recipient by id");
        let result = self
            .conn()
            .query_row(
                "SELECT * FROM recipient WHERE _id = ?1",
                [id],
                Recipient::from_row,
            )
            .ok();
        Ok(result)
    }

    /// Get a recipient by ACI (Account Identity UUID string).
    pub fn get_recipient_by_aci(&self, aci: &str) -> Result<Option<Recipient>> {
        debug!(aci, "loading recipient by aci");
        let result = self
            .conn()
            .query_row(
                "SELECT * FROM recipient WHERE aci = ?1",
                [aci],
                Recipient::from_row,
            )
            .ok();
        Ok(result)
    }

    /// Get a recipient by phone number.
    pub fn get_recipient_by_number(&self, number: &str) -> Result<Option<Recipient>> {
        debug!(number, "loading recipient by number");
        let result = self
            .conn()
            .query_row(
                "SELECT * FROM recipient WHERE number = ?1",
                [number],
                Recipient::from_row,
            )
            .ok();
        Ok(result)
    }

    /// Get or create a recipient by ACI. If the recipient does not exist,
    /// a new row is inserted with minimal data and returned.
    pub fn get_or_create_recipient(&self, aci: &str) -> Result<Recipient> {
        debug!(aci, "get or create recipient");
        if let Some(r) = self.get_recipient_by_aci(aci)? {
            return Ok(r);
        }

        self.conn().execute(
            "INSERT INTO recipient (aci) VALUES (?1)",
            [aci],
        )?;

        let id = self.conn().last_insert_rowid();
        self.get_recipient_by_id(id)?
            .ok_or_else(|| StoreError::NotFound(format!("recipient with id {id} not found after insert")))
    }

    /// Update a recipient record.
    ///
    /// Updates all mutable fields (contact name, number, settings, etc.).
    pub fn update_recipient(&self, recipient: &Recipient) -> Result<()> {
        debug!(id = recipient.id, "updating recipient");
        self.conn().execute(
            "UPDATE recipient SET
                storage_id = ?1,
                storage_record = ?2,
                number = ?3,
                username = ?4,
                aci = ?5,
                pni = ?6,
                unregistered_timestamp = ?7,
                profile_key = ?8,
                profile_key_credential = ?9,
                given_name = ?10,
                family_name = ?11,
                nick_name = ?12,
                color = ?13,
                expiration_time = ?14,
                mute_until = ?15,
                blocked = ?16,
                archived = ?17,
                profile_sharing = ?18,
                hide_story = ?19,
                hidden = ?20,
                needs_pni_signature = ?21,
                discoverable = ?22,
                nick_name_given_name = ?23,
                nick_name_family_name = ?24,
                note = ?25,
                profile_phone_number_sharing = ?26,
                expiration_time_version = ?27,
                profile_last_update_timestamp = ?28,
                profile_given_name = ?29,
                profile_family_name = ?30,
                profile_about = ?31,
                profile_about_emoji = ?32,
                profile_avatar_url_path = ?33,
                profile_mobile_coin_address = ?34,
                profile_unidentified_access_mode = ?35,
                profile_capabilities = ?36
             WHERE _id = ?37",
            rusqlite::params![
                recipient.storage_id,
                recipient.storage_record,
                recipient.number,
                recipient.username,
                recipient.aci,
                recipient.pni,
                recipient.unregistered_timestamp,
                recipient.profile_key,
                recipient.profile_key_credential,
                recipient.given_name,
                recipient.family_name,
                recipient.nick_name,
                recipient.color,
                recipient.expiration_time,
                recipient.mute_until,
                recipient.blocked as i64,
                recipient.archived as i64,
                recipient.profile_sharing as i64,
                recipient.hide_story as i64,
                recipient.hidden as i64,
                recipient.needs_pni_signature as i64,
                recipient.discoverable.map(|v| v as i64),
                recipient.nick_name_given_name,
                recipient.nick_name_family_name,
                recipient.note,
                recipient.profile_phone_number_sharing,
                recipient.expiration_time_version,
                recipient.profile_last_update_timestamp,
                recipient.profile_given_name,
                recipient.profile_family_name,
                recipient.profile_about,
                recipient.profile_about_emoji,
                recipient.profile_avatar_url_path,
                recipient.profile_mobile_coin_address,
                recipient.profile_unidentified_access_mode,
                recipient.profile_capabilities,
                recipient.id,
            ],
        )?;
        Ok(())
    }

    /// List all recipients.
    pub fn list_all_recipients(&self) -> Result<Vec<Recipient>> {
        debug!("listing all recipients");
        let mut stmt = self.conn().prepare("SELECT * FROM recipient ORDER BY _id")?;
        let rows = stmt
            .query_map([], Recipient::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Get a recipient by username.
    pub fn get_recipient_by_username(&self, username: &str) -> Result<Option<Recipient>> {
        debug!(username, "loading recipient by username");
        let result = self
            .conn()
            .query_row(
                "SELECT * FROM recipient WHERE username = ?1",
                [username],
                Recipient::from_row,
            )
            .ok();
        Ok(result)
    }

    /// Get a recipient by PNI (Phone Number Identity).
    pub fn get_recipient_by_pni(&self, pni: &str) -> Result<Option<Recipient>> {
        debug!(pni, "loading recipient by pni");
        let result = self
            .conn()
            .query_row(
                "SELECT * FROM recipient WHERE pni = ?1",
                [pni],
                Recipient::from_row,
            )
            .ok();
        Ok(result)
    }

    /// Get or create a recipient by phone number.
    pub fn get_or_create_recipient_by_number(&self, number: &str) -> Result<Recipient> {
        debug!(number, "get or create recipient by number");
        if let Some(r) = self.get_recipient_by_number(number)? {
            return Ok(r);
        }

        self.conn().execute(
            "INSERT INTO recipient (number) VALUES (?1)",
            [number],
        )?;

        let id = self.conn().last_insert_rowid();
        self.get_recipient_by_id(id)?
            .ok_or_else(|| StoreError::NotFound(format!("recipient with id {id} not found after insert")))
    }

    /// Delete a recipient by ID.
    pub fn delete_recipient(&self, id: i64) -> Result<()> {
        debug!(id, "deleting recipient");
        let affected = self.conn().execute(
            "DELETE FROM recipient WHERE _id = ?1",
            [id],
        )?;
        if affected == 0 {
            return Err(StoreError::NotFound(format!("recipient with id {id}")));
        }
        Ok(())
    }

    /// Search recipients by matching against name, number, and username fields.
    pub fn search_recipients(&self, query: &str) -> Result<Vec<Recipient>> {
        debug!(query, "searching recipients");
        let pattern = format!("%{query}%");
        let mut stmt = self.conn().prepare(
            "SELECT * FROM recipient
             WHERE given_name LIKE ?1
                OR family_name LIKE ?1
                OR number LIKE ?1
                OR username LIKE ?1
                OR profile_given_name LIKE ?1
                OR profile_family_name LIKE ?1
             ORDER BY _id",
        )?;
        let rows = stmt
            .query_map([&pattern], Recipient::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Set the blocked status for a recipient.
    pub fn set_recipient_blocked(&self, id: i64, blocked: bool) -> Result<()> {
        debug!(id, blocked, "setting recipient blocked");
        self.conn().execute(
            "UPDATE recipient SET blocked = ?1 WHERE _id = ?2",
            rusqlite::params![blocked as i64, id],
        )?;
        Ok(())
    }

    /// Set the disappearing message timer for a recipient.
    pub fn set_recipient_expiration(&self, id: i64, timer_seconds: Option<i64>) -> Result<()> {
        debug!(id, ?timer_seconds, "setting recipient expiration");
        self.conn().execute(
            "UPDATE recipient SET expiration_time = ?1 WHERE _id = ?2",
            rusqlite::params![timer_seconds.unwrap_or(0), id],
        )?;
        Ok(())
    }

    /// Update a recipient's profile fields.
    pub fn update_recipient_profile(
        &self,
        id: i64,
        given_name: Option<&str>,
        family_name: Option<&str>,
        about: Option<&str>,
        about_emoji: Option<&str>,
        avatar_path: Option<&str>,
    ) -> Result<()> {
        debug!(id, "updating recipient profile");
        self.conn().execute(
            "UPDATE recipient SET
                profile_given_name = ?1,
                profile_family_name = ?2,
                profile_about = ?3,
                profile_about_emoji = ?4,
                profile_avatar_url_path = ?5
             WHERE _id = ?6",
            rusqlite::params![given_name, family_name, about, about_emoji, avatar_path, id],
        )?;
        Ok(())
    }

    /// Merge two recipients by moving all references from secondary to primary,
    /// then deleting the secondary recipient.
    pub fn merge_recipients(&self, primary_id: i64, secondary_id: i64) -> Result<()> {
        debug!(primary_id, secondary_id, "merging recipients");
        // Update message sender references.
        self.conn().execute(
            "UPDATE message SET sender_id = ?1 WHERE sender_id = ?2",
            rusqlite::params![primary_id, secondary_id],
        )?;
        // Update thread recipient references.
        self.conn().execute(
            "UPDATE thread SET recipient_id = ?1 WHERE recipient_id = ?2",
            rusqlite::params![primary_id, secondary_id],
        )?;
        // Update group member references (delete duplicates first to avoid UNIQUE constraint).
        self.conn().execute(
            "DELETE FROM group_v2_member
             WHERE recipient_id = ?1
               AND group_id IN (SELECT group_id FROM group_v2_member WHERE recipient_id = ?2)",
            rusqlite::params![secondary_id, primary_id],
        )?;
        self.conn().execute(
            "UPDATE group_v2_member SET recipient_id = ?1 WHERE recipient_id = ?2",
            rusqlite::params![primary_id, secondary_id],
        )?;
        // Delete the secondary recipient.
        self.conn().execute(
            "DELETE FROM recipient WHERE _id = ?1",
            [secondary_id],
        )?;
        Ok(())
    }

    /// Upsert a recipient from a storage sync contact record.
    ///
    /// Looks up an existing recipient by ACI. If found, updates all supplied
    /// fields. If not found, inserts a new row. Uses a single SQL statement
    /// with `INSERT ... ON CONFLICT DO UPDATE` for atomicity.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_recipient_from_sync(
        &self,
        aci: &str,
        storage_id: Option<&[u8]>,
        storage_record: Option<&[u8]>,
        number: Option<&str>,
        pni: Option<&str>,
        username: Option<&str>,
        profile_key: Option<&[u8]>,
        given_name: Option<&str>,
        family_name: Option<&str>,
        blocked: bool,
        archived: bool,
        profile_sharing: bool,
        hide_story: bool,
        hidden: bool,
        mute_until: i64,
        unregistered_timestamp: Option<i64>,
        nick_name_given_name: Option<&str>,
        nick_name_family_name: Option<&str>,
        note: Option<&str>,
    ) -> Result<Recipient> {
        debug!(aci, "upsert recipient from sync");
        self.conn().execute(
            "INSERT INTO recipient (
                aci, storage_id, storage_record, number, pni, username,
                profile_key, given_name, family_name, blocked, archived,
                profile_sharing, hide_story, hidden, mute_until,
                unregistered_timestamp, nick_name_given_name,
                nick_name_family_name, note
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6,
                ?7, ?8, ?9, ?10, ?11,
                ?12, ?13, ?14, ?15,
                ?16, ?17,
                ?18, ?19
             )
             ON CONFLICT(aci) DO UPDATE SET
                storage_id = excluded.storage_id,
                storage_record = excluded.storage_record,
                number = COALESCE(excluded.number, number),
                pni = COALESCE(excluded.pni, pni),
                username = COALESCE(excluded.username, username),
                profile_key = COALESCE(excluded.profile_key, profile_key),
                given_name = COALESCE(excluded.given_name, given_name),
                family_name = COALESCE(excluded.family_name, family_name),
                blocked = excluded.blocked,
                archived = excluded.archived,
                profile_sharing = excluded.profile_sharing,
                hide_story = excluded.hide_story,
                hidden = excluded.hidden,
                mute_until = excluded.mute_until,
                unregistered_timestamp = COALESCE(excluded.unregistered_timestamp, unregistered_timestamp),
                nick_name_given_name = COALESCE(excluded.nick_name_given_name, nick_name_given_name),
                nick_name_family_name = COALESCE(excluded.nick_name_family_name, nick_name_family_name),
                note = COALESCE(excluded.note, note)",
            rusqlite::params![
                aci,
                storage_id,
                storage_record,
                number,
                pni,
                username,
                profile_key,
                given_name,
                family_name,
                blocked as i64,
                archived as i64,
                profile_sharing as i64,
                hide_story as i64,
                hidden as i64,
                mute_until,
                unregistered_timestamp,
                nick_name_given_name,
                nick_name_family_name,
                note,
            ],
        )?;

        self.get_recipient_by_aci(aci)?
            .ok_or_else(|| StoreError::NotFound(format!("recipient with aci {aci} not found after upsert")))
    }

    /// List contacts: recipients that have a number or ACI and are not hidden.
    pub fn list_contacts(&self) -> Result<Vec<Recipient>> {
        debug!("listing contacts");
        let mut stmt = self.conn().prepare(
            "SELECT * FROM recipient
             WHERE (number IS NOT NULL OR aci IS NOT NULL)
               AND hidden = 0
             ORDER BY _id",
        )?;
        let rows = stmt
            .query_map([], Recipient::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_or_create_and_update_recipient() {
        let db = Database::open_in_memory().unwrap();
        let aci = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

        // Create.
        let r = db.get_or_create_recipient(aci).unwrap();
        assert_eq!(r.aci.as_deref(), Some(aci));
        assert_eq!(r.given_name, None);

        // Update.
        let mut r = r;
        r.given_name = Some("Alice".into());
        r.family_name = Some("Smith".into());
        r.number = Some("+15551234567".into());
        db.update_recipient(&r).unwrap();

        let loaded = db.get_recipient_by_aci(aci).unwrap().unwrap();
        assert_eq!(loaded.given_name.as_deref(), Some("Alice"));
        assert_eq!(loaded.number.as_deref(), Some("+15551234567"));

        // Get or create should return existing.
        let again = db.get_or_create_recipient(aci).unwrap();
        assert_eq!(again.id, loaded.id);
    }

    #[test]
    fn get_recipient_by_username() {
        let db = Database::open_in_memory().unwrap();
        let mut r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        r.username = Some("alice.01".into());
        db.update_recipient(&r).unwrap();

        let found = db.get_recipient_by_username("alice.01").unwrap().unwrap();
        assert_eq!(found.id, r.id);
        assert!(db.get_recipient_by_username("unknown").unwrap().is_none());
    }

    #[test]
    fn get_recipient_by_pni() {
        let db = Database::open_in_memory().unwrap();
        let mut r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        r.pni = Some("11111111-2222-3333-4444-555555555555".into());
        db.update_recipient(&r).unwrap();

        let found = db.get_recipient_by_pni("11111111-2222-3333-4444-555555555555").unwrap().unwrap();
        assert_eq!(found.id, r.id);
        assert!(db.get_recipient_by_pni("nonexistent").unwrap().is_none());
    }

    #[test]
    fn get_or_create_recipient_by_number() {
        let db = Database::open_in_memory().unwrap();
        let r1 = db.get_or_create_recipient_by_number("+15551234567").unwrap();
        let r2 = db.get_or_create_recipient_by_number("+15551234567").unwrap();
        assert_eq!(r1.id, r2.id);
        assert_eq!(r1.number.as_deref(), Some("+15551234567"));
    }

    #[test]
    fn delete_recipient() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-111111111111").unwrap();
        db.delete_recipient(r.id).unwrap();
        assert!(db.get_recipient_by_id(r.id).unwrap().is_none());

        // Deleting non-existent should error.
        assert!(db.delete_recipient(9999).is_err());
    }

    #[test]
    fn search_recipients() {
        let db = Database::open_in_memory().unwrap();
        let mut r1 = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-111111111111").unwrap();
        r1.given_name = Some("Alice".into());
        r1.family_name = Some("Smith".into());
        r1.number = Some("+15551234567".into());
        db.update_recipient(&r1).unwrap();

        let mut r2 = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-222222222222").unwrap();
        r2.given_name = Some("Bob".into());
        r2.profile_given_name = Some("Bobby".into());
        db.update_recipient(&r2).unwrap();

        let results = db.search_recipients("Alice").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, r1.id);

        let results = db.search_recipients("Bob").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, r2.id);

        let results = db.search_recipients("555").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, r1.id);

        let results = db.search_recipients("nonexistent").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn set_recipient_blocked() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-111111111111").unwrap();
        assert!(!r.blocked);

        db.set_recipient_blocked(r.id, true).unwrap();
        let loaded = db.get_recipient_by_id(r.id).unwrap().unwrap();
        assert!(loaded.blocked);

        db.set_recipient_blocked(r.id, false).unwrap();
        let loaded = db.get_recipient_by_id(r.id).unwrap().unwrap();
        assert!(!loaded.blocked);
    }

    #[test]
    fn set_recipient_expiration() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-111111111111").unwrap();

        db.set_recipient_expiration(r.id, Some(3600)).unwrap();
        let loaded = db.get_recipient_by_id(r.id).unwrap().unwrap();
        assert_eq!(loaded.expiration_time, 3600);

        db.set_recipient_expiration(r.id, None).unwrap();
        let loaded = db.get_recipient_by_id(r.id).unwrap().unwrap();
        assert_eq!(loaded.expiration_time, 0);
    }

    #[test]
    fn update_recipient_profile() {
        let db = Database::open_in_memory().unwrap();
        let r = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-111111111111").unwrap();

        db.update_recipient_profile(
            r.id,
            Some("Alice"),
            Some("Smith"),
            Some("Hello world"),
            Some("🎉"),
            Some("/avatars/alice.jpg"),
        )
        .unwrap();

        let loaded = db.get_recipient_by_id(r.id).unwrap().unwrap();
        assert_eq!(loaded.profile_given_name.as_deref(), Some("Alice"));
        assert_eq!(loaded.profile_family_name.as_deref(), Some("Smith"));
        assert_eq!(loaded.profile_about.as_deref(), Some("Hello world"));
        assert_eq!(loaded.profile_about_emoji.as_deref(), Some("🎉"));
        assert_eq!(loaded.profile_avatar_url_path.as_deref(), Some("/avatars/alice.jpg"));
    }

    #[test]
    fn merge_recipients() {
        let db = Database::open_in_memory().unwrap();
        let r1 = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-111111111111").unwrap();
        let r2 = db.get_or_create_recipient("aaaaaaaa-bbbb-cccc-dddd-222222222222").unwrap();

        // Create a thread for the secondary recipient.
        let thread = db.get_or_create_thread_for_recipient(r2.id).unwrap();
        // Insert a message from the secondary recipient.
        db.insert_message(thread.id, Some(r2.id), 1000, None, Some("hello"), crate::models::message::MessageType::Normal, None, None, None).unwrap();

        // Merge r2 into r1.
        db.merge_recipients(r1.id, r2.id).unwrap();

        // Secondary should be gone.
        assert!(db.get_recipient_by_id(r2.id).unwrap().is_none());

        // Thread should now point to r1.
        let threads = db.list_threads().unwrap();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].recipient_id, Some(r1.id));

        // Message should now reference r1 as sender.
        let msgs = db.get_messages_by_thread(thread.id, 10, None).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].sender_id, Some(r1.id));
    }

    #[test]
    fn list_contacts_excludes_hidden() {
        let db = Database::open_in_memory().unwrap();

        // Create two recipients.
        let r1 = db.get_or_create_recipient("11111111-1111-1111-1111-111111111111").unwrap();
        let mut r2 = db.get_or_create_recipient("22222222-2222-2222-2222-222222222222").unwrap();

        // Hide the second one.
        r2.hidden = true;
        db.update_recipient(&r2).unwrap();

        let contacts = db.list_contacts().unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].id, r1.id);
    }

    #[test]
    fn upsert_recipient_from_sync_creates_new() {
        let db = Database::open_in_memory().unwrap();
        let aci = "aaaaaaaa-bbbb-cccc-dddd-111111111111";

        let r = db
            .upsert_recipient_from_sync(
                aci,
                Some(&[0x01; 16]),
                Some(&[0x02; 32]),
                Some("+15551234567"),
                Some("11111111-2222-3333-4444-555555555555"),
                Some("alice.01"),
                Some(&[0xAB; 32]),
                Some("Alice"),
                Some("Smith"),
                false,  // blocked
                false,  // archived
                true,   // profile_sharing
                false,  // hide_story
                false,  // hidden
                0,      // mute_until
                None,   // unregistered_timestamp
                None,   // nick_name_given_name
                None,   // nick_name_family_name
                Some("A note"),
            )
            .unwrap();

        assert_eq!(r.aci.as_deref(), Some(aci));
        assert_eq!(r.number.as_deref(), Some("+15551234567"));
        assert_eq!(r.pni.as_deref(), Some("11111111-2222-3333-4444-555555555555"));
        assert_eq!(r.username.as_deref(), Some("alice.01"));
        assert_eq!(r.profile_key.as_deref(), Some(&[0xAB; 32][..]));
        assert_eq!(r.given_name.as_deref(), Some("Alice"));
        assert_eq!(r.family_name.as_deref(), Some("Smith"));
        assert!(!r.blocked);
        assert!(r.profile_sharing);
        assert_eq!(r.note.as_deref(), Some("A note"));
        assert_eq!(r.storage_id.as_deref(), Some(&[0x01; 16][..]));
    }

    #[test]
    fn upsert_recipient_from_sync_updates_existing() {
        let db = Database::open_in_memory().unwrap();
        let aci = "aaaaaaaa-bbbb-cccc-dddd-222222222222";

        // Create a recipient with initial data.
        let mut initial = db.get_or_create_recipient(aci).unwrap();
        initial.given_name = Some("OldName".to_string());
        initial.number = Some("+15550000000".to_string());
        db.update_recipient(&initial).unwrap();

        // Upsert with new data.
        let updated = db
            .upsert_recipient_from_sync(
                aci,
                Some(&[0x03; 16]),
                None,
                None,  // number is None, should keep old value via COALESCE
                None,
                None,
                None,
                Some("NewName"),
                None,
                true,  // blocked
                false,
                false,
                false,
                false,
                0,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        // ID should be the same (not a new row).
        assert_eq!(updated.id, initial.id);
        // Name should be updated.
        assert_eq!(updated.given_name.as_deref(), Some("NewName"));
        // Number should be preserved from old value.
        assert_eq!(updated.number.as_deref(), Some("+15550000000"));
        // Blocked should be updated.
        assert!(updated.blocked);
    }

    #[test]
    fn upsert_recipient_from_sync_preserves_old_values_when_new_are_null() {
        let db = Database::open_in_memory().unwrap();
        let aci = "aaaaaaaa-bbbb-cccc-dddd-333333333333";

        // First upsert with full data.
        db.upsert_recipient_from_sync(
            aci,
            Some(&[0x04; 16]),
            None,
            Some("+15551111111"),
            Some("pni-1111"),
            Some("user.01"),
            Some(&[0xAB; 32]),
            Some("First"),
            Some("Last"),
            false, false, false, false, false, 0,
            None, None, None,
            Some("note1"),
        )
        .unwrap();

        // Second upsert with all optional fields as None.
        let r = db
            .upsert_recipient_from_sync(
                aci,
                Some(&[0x05; 16]), // storage_id updates
                None,
                None, None, None, None, None, None,
                true, // blocked changes
                false, false, false, false, 0,
                None, None, None, None,
            )
            .unwrap();

        // COALESCE should preserve the original values.
        assert_eq!(r.number.as_deref(), Some("+15551111111"));
        assert_eq!(r.pni.as_deref(), Some("pni-1111"));
        assert_eq!(r.username.as_deref(), Some("user.01"));
        assert_eq!(r.given_name.as_deref(), Some("First"));
        assert_eq!(r.family_name.as_deref(), Some("Last"));
        assert_eq!(r.note.as_deref(), Some("note1"));
        // But blocked should have changed.
        assert!(r.blocked);
        // And storage_id should have updated.
        assert_eq!(r.storage_id.as_deref(), Some(&[0x05; 16][..]));
    }
}
