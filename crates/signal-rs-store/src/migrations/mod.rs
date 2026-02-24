//! Database migration system.
//!
//! Migrations are applied incrementally. Each migration is a (version, sql) tuple.
//! Since this is a new project, the initial migration (version 1) creates all
//! tables at once, matching signal-cli's AccountDatabase schema version 28.

/// The current schema version.
pub const CURRENT_VERSION: u32 = 3;

/// All migrations, ordered by version number.
///
/// Each entry is `(version, sql_statements)`. The SQL in version 1 creates the
/// full schema corresponding to signal-cli's AccountDatabase at version 28.
pub const MIGRATIONS: &[(u32, &str)] = &[
    (1, r#"
-- =========================================================================
-- signal-rs-store schema v1
-- Based on signal-cli AccountDatabase schema version 28
-- =========================================================================

-- Recipient table: stores contacts, their profile data, and settings
CREATE TABLE recipient (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    storage_id BLOB UNIQUE,
    storage_record BLOB,
    number TEXT UNIQUE,
    username TEXT UNIQUE,
    aci TEXT UNIQUE,
    pni TEXT UNIQUE,
    unregistered_timestamp INTEGER,
    profile_key BLOB,
    profile_key_credential BLOB,

    given_name TEXT,
    family_name TEXT,
    nick_name TEXT,
    color TEXT,

    expiration_time INTEGER NOT NULL DEFAULT 0,
    mute_until INTEGER NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0,
    archived INTEGER NOT NULL DEFAULT 0,
    profile_sharing INTEGER NOT NULL DEFAULT 0,
    hide_story INTEGER NOT NULL DEFAULT 0,
    hidden INTEGER NOT NULL DEFAULT 0,
    needs_pni_signature INTEGER NOT NULL DEFAULT 0,
    discoverable INTEGER,

    nick_name_given_name TEXT,
    nick_name_family_name TEXT,
    note TEXT,
    profile_phone_number_sharing TEXT,
    expiration_time_version INTEGER NOT NULL DEFAULT 1,

    profile_last_update_timestamp INTEGER NOT NULL DEFAULT 0,
    profile_given_name TEXT,
    profile_family_name TEXT,
    profile_about TEXT,
    profile_about_emoji TEXT,
    profile_avatar_url_path TEXT,
    profile_mobile_coin_address BLOB,
    profile_unidentified_access_mode TEXT,
    profile_capabilities TEXT
) STRICT;

-- Session table: stores Signal protocol sessions
CREATE TABLE session (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id_type INTEGER NOT NULL,
    address TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    record BLOB NOT NULL,
    UNIQUE(account_id_type, address, device_id)
) STRICT;

-- Pre-key table: stores one-time pre-keys
CREATE TABLE pre_key (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id_type INTEGER NOT NULL,
    key_id INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    private_key BLOB NOT NULL,
    stale_timestamp INTEGER,
    UNIQUE(account_id_type, key_id)
) STRICT;

-- Signed pre-key table
CREATE TABLE signed_pre_key (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id_type INTEGER NOT NULL,
    key_id INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    private_key BLOB NOT NULL,
    signature BLOB NOT NULL,
    timestamp INTEGER DEFAULT 0,
    stale_timestamp INTEGER,
    UNIQUE(account_id_type, key_id)
) STRICT;

-- Kyber (post-quantum) pre-key table
CREATE TABLE kyber_pre_key (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id_type INTEGER NOT NULL,
    key_id INTEGER NOT NULL,
    serialized BLOB NOT NULL,
    is_last_resort INTEGER NOT NULL,
    stale_timestamp INTEGER,
    timestamp INTEGER DEFAULT 0,
    UNIQUE(account_id_type, key_id)
) STRICT;

-- Identity key table: stores remote identity keys and trust decisions
CREATE TABLE identity (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT UNIQUE NOT NULL,
    identity_key BLOB NOT NULL,
    added_timestamp INTEGER NOT NULL,
    trust_level INTEGER NOT NULL
) STRICT;

-- Sender key table: stores sender keys for group messaging
CREATE TABLE sender_key (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    distribution_id BLOB NOT NULL,
    record BLOB NOT NULL,
    created_timestamp INTEGER NOT NULL,
    UNIQUE(address, device_id, distribution_id)
) STRICT;

-- Sender key shared table: tracks which sender keys have been distributed
CREATE TABLE sender_key_shared (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    distribution_id BLOB NOT NULL,
    timestamp INTEGER NOT NULL,
    UNIQUE(address, device_id, distribution_id)
) STRICT;

-- Group V2 table
CREATE TABLE group_v2 (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id BLOB UNIQUE NOT NULL,
    master_key BLOB NOT NULL,
    group_data BLOB,
    distribution_id BLOB UNIQUE NOT NULL,
    blocked INTEGER NOT NULL DEFAULT 0,
    permission_denied INTEGER NOT NULL DEFAULT 0,
    storage_id BLOB,
    storage_record BLOB,
    profile_sharing INTEGER NOT NULL DEFAULT 1,
    endorsement_expiration_time INTEGER NOT NULL DEFAULT 0
) STRICT;

-- Group V2 member table
CREATE TABLE group_v2_member (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL REFERENCES group_v2 (_id) ON DELETE CASCADE,
    recipient_id INTEGER NOT NULL REFERENCES recipient (_id) ON DELETE CASCADE,
    endorsement BLOB NOT NULL,
    UNIQUE(group_id, recipient_id)
) STRICT;

-- Sticker table
CREATE TABLE sticker (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    pack_id BLOB UNIQUE NOT NULL,
    pack_key BLOB NOT NULL,
    installed INTEGER NOT NULL DEFAULT 0
) STRICT;

-- Key-value store for miscellaneous settings
CREATE TABLE key_value (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    value ANY
) STRICT;

-- CDSI (Contact Discovery Service Integration) cache
CREATE TABLE cdsi (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    number TEXT NOT NULL UNIQUE,
    last_seen_at INTEGER NOT NULL
) STRICT;

-- Storage ID table for storage service sync
CREATE TABLE storage_id (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    type INTEGER NOT NULL,
    storage_id BLOB UNIQUE NOT NULL
) STRICT;

-- Message table (for TUI display)
CREATE TABLE message (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER NOT NULL,
    sender_id INTEGER REFERENCES recipient (_id) ON DELETE SET NULL,
    timestamp INTEGER NOT NULL,
    server_timestamp INTEGER,
    body TEXT,
    message_type INTEGER NOT NULL DEFAULT 0,
    quote_id INTEGER,
    expires_in INTEGER,
    expire_start INTEGER,
    read INTEGER NOT NULL DEFAULT 0,
    attachments_json TEXT
) STRICT;

CREATE INDEX idx_message_thread_timestamp ON message (thread_id, timestamp);

-- Thread / conversation table (for TUI display)
CREATE TABLE thread (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id INTEGER REFERENCES recipient (_id) ON DELETE SET NULL,
    group_id INTEGER REFERENCES group_v2 (_id) ON DELETE SET NULL,
    last_message_timestamp INTEGER,
    unread_count INTEGER NOT NULL DEFAULT 0,
    pinned INTEGER NOT NULL DEFAULT 0,
    archived INTEGER NOT NULL DEFAULT 0,
    draft TEXT
) STRICT;

CREATE INDEX idx_thread_last_message ON thread (last_message_timestamp DESC);
"#),
    (2, r#"
-- =========================================================================
-- signal-rs-store schema v2
-- Add expires_at column for disappearing messages
-- =========================================================================

ALTER TABLE message ADD COLUMN expires_at INTEGER;

CREATE INDEX idx_message_expires_at ON message (expires_at) WHERE expires_at IS NOT NULL;
"#),
    (3, r#"
-- =========================================================================
-- signal-rs-store schema v3
-- Reactions, mentions, call log, edit history, FTS5
-- =========================================================================

-- Reaction table: stores emoji reactions to messages
CREATE TABLE reaction (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL REFERENCES message (_id) ON DELETE CASCADE,
    sender_aci TEXT NOT NULL,
    emoji TEXT NOT NULL,
    timestamp_ms INTEGER NOT NULL,
    UNIQUE(message_id, sender_aci)
) STRICT;

CREATE INDEX idx_reaction_message_id ON reaction (message_id);

-- Mentions column: JSON array of {start, length, uuid}
ALTER TABLE message ADD COLUMN mentions TEXT;

-- Edit history: preserve original body before edits
ALTER TABLE message ADD COLUMN original_body TEXT;

-- Call log table
CREATE TABLE call_log (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    call_id TEXT NOT NULL,
    peer_aci TEXT NOT NULL,
    type TEXT NOT NULL,
    direction TEXT NOT NULL,
    timestamp_ms INTEGER NOT NULL,
    duration_seconds INTEGER,
    status TEXT NOT NULL
) STRICT;

CREATE INDEX idx_call_log_peer_aci ON call_log (peer_aci);
CREATE INDEX idx_call_log_timestamp ON call_log (timestamp_ms DESC);

-- FTS5 full-text search index on message body
CREATE VIRTUAL TABLE message_fts USING fts5(body, content=message, content_rowid=_id);

-- Populate FTS index with existing messages
INSERT INTO message_fts(rowid, body) SELECT _id, body FROM message WHERE body IS NOT NULL;

-- Triggers to keep FTS index in sync
CREATE TRIGGER message_fts_insert AFTER INSERT ON message BEGIN
    INSERT INTO message_fts(rowid, body) VALUES (new._id, new.body);
END;

CREATE TRIGGER message_fts_delete AFTER DELETE ON message BEGIN
    INSERT INTO message_fts(message_fts, rowid, body) VALUES('delete', old._id, old.body);
END;

CREATE TRIGGER message_fts_update AFTER UPDATE OF body ON message BEGIN
    INSERT INTO message_fts(message_fts, rowid, body) VALUES('delete', old._id, old.body);
    INSERT INTO message_fts(rowid, body) VALUES (new._id, new.body);
END;
"#),
];
