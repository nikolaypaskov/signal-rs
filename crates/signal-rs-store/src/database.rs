//! Database connection manager.
//!
//! Wraps a `rusqlite::Connection` and provides migration support
//! plus key-value helpers for account state persistence.

use std::fs;
use std::io::Read;
use std::path::Path;

use rusqlite::Connection;
use tracing::{debug, info};

use crate::error::{Result, StoreError};
use crate::migrations::{CURRENT_VERSION, MIGRATIONS};

/// The SQLite database connection manager.
///
/// Holds a single connection and provides methods for opening, migrating,
/// and executing queries.
pub struct Database {
    /// The underlying SQLite connection.
    conn: Connection,
}

impl Database {
    /// Open (or create) an encrypted database at the given file path.
    ///
    /// Issues `PRAGMA key` as the first statement after opening, then verifies
    /// the passphrase by reading from the database. Returns `WrongPassphrase`
    /// if the key is incorrect.
    pub fn open(path: &Path, passphrase: &str) -> Result<Self> {
        debug!(?path, "opening encrypted database");
        let conn = Connection::open(path)?;
        Self::apply_key(&conn, passphrase)?;
        let db = Self { conn };
        db.configure_pragmas()?;
        db.migrate()?;
        Ok(db)
    }

    /// Open an in-memory encrypted database (useful for testing).
    ///
    /// Uses a fixed `"test"` passphrase so existing test call sites don't
    /// need to change.
    pub fn open_in_memory() -> Result<Self> {
        debug!("opening in-memory database");
        let conn = Connection::open_in_memory()?;
        Self::apply_key(&conn, "test")?;
        let db = Self { conn };
        db.configure_pragmas()?;
        db.migrate()?;
        Ok(db)
    }

    /// Check whether a database file is unencrypted (plaintext SQLite).
    ///
    /// A standard SQLite file starts with the 16-byte header `"SQLite format 3\0"`.
    /// An encrypted (SQLCipher) file will have different leading bytes.
    /// Returns `false` for non-existent files.
    pub fn is_encrypted(path: &Path) -> std::io::Result<bool> {
        if !path.exists() {
            return Ok(false);
        }
        let mut file = fs::File::open(path)?;
        let mut header = [0u8; 16];
        let n = file.read(&mut header)?;
        if n < 16 {
            // Too small to be a valid SQLite file — treat as encrypted/unknown.
            return Ok(true);
        }
        Ok(&header != b"SQLite format 3\0")
    }

    /// Encrypt an existing plaintext database file in place.
    ///
    /// Uses SQLCipher's `sqlcipher_export()` to copy data from the plaintext
    /// database into a new encrypted database, then replaces the original.
    pub fn encrypt_existing(path: &Path, passphrase: &str) -> Result<()> {
        let encrypted_path = path.with_extension("db.encrypting");

        // Open the plaintext database (no key).
        let plain_conn = Connection::open(path)?;

        // Attach the new encrypted database.
        plain_conn.execute_batch(&format!(
            "ATTACH DATABASE '{}' AS encrypted KEY '{}';",
            encrypted_path.display(),
            passphrase.replace('\'', "''"),
        ))?;

        // Export all data to the encrypted database.
        plain_conn.execute_batch("SELECT sqlcipher_export('encrypted');")?;
        plain_conn.execute_batch("DETACH DATABASE encrypted;")?;
        drop(plain_conn);

        // Replace the original file with the encrypted version.
        fs::rename(&encrypted_path, path)?;

        // Clean up WAL/SHM files from the old plaintext database.
        let wal = path.with_extension("db-wal");
        let shm = path.with_extension("db-shm");
        let _ = fs::remove_file(wal);
        let _ = fs::remove_file(shm);

        Ok(())
    }

    /// Return a reference to the underlying connection.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Run all pending migrations.
    pub fn migrate(&self) -> Result<()> {
        self.ensure_version_table()?;
        let current = self.get_schema_version()?;
        debug!(current_version = current, target_version = CURRENT_VERSION, "checking migrations");

        if current >= CURRENT_VERSION {
            return Ok(());
        }

        for &(version, sql) in MIGRATIONS {
            if version > current {
                info!(version, "applying migration");
                self.conn.execute_batch(sql).map_err(|e| {
                    StoreError::Migration(format!(
                        "failed to apply migration v{version}: {e}"
                    ))
                })?;
                self.set_schema_version(version)?;
            }
        }

        info!(version = CURRENT_VERSION, "database migration complete");
        Ok(())
    }

    /// Execute a closure inside a database transaction.
    ///
    /// If the closure returns `Ok`, the transaction is committed.
    /// If the closure returns `Err`, the transaction is rolled back.
    pub fn transaction<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        self.conn.execute_batch("BEGIN")?;
        match f() {
            Ok(val) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(val)
            }
            Err(e) => {
                self.conn.execute_batch("ROLLBACK")?;
                Err(e)
            }
        }
    }

    // -- Crypto state purge -------------------------------------------------

    /// Delete all sessions, pre-keys, signed pre-keys, kyber pre-keys, and
    /// sender keys.  Also resets the next-ID counters so fresh keys start at 1.
    ///
    /// Preserves account credentials, identity key pairs, contacts, messages,
    /// groups, and all other non-crypto state.
    pub fn purge_crypto_state(&self) -> Result<()> {
        self.transaction(|| {
            self.conn.execute_batch(
                "DELETE FROM session;
                 DELETE FROM pre_key;
                 DELETE FROM signed_pre_key;
                 DELETE FROM kyber_pre_key;
                 DELETE FROM sender_key;
                 DELETE FROM sender_key_shared;",
            )?;
            // Reset pre-key ID counters so the next upload starts fresh.
            self.delete_kv("next_pre_key_id")?;
            self.delete_kv("next_signed_pre_key_id")?;
            self.delete_kv("next_kyber_pre_key_id")?;
            Ok(())
        })
    }

    // -- Key-Value helpers --------------------------------------------------

    /// Get a string value from the key_value table.
    pub fn get_kv_string(&self, key: &str) -> Result<Option<String>> {
        let result = self.conn.query_row(
            "SELECT value FROM key_value WHERE key = ?1",
            [key],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(val) => Ok(Some(val)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Set a string value in the key_value table.
    pub fn set_kv_string(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO key_value (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    /// Get a blob value from the key_value table.
    pub fn get_kv_blob(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let result = self.conn.query_row(
            "SELECT value FROM key_value WHERE key = ?1",
            [key],
            |row| row.get::<_, Vec<u8>>(0),
        );
        match result {
            Ok(val) => Ok(Some(val)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Set a blob value in the key_value table.
    pub fn set_kv_blob(&self, key: &str, value: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO key_value (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    /// Delete a key from the key_value table.
    pub fn delete_kv(&self, key: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM key_value WHERE key = ?1",
            [key],
        )?;
        Ok(())
    }

    // -- private helpers ----------------------------------------------------

    /// Set recommended SQLite pragmas for performance and safety.
    fn configure_pragmas(&self) -> Result<()> {
        self.conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        Ok(())
    }

    /// Create the internal version tracking table if it does not exist.
    fn ensure_version_table(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _schema_version (
                version INTEGER NOT NULL
            );",
        )?;
        Ok(())
    }

    /// Read the current schema version (0 if no version row exists).
    fn get_schema_version(&self) -> Result<u32> {
        let version: Option<u32> = self.conn.query_row(
            "SELECT version FROM _schema_version LIMIT 1",
            [],
            |row| row.get(0),
        ).ok();
        Ok(version.unwrap_or(0))
    }

    /// Issue `PRAGMA key` and verify that the database is readable.
    ///
    /// Must be called immediately after opening the connection, before any
    /// other statements.
    fn apply_key(conn: &Connection, passphrase: &str) -> Result<()> {
        conn.pragma_update(None, "key", passphrase)?;
        // Verify the key is correct by reading from the database.
        // If the passphrase is wrong, this will fail with a "not a database" error.
        match conn.query_row("SELECT count(*) FROM sqlite_master", [], |_row| Ok(())) {
            Ok(()) => Ok(()),
            Err(_) => Err(StoreError::WrongPassphrase),
        }
    }

    /// Store the schema version.
    fn set_schema_version(&self, version: u32) -> Result<()> {
        let count: u32 = self.conn.query_row(
            "SELECT COUNT(*) FROM _schema_version",
            [],
            |row| row.get(0),
        )?;
        if count == 0 {
            self.conn.execute(
                "INSERT INTO _schema_version (version) VALUES (?1)",
                [version],
            )?;
        } else {
            self.conn.execute(
                "UPDATE _schema_version SET version = ?1",
                [version],
            )?;
        }
        Ok(())
    }
}

/// Account data key constants for the key_value table.
pub mod account_keys {
    pub const PHONE_NUMBER: &str = "phone_number";
    pub const ACI_UUID: &str = "aci_uuid";
    pub const PNI_UUID: &str = "pni_uuid";
    pub const DEVICE_ID: &str = "device_id";
    pub const PASSWORD: &str = "password";
    pub const IDENTITY_KEY_PAIR: &str = "identity_key_pair";
    pub const PNI_IDENTITY_KEY_PAIR: &str = "pni_identity_key_pair";
    pub const REGISTRATION_ID: &str = "registration_id";
    pub const PNI_REGISTRATION_ID: &str = "pni_registration_id";
    pub const PROFILE_KEY: &str = "profile_key";
    pub const MASTER_KEY: &str = "master_key";
    pub const IS_PRIMARY_DEVICE: &str = "is_primary_device";
    pub const REGISTERED: &str = "registered";
    pub const VERIFICATION_SESSION_ID: &str = "verification_session_id";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_in_memory_and_migrate() {
        let db = Database::open_in_memory().expect("should open in-memory db");
        let version = db.get_schema_version().expect("should read version");
        assert_eq!(version, CURRENT_VERSION);
    }

    #[test]
    fn idempotent_migration() {
        let db = Database::open_in_memory().expect("should open");
        // Running migrate again should be a no-op.
        db.migrate().expect("second migrate should succeed");
    }

    #[test]
    fn kv_string_roundtrip() {
        let db = Database::open_in_memory().expect("should open");
        assert_eq!(db.get_kv_string("test_key").unwrap(), None);
        db.set_kv_string("test_key", "test_value").unwrap();
        assert_eq!(db.get_kv_string("test_key").unwrap(), Some("test_value".to_string()));

        // Overwrite
        db.set_kv_string("test_key", "new_value").unwrap();
        assert_eq!(db.get_kv_string("test_key").unwrap(), Some("new_value".to_string()));

        // Delete
        db.delete_kv("test_key").unwrap();
        assert_eq!(db.get_kv_string("test_key").unwrap(), None);
    }

    #[test]
    fn kv_blob_roundtrip() {
        let db = Database::open_in_memory().expect("should open");
        let data = vec![0x01, 0x02, 0x03, 0x04];
        db.set_kv_blob("blob_key", &data).unwrap();
        assert_eq!(db.get_kv_blob("blob_key").unwrap(), Some(data));
    }

    #[test]
    fn transaction_commit() {
        let db = Database::open_in_memory().expect("should open");
        db.transaction(|| {
            db.set_kv_string("tx_key", "tx_value")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(db.get_kv_string("tx_key").unwrap(), Some("tx_value".to_string()));
    }

    #[test]
    fn transaction_rollback() {
        let db = Database::open_in_memory().expect("should open");
        let result: Result<()> = db.transaction(|| {
            db.set_kv_string("rollback_key", "should_not_persist")?;
            Err(StoreError::InvalidData("intentional failure".into()))
        });
        assert!(result.is_err());
        assert_eq!(db.get_kv_string("rollback_key").unwrap(), None);
    }
}
