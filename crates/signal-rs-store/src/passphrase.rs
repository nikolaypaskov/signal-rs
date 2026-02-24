//! Passphrase resolution helpers for SQLCipher encrypted databases.

use std::io;

const ENV_VAR: &str = "SIGNAL_RS_DB_PASSPHRASE";

/// Resolve a database passphrase from (in order):
/// 1. CLI argument value
/// 2. Environment variable `SIGNAL_RS_DB_PASSPHRASE`
/// 3. Interactive terminal prompt
pub fn resolve_passphrase(cli_value: Option<&str>) -> io::Result<String> {
    if let Some(val) = cli_value {
        return Ok(val.to_string());
    }

    if let Ok(val) = std::env::var(ENV_VAR)
        && !val.is_empty()
    {
        return Ok(val);
    }

    rpassword::read_password_from_tty(Some("Database passphrase: "))
}

/// Prompt for a new passphrase with confirmation (for register/link).
///
/// Returns an error if the two entries do not match.
pub fn prompt_new_passphrase() -> io::Result<String> {
    let p1 = rpassword::read_password_from_tty(Some("New database passphrase: "))?;
    let p2 = rpassword::read_password_from_tty(Some("Confirm database passphrase: "))?;

    if p1 != p2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "passphrases do not match",
        ));
    }

    if p1.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "passphrase must not be empty",
        ));
    }

    Ok(p1)
}
