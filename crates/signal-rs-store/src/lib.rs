//! SQLite persistence for the Signal protocol.
//!
//! This crate provides a SQLite-backed storage layer compatible with
//! signal-cli's AccountDatabase schema (version 28). It implements the
//! protocol store traits defined in `signal-rs-protocol` and adds
//! application-level stores for recipients, groups, messages, and threads.

pub mod database;
pub mod error;
pub mod migrations;
pub mod models;
pub mod passphrase;
pub mod stores;

pub use database::Database;
pub use error::StoreError;
