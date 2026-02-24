//! Store implementations.
//!
//! Protocol store traits from `signal-rs-protocol` are implemented for
//! [`Database`](crate::Database). Application-level stores (recipient, group,
//! message) provide additional CRUD operations.

pub mod identity_store;
pub mod pre_key_store;
pub mod signed_pre_key_store;
pub mod kyber_pre_key_store;
pub mod session_store;
pub mod sender_key_store;
pub mod recipient_store;
pub mod group_store;
pub mod message_store;
