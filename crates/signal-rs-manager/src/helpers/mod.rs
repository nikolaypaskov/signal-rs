//! Helper modules — each encapsulates a domain of manager functionality.
//!
//! Helpers are stateless or lazily-initialized objects that implement the
//! actual business logic. They are accessed through the [`Context`] struct.

pub mod send;
pub mod receive;
pub mod group;
pub mod contact;
pub mod profile;
pub mod pre_key;
pub mod identity;
pub mod attachment;
pub mod sticker;
pub mod storage;
pub mod sync;
pub mod recipient;
pub mod pin;
pub mod unidentified_access;
