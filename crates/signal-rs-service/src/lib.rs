//! Signal service communication layer.
//!
//! This crate handles all communication with Signal servers, including:
//!
//! - HTTP REST API calls (registration, keys, messages, profiles, etc.)
//! - WebSocket connections (message receiving, keep-alive)
//! - Message encryption/decryption pipeline
//! - Attachment upload/download
//! - Group operations (Groups v2)
//! - Contact discovery (CDSI)
//!
//! Network-facing methods are implemented using HTTP REST and WebSocket
//! connections to the Signal servers.

pub mod config;
pub mod error;
pub mod credentials;
pub mod net;
pub mod api;
pub mod pipe;
pub mod content;
pub mod groups;
pub mod attachment;
pub mod profile;
