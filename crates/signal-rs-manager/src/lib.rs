//! Signal manager — business logic layer.
//!
//! This crate sits between the CLI/TUI frontends and the service/store layers.
//! It orchestrates all Signal operations:
//!
//! - Account registration, linking, and management
//! - Message sending and receiving
//! - Group operations
//! - Contact management
//! - Profile updates
//! - Pre-key refresh and maintenance jobs
//!
//! The main entry point is the [`SignalManager`] trait, which defines all
//! operations available to the frontend. [`ManagerImpl`] provides the
//! concrete implementation.

pub mod manager;
pub mod context;
pub mod error;
pub mod helpers;
pub mod jobs;
pub mod types;
