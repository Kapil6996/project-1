//! # ORACLE Core
//!
//! Core types, errors, and configuration for the ORACLE Android Network Forensics Platform.
//!
//! This crate defines the foundational data structures shared across all ORACLE subsystems.
//! No subsystem may define its own representation of these core concepts — all must use
//! the canonical types defined here to ensure forensic consistency.

pub mod config;
pub mod error;
pub mod types;
pub mod hash;

pub use config::OracleConfig;
pub use error::{OracleError, OracleResult};
pub use types::*;
pub use hash::ForensicHash;
