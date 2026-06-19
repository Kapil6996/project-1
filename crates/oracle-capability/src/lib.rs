//! # ORACLE Capability Detection Engine
//!
//! Determines what forensic artifacts are available on a target Android device
//! based on its OS version, root status, OEM, and installed applications.
//!
//! The capability engine is the first subsystem invoked during an investigation.
//! It probes the device to build a capability profile that guides the discovery
//! and parsing pipelines — ensuring ORACLE only attempts extractions that are
//! feasible for the specific device under examination.
//!
//! # Modules
//!
//! - [`adb`] — ADB connection and command transport.
//! - [`detector`] — Core capability detection logic.
//! - [`profiles`] — Device capability profile builder.
//! - [`briefing`] — Investigator briefing and acknowledgment.

pub mod adb;
pub mod briefing;
pub mod detector;
pub mod profiles;
