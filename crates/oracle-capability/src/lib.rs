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
//! # Modules (planned)
//!
//! - `detector` — Core capability detection logic
//! - `profile` — Device capability profile builder
//! - `probes` — Individual device probes (root, OS version, OEM, etc.)
//! - `registry` — Known device capability database

// TODO: Uncomment as modules are implemented
// pub mod detector;
// pub mod profile;
// pub mod probes;
// pub mod registry;
