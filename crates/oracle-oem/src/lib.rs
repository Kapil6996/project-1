//! # ORACLE OEM Plugin System
//!
//! Extensible plugin architecture for manufacturer-specific forensic artifact
//! support in the ORACLE platform.
//!
//! Android OEMs (Samsung, Xiaomi, OnePlus, etc.) store proprietary artifacts in
//! non-standard locations and formats. The OEM plugin system allows ORACLE to
//! support these manufacturer-specific artifacts through a unified plugin API
//! without coupling the core platform to any single OEM's implementation.
//!
//! # Modules (planned)
//!
//! - `plugin` — Plugin trait definition and lifecycle management
//! - `loader` — Dynamic plugin discovery and loading
//! - `registry` — OEM plugin registry and dispatch
//! - `samsung` — Samsung-specific artifact support
//! - `xiaomi` — Xiaomi-specific artifact support

// TODO: Uncomment as modules are implemented
// pub mod plugin;
// pub mod loader;
// pub mod registry;
