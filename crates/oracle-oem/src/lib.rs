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
//! # Modules
//!
//! - [`plugin`] — Plugin trait definition and lifecycle management.
//! - [`validation`] — Plugin integrity validation and verification.
//! - [`samsung`] — Samsung OneUI-specific artifact support.

pub mod plugin;
pub mod validation;
pub mod samsung;
