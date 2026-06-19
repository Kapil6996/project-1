//! # ORACLE Correlation & Timeline Engine
//!
//! Cross-references normalized forensic artifacts to build unified timelines
//! and establish connections between evidence from disparate sources.
//!
//! The correlation engine is where forensic analysis truly happens. It takes
//! normalized artifacts and identifies relationships — a Wi-Fi connection
//! event corroborated by a logcat entry and a location record, all timestamped
//! within the same window, produces a high-confidence forensic finding.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
//! │   Identity   │──▶──│    Event         │──▶──│   Timeline   │
//! │   Resolver   │     │  Reconstructor   │     │   Builder    │
//! └──────────────┘     └─────────────────┘     └──────┬───────┘
//!                                                      │
//!        ┌─────────────────────────────┬───────────────┘
//!        ▼                             ▼
//! ┌──────────────┐              ┌─────────────┐
//! │    Role      │              │   Anomaly   │
//! │  Classifier  │              │  Detector   │
//! └──────────────┘              └─────────────┘
//! ```
//!
//! # Modules
//!
//! - [`types`] — Shared types (resolved network identities, claims).
//! - [`identity`] — Network Identity Resolver (de-duplication & merging).
//! - [`events`] — Connection Event Reconstructor.
//! - [`roles`] — Hotspot vs Client Distinguisher.
//! - [`timeline`] — Unified Timeline Builder.
//! - [`anomaly`] — Anomaly Detector & Contradiction Handler.

pub mod types;
pub mod identity;
pub mod events;
pub mod roles;
pub mod timeline;
pub mod anomaly;

// Re-export primary types for ergonomic downstream usage.
pub use types::{NetworkClaim, NetworkIdentityId, ResolvedNetwork};
pub use identity::NetworkIdentityResolver;
pub use events::{
    ConnectionEvent, ConnectionEventId, ConnectionEventType, EventEvidence, EventReconstructor,
};
pub use roles::{RoleClassification, RoleClassifier, RoleSignal};
pub use timeline::{
    SessionId, Timeline, TimelineBuilder, TimelineGap, TimelineOverlap, TimelineSession,
};
pub use anomaly::{Anomaly, AnomalyCategory, AnomalyDetector, AnomalyId, AnomalyReport, AnomalySeverity};
