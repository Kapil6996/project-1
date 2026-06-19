//! # Audit Log Entry
//!
//! Defines the canonical [`AuditEntry`] data structure that forms each link in
//! the cryptographic audit chain. Every auditable operation in the ORACLE
//! platform produces exactly one entry.
//!
//! ## Hash Chain Integrity
//!
//! Each entry's `entry_hash` is computed as:
//!
//! ```text
//! SHA-256(previous_hash_bytes || canonical_json(entry_content))
//! ```
//!
//! where `entry_content` is a deterministic JSON serialisation of every field
//! *except* `entry_hash` itself (to avoid circular dependency).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use oracle_core::error::{OracleError, OracleResult};
use oracle_core::types::{AuditOperationType, AuditResult, InvestigationId};
use oracle_core::ForensicHash;

// ──────────────────────────────────────────────────────────────────────────────
// Audit Entry
// ──────────────────────────────────────────────────────────────────────────────

/// A single, immutable entry in the ORACLE audit log.
///
/// Once written, an `AuditEntry` is never modified. The write-before-execute
/// protocol means that every operation first writes a `Pending` entry (the
/// *intent*) and later appends a *result* entry referencing it. If the system
/// crashes between the two writes, startup recovery detects the orphaned
/// intent and records a [`AuditOperationType::SystemCrashRecovery`] entry.
///
/// The `entry_hash` field cryptographically chains each entry to its
/// predecessor, making any post-hoc insertion, deletion, or modification
/// detectable by the [`crate::verifier::AuditLogVerifier`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique identifier for this entry (UUIDv4).
    pub entry_id: Uuid,

    /// Monotonically increasing index within the log (0-based).
    pub entry_index: u64,

    /// UTC timestamp at which the entry was created.
    pub timestamp: DateTime<Utc>,

    /// The investigation this entry belongs to, if any.
    /// System-level events (startup, shutdown) have `None`.
    pub investigation_id: Option<InvestigationId>,

    /// The type of operation being recorded.
    pub operation: AuditOperationType,

    /// The human identity performing the operation, or `"SYSTEM"` for
    /// automated / internal operations.
    pub actor: String,

    /// A human-readable description of what was operated upon.
    pub subject: String,

    /// Structured metadata specific to the operation.
    pub details: serde_json::Value,

    /// The outcome of the operation.
    pub result: AuditResult,

    /// Hex-encoded SHA-256 hash of the *previous* entry in the chain.
    /// The genesis entry uses an all-zeros hash.
    pub previous_hash: String,

    /// Hex-encoded SHA-256 hash of *this* entry, computed over
    /// `previous_hash || canonical_content`.
    pub entry_hash: String,
}

/// An intermediate struct that holds exactly the fields fed into the hash
/// computation. `entry_hash` is deliberately excluded.
#[derive(Serialize)]
struct HashableContent<'a> {
    entry_id: &'a Uuid,
    entry_index: u64,
    timestamp: &'a DateTime<Utc>,
    investigation_id: &'a Option<InvestigationId>,
    operation: &'a AuditOperationType,
    actor: &'a str,
    subject: &'a str,
    details: &'a serde_json::Value,
    result: &'a AuditResult,
    previous_hash: &'a str,
}

impl AuditEntry {
    /// Compute the SHA-256 hash for this entry.
    ///
    /// The hash is `SHA-256(previous_hash_bytes || canonical_json(content))`
    /// where `content` is every field *except* `entry_hash`.
    ///
    /// # Errors
    ///
    /// Returns [`OracleError::SerializationError`] if the canonical JSON
    /// representation cannot be produced (should never happen for well-formed
    /// entries).
    pub fn compute_hash(&self) -> OracleResult<String> {
        let content = HashableContent {
            entry_id: &self.entry_id,
            entry_index: self.entry_index,
            timestamp: &self.timestamp,
            investigation_id: &self.investigation_id,
            operation: &self.operation,
            actor: &self.actor,
            subject: &self.subject,
            details: &self.details,
            result: &self.result,
            previous_hash: &self.previous_hash,
        };

        let content_bytes = serde_json::to_vec(&content)?;

        let prev_hash_obj = ForensicHash::from_hex(&self.previous_hash)?;
        let hash = ForensicHash::from_chain(&[prev_hash_obj.as_bytes(), &content_bytes]);

        Ok(hash.to_hex())
    }

    /// Verify that the stored `entry_hash` matches the recomputed hash.
    ///
    /// Returns `Ok(true)` if the hashes match, `Ok(false)` if they diverge.
    /// Returns `Err` only if serialisation fails (programming error).
    pub fn verify_hash(&self) -> OracleResult<bool> {
        let recomputed = self.compute_hash()?;
        Ok(recomputed == self.entry_hash)
    }

    /// Construct a new `AuditEntry` with a freshly computed `entry_hash`.
    ///
    /// This is the **only** correct way to create an entry; callers must
    /// never set `entry_hash` manually.
    ///
    /// # Arguments
    ///
    /// * `entry_index` — Monotonically increasing index.
    /// * `investigation_id` — The parent investigation, or `None`.
    /// * `operation` — The audit operation type.
    /// * `actor` — Examiner name or `"SYSTEM"`.
    /// * `subject` — What was operated on.
    /// * `details` — Structured metadata.
    /// * `result` — Operation outcome.
    /// * `previous_hash` — Hex hash of the previous entry (all zeros for genesis).
    ///
    /// # Errors
    ///
    /// Returns an error if hash computation fails.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        entry_index: u64,
        investigation_id: Option<InvestigationId>,
        operation: AuditOperationType,
        actor: String,
        subject: String,
        details: serde_json::Value,
        result: AuditResult,
        previous_hash: String,
    ) -> OracleResult<Self> {
        let mut entry = AuditEntry {
            entry_id: Uuid::new_v4(),
            entry_index,
            timestamp: Utc::now(),
            investigation_id,
            operation,
            actor,
            subject,
            details,
            result,
            previous_hash,
            // Placeholder — will be overwritten immediately below.
            entry_hash: String::new(),
        };

        entry.entry_hash = entry.compute_hash()?;
        Ok(entry)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_core::ForensicHash;
    use serde_json::json;

    /// Helper: build a genesis entry with sensible defaults.
    fn make_genesis() -> AuditEntry {
        AuditEntry::new(
            0,
            None,
            AuditOperationType::SystemStartup,
            "SYSTEM".to_string(),
            "ORACLE platform".to_string(),
            json!({"version": "1.0.0"}),
            AuditResult::Success,
            ForensicHash::GENESIS.to_hex(),
        )
        .unwrap()
    }

    #[test]
    fn test_genesis_previous_hash_is_all_zeros() {
        let entry = make_genesis();
        assert_eq!(
            entry.previous_hash,
            ForensicHash::GENESIS.to_hex(),
            "Genesis entry must have all-zeros previous_hash"
        );
    }

    #[test]
    fn test_entry_hash_is_deterministic() {
        // Two entries with identical content (but different entry_id) produce
        // *different* hashes because entry_id is part of the hashable content.
        let e1 = make_genesis();
        let e2 = make_genesis();
        assert_ne!(e1.entry_hash, e2.entry_hash);
    }

    #[test]
    fn test_verify_hash_succeeds_for_valid_entry() {
        let entry = make_genesis();
        assert!(
            entry.verify_hash().unwrap(),
            "A freshly created entry must verify successfully"
        );
    }

    #[test]
    fn test_verify_hash_fails_after_tampering() {
        let mut entry = make_genesis();
        entry.actor = "TAMPERED_ACTOR".to_string();
        assert!(
            !entry.verify_hash().unwrap(),
            "Tampering with a field must cause verification failure"
        );
    }

    #[test]
    fn test_entry_serialization_roundtrip() {
        let entry = make_genesis();
        let json_bytes = serde_json::to_vec(&entry).unwrap();
        let recovered: AuditEntry = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(entry.entry_hash, recovered.entry_hash);
        assert!(recovered.verify_hash().unwrap());
    }

    #[test]
    fn test_entry_chain_of_two() {
        let first = make_genesis();
        let second = AuditEntry::new(
            1,
            None,
            AuditOperationType::InvestigationCreated,
            "Examiner A".to_string(),
            "Case #42".to_string(),
            json!({"case_number": 42}),
            AuditResult::Success,
            first.entry_hash.clone(),
        )
        .unwrap();

        assert_eq!(second.previous_hash, first.entry_hash);
        assert!(second.verify_hash().unwrap());
    }

    #[test]
    fn test_compute_hash_matches_stored_hash() {
        let entry = make_genesis();
        let recomputed = entry.compute_hash().unwrap();
        assert_eq!(recomputed, entry.entry_hash);
    }
}
