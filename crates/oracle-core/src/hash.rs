//! # Forensic Hash Utilities
//!
//! Provides SHA-256 hashing primitives used throughout the ORACLE platform
//! for evidence integrity verification, audit log chaining, and content-addressable storage.
//!
//! SHA-256 is selected as the NIST-approved standard for digital forensics.
//! All hashes in the platform use this module to ensure algorithmic consistency.

use sha2::{Sha256, Digest};
use std::io::Read;
use std::path::Path;
use std::fs::File;
use crate::error::{OracleError, OracleResult};

/// A computed SHA-256 hash value, stored as a 32-byte array.
///
/// This type wraps the raw hash bytes and provides display formatting
/// and comparison operations required for forensic integrity checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ForensicHash {
    /// The raw 32-byte SHA-256 digest.
    bytes: [u8; 32],
}

impl ForensicHash {
    /// The hash representing the genesis state (all zeros).
    /// Used as the "previous hash" for the first entry in any chain.
    pub const GENESIS: ForensicHash = ForensicHash { bytes: [0u8; 32] };

    /// Compute the SHA-256 hash of a byte slice.
    ///
    /// This is the primary entry point for hashing in-memory data
    /// such as audit log entries, parsed records, and small artifacts.
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        ForensicHash { bytes }
    }

    /// Compute the SHA-256 hash of a file on disk using streaming I/O.
    ///
    /// Reads the file in 64KB chunks to avoid loading multi-gigabyte
    /// evidence files entirely into memory. The resulting hash is
    /// mathematically identical to hashing the entire file at once.
    pub fn from_file(path: &Path) -> OracleResult<Self> {
        let mut file = File::open(path).map_err(|e| OracleError::IoError {
            path: path.to_path_buf(),
            source: e,
        })?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 65536]; // 64KB read buffer
        loop {
            let bytes_read = file.read(&mut buffer).map_err(|e| OracleError::IoError {
                path: path.to_path_buf(),
                source: e,
            })?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Ok(ForensicHash { bytes })
    }

    /// Compute the SHA-256 hash of multiple byte slices concatenated.
    ///
    /// Used for chaining operations where the hash incorporates
    /// the previous hash plus the current entry data.
    pub fn from_chain(parts: &[&[u8]]) -> Self {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        ForensicHash { bytes }
    }

    /// Return the hash as a lowercase hex string.
    ///
    /// This is the canonical display format used in audit logs,
    /// evidence reports, and chain of custody documents.
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Parse a hex string back into a ForensicHash.
    ///
    /// Returns an error if the string is not exactly 64 hex characters.
    pub fn from_hex(s: &str) -> OracleResult<Self> {
        let decoded = hex::decode(s).map_err(|e| OracleError::SerializationError {
            reason: format!("Invalid hex hash string: {}", e),
        })?;
        if decoded.len() != 32 {
            return Err(OracleError::SerializationError {
                reason: format!("Hash must be 32 bytes, got {}", decoded.len()),
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&decoded);
        Ok(ForensicHash { bytes })
    }

    /// Return the raw 32-byte hash value.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Check if this hash represents the genesis (all-zero) state.
    pub fn is_genesis(&self) -> bool {
        self.bytes == [0u8; 32]
    }
}

impl std::fmt::Display for ForensicHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_hash_deterministic() {
        let data = b"ORACLE forensic evidence data";
        let hash1 = ForensicHash::from_bytes(data);
        let hash2 = ForensicHash::from_bytes(data);
        assert_eq!(hash1, hash2, "Same input must produce identical hash");
    }

    #[test]
    fn test_hash_different_inputs() {
        let hash1 = ForensicHash::from_bytes(b"data1");
        let hash2 = ForensicHash::from_bytes(b"data2");
        assert_ne!(hash1, hash2, "Different inputs must produce different hashes");
    }

    #[test]
    fn test_hash_hex_roundtrip() {
        let original = ForensicHash::from_bytes(b"roundtrip test");
        let hex_str = original.to_hex();
        let recovered = ForensicHash::from_hex(&hex_str).unwrap();
        assert_eq!(original, recovered, "Hex roundtrip must be lossless");
    }

    #[test]
    fn test_hash_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test_artifact.bin");
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"artifact content for hashing").unwrap();
        file.sync_all().unwrap();
        drop(file);

        let hash = ForensicHash::from_file(&file_path).unwrap();
        let expected = ForensicHash::from_bytes(b"artifact content for hashing");
        assert_eq!(hash, expected, "File hash must match in-memory hash of same content");
    }

    #[test]
    fn test_chain_hash() {
        let prev_hash = ForensicHash::from_bytes(b"previous entry");
        let entry_data = b"current entry data";
        let chain_hash = ForensicHash::from_chain(&[prev_hash.as_bytes(), entry_data]);
        // Verify determinism
        let chain_hash2 = ForensicHash::from_chain(&[prev_hash.as_bytes(), entry_data]);
        assert_eq!(chain_hash, chain_hash2);
    }

    #[test]
    fn test_genesis_hash() {
        assert!(ForensicHash::GENESIS.is_genesis());
        let non_genesis = ForensicHash::from_bytes(b"not genesis");
        assert!(!non_genesis.is_genesis());
    }

    #[test]
    fn test_invalid_hex_rejected() {
        let result = ForensicHash::from_hex("not_valid_hex");
        assert!(result.is_err());

        let result = ForensicHash::from_hex("abcd"); // too short
        assert!(result.is_err());
    }
}
