# ORACLE — Android Network Forensics Platform

A production-grade forensic analysis platform for extracting, correlating, and
reporting network activity evidence from Android devices. Built in Rust for
safety, performance, and auditability.

## Architecture

ORACLE is organized as a Cargo workspace with the following crates:

| Crate | Purpose |
|---|---|
| `oracle-core` | Core types, errors, configuration, and forensic hash utilities |
| `oracle-audit` | Cryptographically chained audit logger and chain-of-custody system |
| `oracle-evidence` | Append-only evidence store with content-addressable storage |
| `oracle-capability` | Device capability detection engine |
| `oracle-discovery` | Artifact discovery engine for locating forensic evidence |
| `oracle-parser` | Parser registry and core parsers for Android artifact formats |
| `oracle-oem` | OEM plugin system for manufacturer-specific artifacts |
| `oracle-normalize` | Evidence normalization layer (timestamps, identifiers, coordinates) |
| `oracle-correlate` | Correlation and timeline engine for cross-referencing evidence |
| `oracle-confidence` | Confidence scoring engine for evidence quality assessment |
| `oracle-report` | Court-ready forensic report generator (PDF & JSON) |
| `oracle-cli` | Command-line interface entry point |

## Key Design Principles

- **Forensic Integrity:** SHA-256 hashes on every artifact, cryptographically
  chained audit log, append-only evidence store.
- **Chain of Custody:** Every file access, configuration change, and analysis
  step is recorded in the audit trail.
- **Court-Ready Output:** Reports include methodology disclosure, evidence
  hashes, and full chain-of-custody documentation.
- **Type Safety:** Rust's type system enforces correct handling of forensic
  data at compile time.

## Quick Start

```bash
# Build the entire workspace
cargo build --workspace

# Run tests
cargo test --workspace

# Create a new investigation
cargo run --bin oracle -- new-investigation \
  --case-name "CASE-2026-0042" \
  --examiner "J. Smith"

# Verify evidence integrity
cargo run --bin oracle -- verify \
  --investigation-id <UUID>
```

## Configuration

Copy `config/default.toml` to customize settings for your environment.
See `oracle-core/src/config.rs` for full documentation of all options.

## License

Proprietary — All rights reserved.
