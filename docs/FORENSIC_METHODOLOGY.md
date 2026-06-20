# ORACLE — Forensic Methodology Document

## Document Control

| Field              | Value                                      |
|--------------------|--------------------------------------------|
| Document ID        | ORACLE-FMD-001                             |
| Version            | 1.0                                        |
| Classification     | PUBLIC — Methodology Disclosure            |
| Author             | ORACLE Forensic Engineering Team           |
| Effective Date     | 2026-06-20                                 |

---

## 1. Introduction

This document describes the scientific methodology employed by the ORACLE
Android Network Forensics Platform for extracting, analyzing, and reporting
network connection evidence from Android devices.

This methodology disclosure is intended for:
- Courts evaluating the admissibility of ORACLE findings
- Defense experts conducting independent review
- Forensic peer reviewers assessing examination quality
- Accreditation bodies evaluating laboratory procedures

---

## 2. Scientific Foundation

### 2.1 Principle of Evidence Integrity

ORACLE operates on the principle that forensic evidence must be:

1. **Acquired without modification** — The platform uses read-only ADB pull
   operations. No data is written to the target device during acquisition.

2. **Verified at every stage** — SHA-256 cryptographic hashes are computed at
   acquisition time and re-verified before every access.

3. **Immutably stored** — Evidence is stored in a content-addressable store where
   modification and deletion are architecturally prevented.

4. **Fully audited** — Every operation is logged in a cryptographically chained
   audit log before execution (write-before-execute semantics).

### 2.2 Evidence Layer Model

ORACLE processes evidence through four distinct layers, each preserving full
provenance back to the original artifact:

```
Layer 0: Raw     — Original bytes exactly as acquired from the device
Layer 1: Parsed  — Structured data extracted by artifact-specific parsers
Layer 2: Normal  — Standardized records with canonical formats
Layer 3: Correl  — Cross-referenced findings with confidence scores
```

Each derived record maintains a `SourceReference` that identifies:
- The exact artifact (by ArtifactId and SHA-256 hash)
- The parser used (by parser_id and version)
- The byte offset and length within the source artifact
- The timestamp of the processing operation

This provenance chain enables any finding to be traced back to the exact bytes
in the original artifact that produced it.

---

## 3. Data Acquisition Methodology

### 3.1 Acquisition Methods

ORACLE supports the following acquisition methods, selected based on the
device's capability profile:

| Method                | Access Level    | Scope                           |
|-----------------------|-----------------|----------------------------------|
| Privileged Logical    | Root (ADB)      | Full /data partition access      |
| ADB Backup            | Shell           | App data per backup allowlist    |
| Unprivileged Logical  | Shell           | World-readable files only        |
| Content Provider      | Shell           | Exposed content providers        |

### 3.2 Zero-Write Guarantee

ORACLE does **not** write any data to the target device. All operations are
read-only ADB shell commands and file pulls. The platform does not:
- Install any agent or application on the device
- Modify any file on the device
- Create any temporary files on the device
- Alter any system settings on the device

### 3.3 Hash Verification

Every acquired artifact receives a SHA-256 hash computed from its raw bytes at
the moment of acquisition. This hash is:
- Stored in the evidence metadata database
- Used as the content-addressable storage key
- Re-verified on every subsequent access
- Included in all reports referencing the artifact

---

## 4. Parsing Methodology

### 4.1 Parser Design Principles

Each parser in ORACLE:
- Is specific to a single artifact format
- Is versioned independently
- Produces structured output validated against a schema
- Records byte offsets for every extracted record
- Never modifies the source artifact
- Degrades gracefully on malformed input

### 4.2 Core Parsers

| Parser                    | Artifact                   | Output Records              |
|---------------------------|----------------------------|-----------------------------|
| WifiConfigStoreParser     | WifiConfigStore.xml        | wifi_configured_network     |
| WpaSupplicantParser       | wpa_supplicant.conf        | wifi_known_network          |
| DhcpLeaseParser           | DHCP lease files           | dhcp_lease                  |
| ConnectivityLogParser     | Connectivity service logs  | connectivity_event          |

### 4.3 OEM Handling

Android OEM manufacturers (Samsung, Xiaomi, etc.) may modify artifact formats
or locations. ORACLE handles this through:

1. **OEM Plugin System** — Manufacturer-specific plugins override default paths
   and parsers when the target device is identified as an OEM-modified device.

2. **Plugin Validation** — Every OEM plugin is validated before use. Invalid
   plugins are rejected with audit logging.

3. **Transparent Override** — When an OEM plugin overrides a default parser, the
   override is documented in the report with the rationale.

---

## 5. Normalization Methodology

### 5.1 SSID Normalization

SSIDs extracted from different sources may have different encodings:
- Quoted strings: `"MyNetwork"` → `MyNetwork`
- Hex-encoded: `4d794e6574776f726b` → `MyNetwork`
- Unicode escapes: `My\x20Network` → `My Network`

The normalizer strips encoding artifacts while preserving the original raw value
for verification.

### 5.2 BSSID Normalization

MAC addresses are normalized to uppercase colon-separated format:
- `aa:bb:cc:dd:ee:ff` → `AA:BB:CC:DD:EE:FF`
- `AA-BB-CC-DD-EE-FF` → `AA:BB:CC:DD:EE:FF`
- `aabbccddeeff` → `AA:BB:CC:DD:EE:FF`

The normalizer also detects:
- Broadcast addresses (`FF:FF:FF:FF:FF:FF`)
- Locally administered addresses (second hex digit is 2, 6, A, or E)
- Invalid formats

### 5.3 Timestamp Normalization

All timestamps are normalized to UTC. The normalizer handles:
- Unix epoch (seconds and milliseconds)
- ISO 8601 format
- Android logcat format
- Boot-relative timestamps (requires device boot time)

**Anomaly Detection:**

| Anomaly              | Condition                                    |
|----------------------|----------------------------------------------|
| Future               | Timestamp is after acquisition time          |
| EpochDefault         | Timestamp is 1970-01-01T00:00:00Z            |
| PreAndroidEra        | Timestamp is before 2008                     |
| OemDefault           | Matches known OEM default dates              |
| ClockSkewDetected    | Device clock differs from acquisition clock  |
| FormatAmbiguous      | Format could not be reliably determined      |

### 5.4 Security Protocol Normalization

Various string representations are mapped to canonical protocol identifiers:

| Raw Strings                          | Canonical Value |
|--------------------------------------|-----------------|
| `WPA-PSK`, `WPA_PSK`                | WPA-PSK         |
| `WPA2-PSK`, `RSN-PSK`, `[WPA2-PSK]` | WPA2-PSK        |
| `SAE`, `WPA3-SAE`                   | WPA3-SAE        |
| `OWE`, `Enhanced Open`              | OWE             |
| `OPEN`, `NONE`, (empty)             | OPEN            |

---

## 6. Correlation Methodology

### 6.1 Network Identity Resolution

Records from different sources referencing the same network are grouped by:
1. Exact SSID match (after normalization)
2. BSSID match (when available)
3. Temporal proximity (records within a configurable window)

### 6.2 Connection Event Reconstruction

WiFi connection events and DHCP lease records are merged to reconstruct
complete connection events:

```
WiFi Connected to "HomeNetwork" at 10:00:00
  + DHCP Lease: 192.168.1.42 at 10:00:02
  = Complete Connection Event:
    Network: HomeNetwork (AA:BB:CC:DD:EE:FF)
    Connected: 10:00:00
    IP Assigned: 192.168.1.42
    Lease Duration: 86400s
```

### 6.3 Role Classification

ORACLE determines whether the device acted as a WiFi **client** or a **hotspot**:

| Evidence                              | Classification    |
|---------------------------------------|-------------------|
| DHCP client lease present             | Client            |
| hostapd configuration for SSID        | Hotspot           |
| tethering/hotspot logs present        | Hotspot           |
| Insufficient evidence                 | Ambiguous         |

### 6.4 Anomaly Detection

The correlation engine detects:
- **Simultaneous connections** — Device connected to multiple networks at the
  same time (may indicate log corruption or clock issues)
- **Timestamp reversals** — Events appearing out of chronological order
- **Data gaps** — Expected continuous data (e.g., battery stats) has unexplained
  gaps that may indicate device manipulation

---

## 7. Confidence Scoring Methodology

### 7.1 Confidence Model v1.0

Each finding receives a confidence score between 0.0 and 1.0, computed as a
weighted sum of the following factors:

| Factor                  | Weight | Description                               |
|-------------------------|--------|-------------------------------------------|
| Source Reliability       | 0.30   | Baseline reliability of the artifact type |
| Corroboration Count      | 0.25   | Number of independent confirming sources  |
| Temporal Consistency     | 0.15   | Whether timestamps are consistent         |
| Acquisition Integrity    | 0.15   | Whether artifact hash verified at read    |
| Parser Validation        | 0.10   | Whether parser output passed validation   |
| Contradiction Penalty    | 0.05   | Deduction for contradicting evidence      |

### 7.2 Score Computation

```
score = Σ(factor_value × weight) - contradiction_penalty

where:
  source_reliability = ArtifactClass.baseline_reliability()
  corroboration      = min(1.0, corroboration_count / 3.0)
  contradiction_penalty = min(1.0, contradiction_count × 0.25)
```

### 7.3 Classification Thresholds

| Classification | Score Range | Meaning                                    |
|---------------|-------------|--------------------------------------------|
| Definitive    | ≥ 0.95      | Multiple independent sources, no conflicts |
| High          | 0.80 – 0.94 | Strong evidence with minor gaps            |
| Moderate      | 0.50 – 0.79 | Moderate evidence, some uncertainty        |
| Low           | < 0.50      | Weak evidence, significant gaps            |
| Contradicted  | N/A         | Active contradictions exist                |

### 7.4 Score Versioning

Confidence scores are versioned and append-only. When a finding is re-scored
(e.g., after new evidence), the previous score is preserved alongside the new
score. This ensures the complete scoring history is available for review.

### 7.5 Examiner Overrides

A qualified examiner may override a computed confidence score with justification.
Overrides:
- Never replace the computed score (both are preserved)
- Require a written justification
- Are audit-logged with the examiner's identity
- Are disclosed in the final report

---

## 8. Known Limitations

### 8.1 Acquisition Limitations
- ORACLE performs logical acquisition only — deleted files are not recoverable
- File-Based Encryption (FBE) prevents access to credential-encrypted storage before first unlock
- SELinux in enforcing mode may block access to certain artifacts even with root
- Some artifacts are volatile and lost on device reboot

### 8.2 Parser Limitations
- Parsers are designed for known Android artifact formats; undocumented OEM modifications may cause partial extraction
- Corrupted or truncated artifacts produce partial results
- Encrypted application databases are not decryptable without the application key

### 8.3 Correlation Limitations
- Network identity resolution relies on SSID/BSSID matching; identical SSIDs at different locations will be grouped together
- Temporal correlation depends on device clock accuracy
- Role classification may be ambiguous when insufficient evidence exists

### 8.4 Scoring Limitations
- Confidence scores are model-based assessments, not probability statements
- The model weights are defined by forensic engineering judgment, not statistical derivation
- Scores should be interpreted in context, not as standalone truth indicators

---

## 9. Validation and Testing

### 9.1 Parser Validation
Every parser is validated against:
- Known-good reference artifacts
- Malformed/corrupted artifacts (graceful degradation)
- Empty artifacts (no crash, appropriate error)
- Cross-version artifacts (multiple Android versions)

### 9.2 Integrity Validation
The evidence store is validated by:
- Storing and retrieving artifacts with hash verification
- Deliberately corrupting stored files and confirming detection
- Attempting modification/deletion operations and confirming rejection

### 9.3 Audit Chain Validation
The audit log is validated by:
- Writing entries and verifying hash chain integrity
- Tampering with entries and confirming chain break detection
- Simulating crashes and confirming recovery of incomplete entries

---

## 10. Revision History

| Version | Date       | Author          | Changes                |
|---------|------------|-----------------|------------------------|
| 1.0     | 2026-06-20 | ORACLE Team     | Initial release        |
