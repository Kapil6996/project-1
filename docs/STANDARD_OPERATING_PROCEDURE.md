# ORACLE — Standard Operating Procedure (SOP)

## Document Control

| Field              | Value                                      |
|--------------------|--------------------------------------------|
| Document ID        | ORACLE-SOP-001                             |
| Version            | 1.0                                        |
| Classification     | RESTRICTED — Law Enforcement Use Only      |
| Author             | ORACLE Forensic Engineering Team           |
| Effective Date     | 2026-06-20                                 |
| Review Cycle       | Annual or upon significant platform update |

---

## 1. Purpose

This Standard Operating Procedure defines the step-by-step process for conducting
a forensic network artifact investigation on an Android device using the ORACLE
platform. Following this SOP ensures forensic soundness, admissibility, and
repeatability of the examination.

---

## 2. Scope

This SOP covers:
- Pre-examination preparation
- Device connection and capability assessment
- Artifact acquisition
- Parsing, normalization, and correlation
- Report generation
- Evidence preservation

This SOP does **not** cover:
- Physical device seizure procedures (governed by agency SOPs)
- Warrant/authorization acquisition (governed by legal counsel)
- Device imaging (ORACLE performs logical acquisition only)

---

## 3. Prerequisites

### 3.1 Personnel Requirements
- Examiner must hold a recognized digital forensic certification (e.g., CFCE, EnCE, GCFE) or equivalent agency training.
- Examiner must be authorized to conduct the examination under the applicable legal authority.
- Examiner must have completed ORACLE platform training.

### 3.2 Equipment Requirements
- Forensic workstation with ORACLE installed (see Setup Guide)
- USB cable (OEM-certified, data-capable)
- Write-blocker for USB (recommended but not required for logical acquisition)
- Case file documentation (paper or digital)

### 3.3 Legal Requirements
- Valid search warrant, consent form, or other legal authority authorizing examination
- Authority must specifically cover network/WiFi data extraction
- Document the legal authority reference number in the case file

---

## 4. Procedure

### Step 1: Pre-Examination Documentation

1. **Create case documentation** recording:
   - Case number
   - Legal authority reference
   - Examiner name, badge/ID number, organization
   - Date and time of examination start
   - Device description (make, model, condition, identifiers)

2. **Photograph the device** showing:
   - Overall condition
   - Serial number / IMEI label
   - Screen state (locked/unlocked)
   - USB port condition

### Step 2: Initialize Investigation

```bash
oracle new-investigation \
  --case-number "CASE-2026-0042" \
  --examiner-name "Det. Jane Smith" \
  --examiner-badge "JS-4872" \
  --examiner-org "Metro PD Digital Forensics Unit"
```

Record the generated `Investigation ID` in the case file.

### Step 3: Connect Device

1. Connect the Android device to the forensic workstation via USB.
2. If the device displays an "Allow USB debugging?" prompt, authorize it.
3. Verify connection:

```bash
oracle connect-device --serial <device_serial>
```

### Step 4: Capability Detection

```bash
oracle detect-capabilities --serial <device_serial>
```

**CRITICAL**: Review the Investigator Briefing carefully.

The briefing will report:
- Device identity (make, model, Android version, build fingerprint)
- Root access availability and method
- SELinux enforcement mode
- Encryption state (BFU/AFU)
- Accessible artifact classes and their acquisition methods
- **Inaccessible artifact classes and the reason why**

**Examiner must acknowledge** the capability profile before proceeding.
Document any inaccessible artifacts in the case file — this is critical for
establishing the completeness (or known incompleteness) of the examination.

### Step 5: Artifact Discovery and Manifest Review

```bash
oracle discover-artifacts --serial <device_serial>
```

Review the artifact manifest. The manifest lists every artifact that will be
acquired, including:
- File path on device
- Artifact classification
- Estimated file size
- Acquisition method

**Document the manifest in the case file** before authorizing acquisition.

### Step 6: Artifact Acquisition

```bash
oracle acquire --serial <device_serial>
```

This step:
- Pulls each artifact from the device via ADB
- Computes SHA-256 hash of each artifact at acquisition time
- Stores artifacts in the content-addressable evidence store
- Logs every operation in the cryptographic audit chain

**Do NOT disconnect the device during acquisition.**

### Step 7: Parsing

```bash
oracle parse --investigation-id <investigation_id>
```

The platform applies the appropriate parser to each artifact:
- WifiConfigStore.xml → Configured network extraction
- wpa_supplicant.conf → Known network extraction
- DHCP lease files → IP assignment extraction
- Connectivity logs → Network event extraction

### Step 8: Normalization

```bash
oracle normalize --investigation-id <investigation_id>
```

This step standardizes all extracted data:
- SSIDs are decoded and cleaned
- BSSIDs are normalized to uppercase colon-separated format
- Timestamps are converted to UTC with anomaly detection
- Security protocols are mapped to canonical names
- Conflicts between sources are detected and flagged

### Step 9: Correlation

```bash
oracle correlate --investigation-id <investigation_id>
```

The correlation engine:
- Resolves network identities (grouping by SSID/BSSID)
- Reconstructs connection events (merging WiFi + DHCP data)
- Classifies device role (client vs. hotspot)
- Builds a chronological timeline
- Detects anomalies (simultaneous connections, timestamp reversals)

### Step 10: Confidence Scoring

```bash
oracle score --investigation-id <investigation_id>
```

Each finding receives a confidence score based on:
- Source reliability (artifact class baseline)
- Corroboration count (how many independent sources confirm)
- Temporal consistency
- Acquisition integrity
- Parser validation status
- Contradiction penalties

Scores are classified as: **Definitive** (≥0.95), **High** (0.80–0.94),
**Moderate** (0.50–0.79), or **Low** (<0.50).

### Step 11: Report Generation

```bash
oracle generate-report --investigation-id <investigation_id>
```

Generated reports:
- **Executive Summary** — Non-technical overview for legal proceedings
- **Technical Findings** — Full technical detail for peer review
- **Chain of Custody Document** — Complete evidence handling timeline
- **Evidence Appendix** — All artifacts with hashes

### Step 12: Verification and Closure

```bash
oracle verify-audit --investigation-id <investigation_id>
oracle verify-evidence --investigation-id <investigation_id>
```

1. Verify the audit chain integrity (must show INTACT)
2. Verify all evidence store artifacts (must show no hash mismatches)
3. Export the final audit log
4. Document the verification results in the case file
5. Disconnect and secure the device per agency policy

---

## 5. Quality Control

- All examinations must be peer-reviewed by a second qualified examiner
- The peer reviewer must independently run `oracle verify-audit` and `oracle verify-evidence`
- Any discrepancies between the original and review verification must be documented and resolved

---

## 6. Evidence Handling

- The ORACLE investigation directory contains all evidence and must be treated as the digital evidence package
- Back up the investigation directory to agency-approved secure storage
- The investigation directory must be preserved for the case retention period
- Never modify files within the investigation directory after examination completion

---

## 7. Limitations Disclosure

Every ORACLE report must include a limitations disclosure stating:

1. ORACLE performs **logical acquisition only** — it does not image the full device
2. Network artifacts may have been deleted, overwritten, or modified by the device owner or OS before acquisition
3. Timestamp accuracy depends on the device clock, which may have been manipulated
4. Artifacts from before the last factory reset are generally not recoverable
5. File-Based Encryption (FBE) may prevent access to credential-encrypted storage before first unlock
6. OEM modifications may alter artifact formats or locations in undocumented ways
7. Confidence scores are model-based assessments, not certainties

---

## 8. Revision History

| Version | Date       | Author          | Changes                |
|---------|------------|-----------------|------------------------|
| 1.0     | 2026-06-20 | ORACLE Team     | Initial release        |
