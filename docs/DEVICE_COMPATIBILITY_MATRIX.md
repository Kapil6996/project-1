# ORACLE — Device Compatibility Matrix

## Overview

This matrix tracks ORACLE's tested compatibility across Android device models,
Android versions, and OEM skins. Use this to plan validation testing and
document known limitations per device.

---

## Compatibility Status Legend

| Symbol | Meaning                                            |
|--------|----------------------------------------------------|
| ✅     | Fully validated — all artifacts extracted correctly |
| ⚠️     | Partially validated — some artifacts inaccessible  |
| ❌     | Not compatible — critical artifacts missing        |
| 🔲     | Not yet tested                                     |

---

## Test Matrix

### Google Pixel Devices (Stock AOSP)

| Device        | Android | API | Root    | WiFiConfig | WPA Supp | DHCP | ConnLog | BattStats | Hotspot | Status |
|---------------|---------|-----|---------|------------|----------|------|---------|-----------|---------|--------|
| Pixel 8 Pro   | 14      | 34  | None    | 🔲         | 🔲       | 🔲   | 🔲      | 🔲        | 🔲      | 🔲     |
| Pixel 8 Pro   | 14      | 34  | Magisk  | 🔲         | 🔲       | 🔲   | 🔲      | 🔲        | 🔲      | 🔲     |
| Pixel 7       | 14      | 34  | None    | 🔲         | 🔲       | 🔲   | 🔲      | 🔲        | 🔲      | 🔲     |
| Pixel 6a      | 13      | 33  | None    | 🔲         | 🔲       | 🔲   | 🔲      | 🔲        | 🔲      | 🔲     |
| Pixel 5       | 12      | 31  | Magisk  | 🔲         | 🔲       | 🔲   | 🔲      | 🔲        | 🔲      | 🔲     |
| Pixel 3       | 10      | 29  | None    | 🔲         | 🔲       | 🔲   | 🔲      | 🔲        | 🔲      | 🔲     |

### Samsung Galaxy Devices (One UI)

| Device        | Android | API | One UI | Root    | WiFiConfig | WPA Supp | DHCP | ConnLog | BattStats | Hotspot | Status |
|---------------|---------|-----|--------|---------|------------|----------|------|---------|-----------|---------|--------|
| Galaxy S24    | 14      | 34  | 6.1    | None    | 🔲         | 🔲       | 🔲   | 🔲      | 🔲        | 🔲      | 🔲     |
| Galaxy S23    | 14      | 34  | 6.0    | None    | 🔲         | 🔲       | 🔲   | 🔲      | 🔲        | 🔲      | 🔲     |
| Galaxy S22    | 13      | 33  | 5.1    | Magisk  | 🔲         | 🔲       | 🔲   | 🔲      | 🔲        | 🔲      | 🔲     |
| Galaxy A54    | 14      | 34  | 6.0    | None    | 🔲         | 🔲       | 🔲   | 🔲      | 🔲        | 🔲      | 🔲     |
| Galaxy Note20 | 12      | 31  | 4.1    | None    | 🔲         | 🔲       | 🔲   | 🔲      | 🔲        | 🔲      | 🔲     |

### Xiaomi Devices (HyperOS / MIUI)

| Device        | Android | API | Skin    | Root    | WiFiConfig | WPA Supp | DHCP | ConnLog | BattStats | Hotspot | Status |
|---------------|---------|-----|---------|---------|------------|----------|------|---------|-----------|---------|--------|
| Xiaomi 14     | 14      | 34  | HyperOS | None   | 🔲         | 🔲       | 🔲   | 🔲      | 🔲        | 🔲      | 🔲     |
| Redmi Note 13 | 13      | 33  | MIUI 14 | None   | 🔲         | 🔲       | 🔲   | 🔲      | 🔲        | 🔲      | 🔲     |
| Poco F5       | 13      | 33  | MIUI 14 | Magisk | 🔲         | 🔲       | 🔲   | 🔲      | 🔲        | 🔲      | 🔲     |

### OnePlus Devices (OxygenOS)

| Device        | Android | API | Skin      | Root    | WiFiConfig | WPA Supp | DHCP | ConnLog | BattStats | Hotspot | Status |
|---------------|---------|-----|-----------|---------|------------|----------|------|---------|-----------|---------|--------|
| OnePlus 12    | 14      | 34  | OOS 14    | None    | 🔲         | 🔲       | 🔲   | 🔲      | 🔲        | 🔲      | 🔲     |
| OnePlus 11    | 13      | 33  | OOS 13    | Magisk  | 🔲         | 🔲       | 🔲   | 🔲      | 🔲        | 🔲      | 🔲     |

---

## Validation Test Procedure

For each device in the matrix, perform the following:

1. **Factory reset** the device
2. **Configure test networks**:
   - Connect to WiFi network "ORACLE-TEST-OPEN" (Open security)
   - Connect to WiFi network "ORACLE-TEST-WPA2" (WPA2-PSK)
   - Enable mobile hotspot with SSID "ORACLE-HOTSPOT"
3. **Wait 24 hours** for artifact accumulation
4. **Run ORACLE full investigation pipeline**
5. **Record results** in the matrix above:
   - ✅ if the artifact was correctly extracted and parsed
   - ⚠️ if the artifact was partially extracted or had parsing issues
   - ❌ if the artifact could not be accessed or parsed
6. **Document anomalies** in the notes section below

---

## Known Issues

| Device / OEM     | Issue                                          | Workaround          |
|------------------|-------------------------------------------------|---------------------|
| (None documented yet — fill in during validation testing)              |                     |

---

## Notes

- Test results should be recorded by the examiner who performed the validation
- Each test run should reference the ORACLE version and commit hash
- Retest after major ORACLE updates or Android OS upgrades
