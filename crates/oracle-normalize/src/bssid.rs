//! # BSSID Normalizer
//!
//! Normalizes raw BSSID (MAC address) strings from Android artifacts into
//! the canonical uppercase, colon-separated format (e.g., `AA:BB:CC:DD:EE:FF`).
//!
//! # Handled Formats
//!
//! - Colon-separated: `aa:bb:cc:dd:ee:ff`
//! - Hyphen-separated: `aa-bb-cc-dd-ee-ff`
//! - Dot-separated (Cisco): `aabb.ccdd.eeff`
//! - Unseparated: `aabbccddeeff`
//!
//! # Detections
//!
//! - Broadcast address (`FF:FF:FF:FF:FF:FF`)
//! - Multicast bit set (bit 0 of first octet)
//! - Locally administered bit (bit 1 of first octet)

use serde::{Deserialize, Serialize};

/// A normalized BSSID (MAC address) with validation metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedBssid {
    /// The raw BSSID exactly as extracted from the artifact.
    pub raw: String,
    /// The normalized BSSID in uppercase colon-separated format.
    /// Empty string if the raw value could not be parsed.
    pub normalized: String,
    /// Whether the raw value was successfully parsed as a valid MAC address.
    pub is_valid: bool,
    /// Whether this is the broadcast address (`FF:FF:FF:FF:FF:FF`).
    pub is_broadcast: bool,
    /// Whether the locally administered bit is set (bit 1 of first octet).
    ///
    /// Locally administered addresses are used by Android for MAC randomization
    /// (Android 10+) and are forensically significant because they indicate
    /// the MAC was not the device's factory-assigned address.
    pub is_locally_administered: bool,
}

/// Normalizes raw BSSID (MAC address) strings into canonical form.
pub struct BssidNormalizer;

impl BssidNormalizer {
    /// Normalize a raw BSSID string into canonical uppercase colon-separated format.
    ///
    /// # Processing Order
    ///
    /// 1. Strip whitespace.
    /// 2. Remove all separators (`:`, `-`, `.`) and validate hex content.
    /// 3. Verify exactly 12 hex digits remain.
    /// 4. Format as `XX:XX:XX:XX:XX:XX`.
    /// 5. Detect broadcast, multicast, and locally administered flags.
    ///
    /// # Examples
    ///
    /// ```
    /// use oracle_normalize::bssid::BssidNormalizer;
    ///
    /// let result = BssidNormalizer::normalize("aa:bb:cc:dd:ee:ff");
    /// assert_eq!(result.normalized, "AA:BB:CC:DD:EE:FF");
    /// assert!(result.is_valid);
    /// ```
    pub fn normalize(raw_bssid: &str) -> NormalizedBssid {
        let raw = raw_bssid.to_string();
        let trimmed = raw_bssid.trim();

        // Remove all common separators and collect hex digits
        let hex_only: String = trimmed
            .chars()
            .filter(|c| *c != ':' && *c != '-' && *c != '.')
            .collect();

        // Validate: must be exactly 12 hex characters
        if hex_only.len() != 12 || !hex_only.chars().all(|c| c.is_ascii_hexdigit()) {
            return NormalizedBssid {
                raw,
                normalized: String::new(),
                is_valid: false,
                is_broadcast: false,
                is_locally_administered: false,
            };
        }

        // Format as uppercase colon-separated
        let upper = hex_only.to_ascii_uppercase();
        let normalized = format!(
            "{}:{}:{}:{}:{}:{}",
            &upper[0..2],
            &upper[2..4],
            &upper[4..6],
            &upper[6..8],
            &upper[8..10],
            &upper[10..12],
        );

        // Parse first octet for flag detection
        // Safety: we already validated these are hex digits
        let first_octet = u8::from_str_radix(&upper[0..2], 16).unwrap_or(0);

        let is_broadcast = normalized == "FF:FF:FF:FF:FF:FF";

        // Bit 0 of first octet: multicast flag
        // Bit 1 of first octet: locally administered flag
        let is_locally_administered = (first_octet & 0x02) != 0;

        NormalizedBssid {
            raw,
            normalized,
            is_valid: true,
            is_broadcast,
            is_locally_administered,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_colon_separated_lowercase() {
        let result = BssidNormalizer::normalize("aa:bb:cc:dd:ee:ff");
        assert_eq!(result.normalized, "AA:BB:CC:DD:EE:FF");
        assert!(result.is_valid);
        assert!(!result.is_broadcast);
    }

    #[test]
    fn test_colon_separated_uppercase() {
        let result = BssidNormalizer::normalize("AA:BB:CC:DD:EE:FF");
        assert_eq!(result.normalized, "AA:BB:CC:DD:EE:FF");
        assert!(result.is_valid);
    }

    #[test]
    fn test_hyphen_separated() {
        let result = BssidNormalizer::normalize("aa-bb-cc-dd-ee-ff");
        assert_eq!(result.normalized, "AA:BB:CC:DD:EE:FF");
        assert!(result.is_valid);
    }

    #[test]
    fn test_dot_separated_cisco() {
        let result = BssidNormalizer::normalize("aabb.ccdd.eeff");
        assert_eq!(result.normalized, "AA:BB:CC:DD:EE:FF");
        assert!(result.is_valid);
    }

    #[test]
    fn test_unseparated() {
        let result = BssidNormalizer::normalize("aabbccddeeff");
        assert_eq!(result.normalized, "AA:BB:CC:DD:EE:FF");
        assert!(result.is_valid);
    }

    #[test]
    fn test_broadcast_address() {
        let result = BssidNormalizer::normalize("ff:ff:ff:ff:ff:ff");
        assert_eq!(result.normalized, "FF:FF:FF:FF:FF:FF");
        assert!(result.is_valid);
        assert!(result.is_broadcast);
    }

    #[test]
    fn test_locally_administered() {
        // 02:xx:xx:xx:xx:xx has locally-administered bit set
        let result = BssidNormalizer::normalize("02:00:00:00:00:00");
        assert!(result.is_valid);
        assert!(result.is_locally_administered);
    }

    #[test]
    fn test_globally_unique() {
        // 00:xx:xx:xx:xx:xx — globally unique (OUI assigned)
        let result = BssidNormalizer::normalize("00:1a:2b:3c:4d:5e");
        assert!(result.is_valid);
        assert!(!result.is_locally_administered);
    }

    #[test]
    fn test_android_randomized_mac() {
        // Android randomized MACs have the locally administered bit set
        // Example: DA:A1:19:xx:xx:xx → first octet 0xDA = 1101 1010, bit 1 = 1
        let result = BssidNormalizer::normalize("da:a1:19:ab:cd:ef");
        assert!(result.is_valid);
        assert!(result.is_locally_administered);
    }

    #[test]
    fn test_invalid_too_short() {
        let result = BssidNormalizer::normalize("aa:bb:cc");
        assert!(!result.is_valid);
        assert!(result.normalized.is_empty());
    }

    #[test]
    fn test_invalid_too_long() {
        let result = BssidNormalizer::normalize("aa:bb:cc:dd:ee:ff:00");
        assert!(!result.is_valid);
    }

    #[test]
    fn test_invalid_non_hex() {
        let result = BssidNormalizer::normalize("gg:hh:ii:jj:kk:ll");
        assert!(!result.is_valid);
    }

    #[test]
    fn test_empty_string() {
        let result = BssidNormalizer::normalize("");
        assert!(!result.is_valid);
    }

    #[test]
    fn test_whitespace_trimming() {
        let result = BssidNormalizer::normalize("  aa:bb:cc:dd:ee:ff  ");
        assert_eq!(result.normalized, "AA:BB:CC:DD:EE:FF");
        assert!(result.is_valid);
    }

    #[test]
    fn test_raw_preserved() {
        let raw = "aa-bb-cc-dd-ee-ff";
        let result = BssidNormalizer::normalize(raw);
        assert_eq!(result.raw, raw);
    }

    #[test]
    fn test_mixed_case() {
        let result = BssidNormalizer::normalize("aA:Bb:cC:Dd:eE:fF");
        assert_eq!(result.normalized, "AA:BB:CC:DD:EE:FF");
        assert!(result.is_valid);
    }
}
