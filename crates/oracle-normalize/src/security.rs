//! # Security Protocol Normalizer
//!
//! Maps diverse string representations of Wi-Fi security protocols found
//! across Android artifact sources into the canonical [`SecurityProtocol`]
//! enum defined in `oracle-core`.
//!
//! # Handled Representations
//!
//! | Source Format                  | Maps To              |
//! |-------------------------------|----------------------|
//! | `NONE`, `Open`, `[ESS]`       | `Open`               |
//! | `WEP`, `[WEP]`                | `Wep`                |
//! | `WPA-PSK`, `[WPA-PSK-TKIP]`   | `WpaPsk`             |
//! | `WPA2-PSK`, `[WPA2-PSK-CCMP]` | `Wpa2Psk`            |
//! | `SAE`, `WPA3-SAE`, `[SAE]`    | `Wpa3Sae`            |
//! | `OWE`, `[OWE]`                | `Owe`                |
//! | `EAP`, `802.1X`, `PEAP`       | `EapPeap`            |
//! | `EAP-TLS`                     | `EapTls`             |
//! | Android `key_mgmt` integers   | Corresponding variant|

use oracle_core::types::SecurityProtocol;

/// Normalizes raw security protocol strings into canonical [`SecurityProtocol`] values.
pub struct SecurityNormalizer;

impl SecurityNormalizer {
    /// Normalize a raw security protocol string.
    ///
    /// The input is cleaned (trimmed, uppercased, brackets stripped) before
    /// pattern matching against known security protocol identifiers.
    ///
    /// # Examples
    ///
    /// ```
    /// use oracle_normalize::security::SecurityNormalizer;
    /// use oracle_core::types::SecurityProtocol;
    ///
    /// assert_eq!(SecurityNormalizer::normalize("[WPA2-PSK-CCMP]"), SecurityProtocol::Wpa2Psk);
    /// assert_eq!(SecurityNormalizer::normalize("SAE"), SecurityProtocol::Wpa3Sae);
    /// ```
    pub fn normalize(raw: &str) -> SecurityProtocol {
        let cleaned = Self::clean(raw);

        // Try exact match first, then substring-based matching
        if let Some(proto) = Self::match_exact(&cleaned) {
            return proto;
        }

        if let Some(proto) = Self::match_substring(&cleaned) {
            return proto;
        }

        // Try Android integer key_mgmt values
        if let Some(proto) = Self::match_android_key_mgmt(&cleaned) {
            return proto;
        }

        SecurityProtocol::Unknown
    }

    /// Clean and normalize the raw input string for matching.
    fn clean(raw: &str) -> String {
        let trimmed = raw.trim();

        // Strip surrounding brackets (Android scan result format)
        let stripped = if trimmed.starts_with('[') && trimmed.ends_with(']') {
            &trimmed[1..trimmed.len() - 1]
        } else {
            trimmed
        };

        stripped.to_ascii_uppercase()
    }

    /// Attempt exact match against known protocol strings.
    fn match_exact(cleaned: &str) -> Option<SecurityProtocol> {
        match cleaned {
            // Open / None
            "NONE" | "OPEN" | "ESS" | "" => Some(SecurityProtocol::Open),

            // WEP
            "WEP" => Some(SecurityProtocol::Wep),

            // WPA-PSK
            "WPA-PSK" | "WPA_PSK" | "WPAPSK" | "WPA-PSK-TKIP" | "WPA-PSK-CCMP"
            | "WPA-PSK-TKIP+CCMP" => Some(SecurityProtocol::WpaPsk),

            // WPA2-PSK
            "WPA2-PSK" | "WPA2_PSK" | "WPA2PSK" | "WPA2-PSK-CCMP" | "WPA2-PSK-TKIP"
            | "WPA2-PSK-CCMP+TKIP" | "RSN-PSK" | "RSN-PSK-CCMP" | "RSN-PSK-TKIP"
            | "WPA/WPA2-PSK" => Some(SecurityProtocol::Wpa2Psk),

            // WPA3-SAE
            "SAE" | "WPA3-SAE" | "WPA3_SAE" | "WPA3SAE" | "RSN-SAE" | "SAE-CCMP"
            | "WPA3-SAE-CCMP" => Some(SecurityProtocol::Wpa3Sae),

            // OWE (Opportunistic Wireless Encryption)
            "OWE" | "OWE-CCMP" | "RSN-OWE" => Some(SecurityProtocol::Owe),

            // EAP-TLS
            "EAP-TLS" | "EAP_TLS" | "802.1X-TLS" => Some(SecurityProtocol::EapTls),

            // EAP-PEAP (and generic EAP / 802.1X)
            "EAP" | "EAP-PEAP" | "EAP_PEAP" | "802.1X" | "PEAP" | "WPA2-EAP"
            | "WPA-EAP" | "RSN-EAP" | "WPA2-EAP-CCMP" | "IEEE8021X" => {
                Some(SecurityProtocol::EapPeap)
            }

            _ => None,
        }
    }

    /// Attempt substring-based matching for compound/partial strings.
    fn match_substring(cleaned: &str) -> Option<SecurityProtocol> {
        // Order matters: match more specific patterns first

        // SAE / WPA3 checks before WPA2/WPA (since "WPA" is a substring of "WPA3")
        if cleaned.contains("SAE") {
            return Some(SecurityProtocol::Wpa3Sae);
        }

        if cleaned.contains("OWE") {
            return Some(SecurityProtocol::Owe);
        }

        // EAP-TLS before generic EAP
        if cleaned.contains("EAP-TLS") || cleaned.contains("EAP_TLS") {
            return Some(SecurityProtocol::EapTls);
        }

        if cleaned.contains("EAP") || cleaned.contains("802.1X") || cleaned.contains("PEAP") {
            return Some(SecurityProtocol::EapPeap);
        }

        // WPA2 before WPA
        if cleaned.contains("WPA2") || cleaned.contains("RSN") {
            return Some(SecurityProtocol::Wpa2Psk);
        }

        if cleaned.contains("WPA") {
            return Some(SecurityProtocol::WpaPsk);
        }

        if cleaned.contains("WEP") {
            return Some(SecurityProtocol::Wep);
        }

        None
    }

    /// Match Android `key_mgmt` integer values.
    ///
    /// Android's WifiConfiguration uses integer constants for key management:
    /// - 0: NONE (Open)
    /// - 1: WPA_PSK
    /// - 2: WPA_EAP (802.1X)
    /// - 3: IEEE8021X
    /// - 4: WPA2_PSK
    /// - 6: SAE
    /// - 9: OWE
    fn match_android_key_mgmt(cleaned: &str) -> Option<SecurityProtocol> {
        match cleaned {
            "0" => Some(SecurityProtocol::Open),
            "1" => Some(SecurityProtocol::WpaPsk),
            "2" | "3" => Some(SecurityProtocol::EapPeap),
            "4" => Some(SecurityProtocol::Wpa2Psk),
            "6" => Some(SecurityProtocol::Wpa3Sae),
            "9" => Some(SecurityProtocol::Owe),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Open ──────────────────────────────────────────────────────

    #[test]
    fn test_open_none() {
        assert_eq!(SecurityNormalizer::normalize("NONE"), SecurityProtocol::Open);
    }

    #[test]
    fn test_open_lowercase() {
        assert_eq!(SecurityNormalizer::normalize("open"), SecurityProtocol::Open);
    }

    #[test]
    fn test_open_bracket_ess() {
        assert_eq!(SecurityNormalizer::normalize("[ESS]"), SecurityProtocol::Open);
    }

    #[test]
    fn test_open_empty() {
        assert_eq!(SecurityNormalizer::normalize(""), SecurityProtocol::Open);
    }

    #[test]
    fn test_open_android_key_mgmt_0() {
        assert_eq!(SecurityNormalizer::normalize("0"), SecurityProtocol::Open);
    }

    // ── WEP ──────────────────────────────────────────────────────

    #[test]
    fn test_wep() {
        assert_eq!(SecurityNormalizer::normalize("WEP"), SecurityProtocol::Wep);
    }

    #[test]
    fn test_wep_bracketed() {
        assert_eq!(SecurityNormalizer::normalize("[WEP]"), SecurityProtocol::Wep);
    }

    // ── WPA-PSK ──────────────────────────────────────────────────

    #[test]
    fn test_wpa_psk() {
        assert_eq!(
            SecurityNormalizer::normalize("WPA-PSK"),
            SecurityProtocol::WpaPsk
        );
    }

    #[test]
    fn test_wpa_psk_tkip_bracket() {
        assert_eq!(
            SecurityNormalizer::normalize("[WPA-PSK-TKIP]"),
            SecurityProtocol::WpaPsk
        );
    }

    #[test]
    fn test_wpa_psk_android_key_mgmt_1() {
        assert_eq!(SecurityNormalizer::normalize("1"), SecurityProtocol::WpaPsk);
    }

    // ── WPA2-PSK ─────────────────────────────────────────────────

    #[test]
    fn test_wpa2_psk() {
        assert_eq!(
            SecurityNormalizer::normalize("WPA2-PSK"),
            SecurityProtocol::Wpa2Psk
        );
    }

    #[test]
    fn test_wpa2_psk_ccmp_bracket() {
        assert_eq!(
            SecurityNormalizer::normalize("[WPA2-PSK-CCMP]"),
            SecurityProtocol::Wpa2Psk
        );
    }

    #[test]
    fn test_wpa2_rsn_psk() {
        assert_eq!(
            SecurityNormalizer::normalize("RSN-PSK"),
            SecurityProtocol::Wpa2Psk
        );
    }

    #[test]
    fn test_wpa2_android_key_mgmt_4() {
        assert_eq!(
            SecurityNormalizer::normalize("4"),
            SecurityProtocol::Wpa2Psk
        );
    }

    // ── WPA3-SAE ─────────────────────────────────────────────────

    #[test]
    fn test_wpa3_sae() {
        assert_eq!(
            SecurityNormalizer::normalize("SAE"),
            SecurityProtocol::Wpa3Sae
        );
    }

    #[test]
    fn test_wpa3_sae_full() {
        assert_eq!(
            SecurityNormalizer::normalize("WPA3-SAE"),
            SecurityProtocol::Wpa3Sae
        );
    }

    #[test]
    fn test_wpa3_sae_bracketed() {
        assert_eq!(
            SecurityNormalizer::normalize("[SAE]"),
            SecurityProtocol::Wpa3Sae
        );
    }

    #[test]
    fn test_wpa3_android_key_mgmt_6() {
        assert_eq!(
            SecurityNormalizer::normalize("6"),
            SecurityProtocol::Wpa3Sae
        );
    }

    // ── OWE ──────────────────────────────────────────────────────

    #[test]
    fn test_owe() {
        assert_eq!(SecurityNormalizer::normalize("OWE"), SecurityProtocol::Owe);
    }

    #[test]
    fn test_owe_bracketed() {
        assert_eq!(
            SecurityNormalizer::normalize("[OWE]"),
            SecurityProtocol::Owe
        );
    }

    #[test]
    fn test_owe_android_key_mgmt_9() {
        assert_eq!(SecurityNormalizer::normalize("9"), SecurityProtocol::Owe);
    }

    // ── EAP ──────────────────────────────────────────────────────

    #[test]
    fn test_eap_peap() {
        assert_eq!(
            SecurityNormalizer::normalize("EAP-PEAP"),
            SecurityProtocol::EapPeap
        );
    }

    #[test]
    fn test_eap_generic() {
        assert_eq!(
            SecurityNormalizer::normalize("EAP"),
            SecurityProtocol::EapPeap
        );
    }

    #[test]
    fn test_eap_802_1x() {
        assert_eq!(
            SecurityNormalizer::normalize("802.1X"),
            SecurityProtocol::EapPeap
        );
    }

    #[test]
    fn test_eap_tls() {
        assert_eq!(
            SecurityNormalizer::normalize("EAP-TLS"),
            SecurityProtocol::EapTls
        );
    }

    // ── Unknown ──────────────────────────────────────────────────

    #[test]
    fn test_unknown_protocol() {
        assert_eq!(
            SecurityNormalizer::normalize("SOME_FUTURE_PROTOCOL"),
            SecurityProtocol::Unknown
        );
    }

    // ── Whitespace / case handling ───────────────────────────────

    #[test]
    fn test_whitespace_handling() {
        assert_eq!(
            SecurityNormalizer::normalize("  WPA2-PSK  "),
            SecurityProtocol::Wpa2Psk
        );
    }

    #[test]
    fn test_lowercase_handling() {
        assert_eq!(
            SecurityNormalizer::normalize("wpa2-psk"),
            SecurityProtocol::Wpa2Psk
        );
    }

    #[test]
    fn test_mixed_case() {
        assert_eq!(
            SecurityNormalizer::normalize("Wpa2-Psk"),
            SecurityProtocol::Wpa2Psk
        );
    }
}
