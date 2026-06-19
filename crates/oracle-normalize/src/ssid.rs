//! # SSID Normalizer
//!
//! Normalizes raw SSID strings from diverse Android artifact sources into a
//! canonical representation suitable for cross-source correlation.
//!
//! # Handled Formats
//!
//! - **Quoted SSIDs:** `"MyNetwork"` → `MyNetwork`
//! - **Hex-encoded SSIDs:** `4d794e6574776f726b` → `MyNetwork`
//! - **Unicode escape sequences:** `\u0041\u0042` → `AB`
//! - **Whitespace anomalies:** Leading/trailing whitespace trimmed
//! - **Null bytes:** Stripped with anomaly flag

use serde::{Deserialize, Serialize};

/// The encoding detected during SSID normalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SsidEncoding {
    /// Plain UTF-8 text.
    Utf8,
    /// The SSID was enclosed in double quotes (common in `wpa_supplicant.conf`).
    Quoted,
    /// The SSID was hex-encoded (e.g., `wpa_supplicant` non-UTF-8 fallback).
    HexEncoded,
    /// The SSID contained Unicode escape sequences (`\uXXXX`).
    UnicodeEscaped,
    /// The encoding could not be determined.
    Unknown,
}

/// A normalized SSID carrying both the original and canonical values,
/// along with metadata about the encoding detected and any anomalies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedSsid {
    /// The raw SSID exactly as extracted from the artifact.
    pub raw: String,
    /// The normalized, canonical SSID string.
    pub normalized: String,
    /// The encoding format detected during normalization.
    pub encoding_detected: SsidEncoding,
    /// Whether the raw SSID exhibited any anomaly (null bytes, control chars, etc.).
    pub had_anomaly: bool,
}

/// Normalizes raw SSID strings into canonical form.
///
/// This normalizer is stateless — all configuration is embedded
/// in the normalization logic itself.
pub struct SsidNormalizer;

impl SsidNormalizer {
    /// Normalize a raw SSID string into canonical form.
    ///
    /// # Processing Order
    ///
    /// 1. Detect and strip surrounding double quotes.
    /// 2. Detect and decode hex-encoded SSIDs.
    /// 3. Decode Unicode escape sequences (`\uXXXX`).
    /// 4. Strip null bytes (flagging as anomaly).
    /// 5. Trim leading/trailing whitespace.
    ///
    /// # Examples
    ///
    /// ```
    /// use oracle_normalize::ssid::SsidNormalizer;
    ///
    /// let result = SsidNormalizer::normalize("\"MyNetwork\"");
    /// assert_eq!(result.normalized, "MyNetwork");
    /// ```
    pub fn normalize(raw_ssid: &str) -> NormalizedSsid {
        let raw = raw_ssid.to_string();
        let mut had_anomaly = false;
        let mut encoding = SsidEncoding::Utf8;

        let working = raw_ssid.trim();

        // Step 1: Strip surrounding double quotes
        let (working, is_quoted) = if working.len() >= 2
            && working.starts_with('"')
            && working.ends_with('"')
        {
            (&working[1..working.len() - 1], true)
        } else {
            (working, false)
        };

        if is_quoted {
            encoding = SsidEncoding::Quoted;
        }

        // Step 2: Try hex decoding — only if the string looks like a pure hex
        // sequence (even length, all hex chars, and decodes to valid UTF-8).
        let (working_owned, is_hex) = if !is_quoted && is_hex_encoded(working) {
            match decode_hex(working) {
                Some(decoded) => (decoded, true),
                None => (working.to_string(), false),
            }
        } else {
            (working.to_string(), false)
        };

        if is_hex {
            encoding = SsidEncoding::HexEncoded;
        }

        // Step 3: Decode Unicode escape sequences (\uXXXX)
        let (working_owned, had_unicode) = decode_unicode_escapes(&working_owned);

        if had_unicode && !is_hex {
            encoding = SsidEncoding::UnicodeEscaped;
        }

        // Step 4: Strip null bytes
        let contains_null = working_owned.contains('\0');
        if contains_null {
            had_anomaly = true;
        }
        let working_owned = working_owned.replace('\0', "");

        // Step 5: Detect control characters (other than null) as anomalies
        if working_owned.chars().any(|c| c.is_control() && c != '\0') {
            had_anomaly = true;
        }

        // Step 6: Trim whitespace
        let normalized = working_owned.trim().to_string();

        // Flag empty result as anomaly if input was non-empty
        if normalized.is_empty() && !raw.trim().is_empty() {
            had_anomaly = true;
        }

        NormalizedSsid {
            raw,
            normalized,
            encoding_detected: encoding,
            had_anomaly,
        }
    }
}

/// Returns `true` if the string looks like a hex-encoded SSID:
/// - Even length
/// - At least 2 characters
/// - All characters are hexadecimal digits
/// - Minimum 4 chars to avoid false positives on short strings like "AB"
fn is_hex_encoded(s: &str) -> bool {
    let len = s.len();
    len >= 4 && len % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Decode a hex-encoded string into UTF-8.
/// Returns `None` if the hex string does not decode to valid UTF-8.
fn decode_hex(hex: &str) -> Option<String> {
    let bytes: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();

    bytes.and_then(|b| String::from_utf8(b).ok())
}

/// Decode `\uXXXX` escape sequences in the string.
/// Returns the decoded string and whether any escapes were found.
fn decode_unicode_escapes(s: &str) -> (String, bool) {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    let mut found_escape = false;

    while let Some(c) = chars.next() {
        if c == '\\' {
            if chars.peek() == Some(&'u') {
                chars.next(); // consume 'u'
                let hex: String = chars.by_ref().take(4).collect();
                if hex.len() == 4 {
                    if let Ok(code_point) = u32::from_str_radix(&hex, 16) {
                        if let Some(decoded_char) = char::from_u32(code_point) {
                            result.push(decoded_char);
                            found_escape = true;
                            continue;
                        }
                    }
                }
                // Failed to decode — preserve original sequence
                result.push('\\');
                result.push('u');
                result.push_str(&hex);
            } else {
                result.push(c);
            }
        } else {
            result.push(c);
        }
    }

    (result, found_escape)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_ssid() {
        let result = SsidNormalizer::normalize("MyNetwork");
        assert_eq!(result.normalized, "MyNetwork");
        assert_eq!(result.encoding_detected, SsidEncoding::Utf8);
        assert!(!result.had_anomaly);
    }

    #[test]
    fn test_quoted_ssid() {
        let result = SsidNormalizer::normalize("\"HomeWifi\"");
        assert_eq!(result.normalized, "HomeWifi");
        assert_eq!(result.encoding_detected, SsidEncoding::Quoted);
        assert!(!result.had_anomaly);
    }

    #[test]
    fn test_quoted_ssid_with_spaces() {
        let result = SsidNormalizer::normalize("\"My Home Network\"");
        assert_eq!(result.normalized, "My Home Network");
        assert_eq!(result.encoding_detected, SsidEncoding::Quoted);
        assert!(!result.had_anomaly);
    }

    #[test]
    fn test_hex_encoded_ssid() {
        // "MyNetwork" in hex
        let result = SsidNormalizer::normalize("4d794e6574776f726b");
        assert_eq!(result.normalized, "MyNetwork");
        assert_eq!(result.encoding_detected, SsidEncoding::HexEncoded);
        assert!(!result.had_anomaly);
    }

    #[test]
    fn test_hex_encoded_hello() {
        // "Hello" in hex
        let result = SsidNormalizer::normalize("48656c6c6f");
        assert_eq!(result.normalized, "Hello");
        assert_eq!(result.encoding_detected, SsidEncoding::HexEncoded);
    }

    #[test]
    fn test_unicode_escape_ssid() {
        let result = SsidNormalizer::normalize("\\u0041\\u0042\\u0043");
        assert_eq!(result.normalized, "ABC");
        assert_eq!(result.encoding_detected, SsidEncoding::UnicodeEscaped);
        assert!(!result.had_anomaly);
    }

    #[test]
    fn test_unicode_escape_mixed() {
        let result = SsidNormalizer::normalize("Net\\u0077ork");
        assert_eq!(result.normalized, "Network");
        assert_eq!(result.encoding_detected, SsidEncoding::UnicodeEscaped);
    }

    #[test]
    fn test_whitespace_trimming() {
        let result = SsidNormalizer::normalize("  MyNetwork  ");
        assert_eq!(result.normalized, "MyNetwork");
        assert!(!result.had_anomaly);
    }

    #[test]
    fn test_null_bytes() {
        let result = SsidNormalizer::normalize("My\0Network");
        assert_eq!(result.normalized, "MyNetwork");
        assert!(result.had_anomaly);
    }

    #[test]
    fn test_control_characters() {
        let result = SsidNormalizer::normalize("My\x01Network");
        assert_eq!(result.normalized, "My\x01Network");
        assert!(result.had_anomaly);
    }

    #[test]
    fn test_empty_ssid() {
        let result = SsidNormalizer::normalize("");
        assert_eq!(result.normalized, "");
        assert!(!result.had_anomaly);
    }

    #[test]
    fn test_empty_after_stripping() {
        let result = SsidNormalizer::normalize("\0\0\0");
        assert_eq!(result.normalized, "");
        assert!(result.had_anomaly);
    }

    #[test]
    fn test_quoted_preserves_inner_whitespace() {
        let result = SsidNormalizer::normalize("\"  spaced  \"");
        assert_eq!(result.normalized, "spaced");
        assert_eq!(result.encoding_detected, SsidEncoding::Quoted);
    }

    #[test]
    fn test_raw_is_preserved() {
        let raw = "\"MyNetwork\"";
        let result = SsidNormalizer::normalize(raw);
        assert_eq!(result.raw, raw);
    }
}
