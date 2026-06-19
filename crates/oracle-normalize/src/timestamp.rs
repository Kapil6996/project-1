//! # Timestamp Normalizer
//!
//! Normalizes raw timestamp values from Android forensic artifacts into
//! [`ForensicTimestamp`] instances with anomaly detection and clock skew
//! compensation.
//!
//! # Supported Formats
//!
//! | Format ID              | Example                          |
//! |------------------------|----------------------------------|
//! | `unix_epoch_s`         | `1700000000`                     |
//! | `unix_epoch_ms`        | `1700000000000`                  |
//! | `iso8601`              | `2023-11-14T22:13:20Z`           |
//! | `android_logcat`       | `11-14 22:13:20.000`             |
//! | `boot_relative_s`      | `12345.678` (seconds since boot) |
//!
//! # Anomaly Detection
//!
//! - **Future timestamps:** Device clock set ahead of acquisition time.
//! - **Epoch defaults:** `1970-01-01T00:00:00Z` — common uninitialized value.
//! - **Pre-Android era:** Timestamps before 2008, the year Android 1.0 shipped.
//! - **Clock skew:** Significant delta between device time and acquisition time.

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use oracle_core::types::{ForensicTimestamp, TimestampAnomaly};
use tracing::warn;

/// Threshold in seconds beyond which clock skew is flagged.
const CLOCK_SKEW_THRESHOLD_SECS: f64 = 300.0; // 5 minutes

/// The earliest plausible Android timestamp (Android 1.0 release: 2008-09-23).
const ANDROID_EPOCH_YEAR: i32 = 2008;

/// Normalizes raw timestamp strings from Android artifacts.
pub struct TimestampNormalizer;

impl TimestampNormalizer {
    /// Normalize a raw timestamp string into a [`ForensicTimestamp`].
    ///
    /// # Arguments
    ///
    /// * `raw` — The raw timestamp value exactly as extracted from the artifact.
    /// * `source_format` — The expected format identifier (e.g., `"unix_epoch_s"`,
    ///   `"iso8601"`, `"android_logcat"`, `"boot_relative_s"`, `"unix_epoch_ms"`).
    /// * `device_boot_time` — If known, the device's last boot time. Required for
    ///   `boot_relative_s` format.
    /// * `acquisition_time` — The time at which the artifact was acquired from the
    ///   device. Used for anomaly detection and clock skew computation.
    ///
    /// # Returns
    ///
    /// A [`ForensicTimestamp`] with the normalized UTC time, anomaly flags, and
    /// confidence score. If parsing fails entirely, the timestamp is set to the
    /// Unix epoch with a `FormatAmbiguous` anomaly and zero confidence.
    pub fn normalize(
        raw: &str,
        source_format: &str,
        device_boot_time: Option<DateTime<Utc>>,
        acquisition_time: DateTime<Utc>,
    ) -> ForensicTimestamp {
        let parsed = match source_format {
            "unix_epoch_s" => Self::parse_unix_epoch_s(raw),
            "unix_epoch_ms" => Self::parse_unix_epoch_ms(raw),
            "iso8601" => Self::parse_iso8601(raw),
            "android_logcat" => Self::parse_android_logcat(raw, acquisition_time),
            "boot_relative_s" => Self::parse_boot_relative(raw, device_boot_time),
            _ => {
                warn!(
                    format = source_format,
                    raw_value = raw,
                    "Unknown timestamp format, attempting auto-detection"
                );
                Self::auto_detect(raw, device_boot_time, acquisition_time)
            }
        };

        match parsed {
            Some(dt) => Self::build_forensic_timestamp(
                raw.to_string(),
                source_format.to_string(),
                dt,
                acquisition_time,
            ),
            None => {
                warn!(
                    format = source_format,
                    raw_value = raw,
                    "Failed to parse timestamp"
                );
                ForensicTimestamp {
                    raw_value: raw.to_string(),
                    source_format: source_format.to_string(),
                    normalized_utc: Utc.timestamp_opt(0, 0)
                        .single()
                        .unwrap_or_else(|| DateTime::<Utc>::MIN_UTC),
                    clock_skew_compensation_secs: None,
                    anomaly: TimestampAnomaly::FormatAmbiguous,
                    confidence: 0.0,
                }
            }
        }
    }

    /// Parse a Unix epoch timestamp in seconds.
    fn parse_unix_epoch_s(raw: &str) -> Option<DateTime<Utc>> {
        let secs: i64 = raw.trim().parse().ok()?;
        Utc.timestamp_opt(secs, 0).single()
    }

    /// Parse a Unix epoch timestamp in milliseconds.
    fn parse_unix_epoch_ms(raw: &str) -> Option<DateTime<Utc>> {
        let ms: i64 = raw.trim().parse().ok()?;
        Utc.timestamp_opt(ms / 1000, ((ms % 1000) * 1_000_000) as u32)
            .single()
    }

    /// Parse an ISO 8601 timestamp.
    fn parse_iso8601(raw: &str) -> Option<DateTime<Utc>> {
        let trimmed = raw.trim();

        // Try full DateTime with timezone
        if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
            return Some(dt.with_timezone(&Utc));
        }

        // Try ISO 8601 without timezone (assume UTC)
        if let Ok(ndt) = NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S%.f") {
            return Some(Utc.from_utc_datetime(&ndt));
        }
        if let Ok(ndt) = NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S") {
            return Some(Utc.from_utc_datetime(&ndt));
        }

        // Try date-only
        if let Ok(nd) = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
            let ndt = nd.and_hms_opt(0, 0, 0)?;
            return Some(Utc.from_utc_datetime(&ndt));
        }

        None
    }

    /// Parse Android logcat timestamp format: `MM-DD HH:MM:SS.mmm`.
    ///
    /// Logcat timestamps lack a year, so we use the acquisition time's year.
    fn parse_android_logcat(raw: &str, acquisition_time: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let trimmed = raw.trim();
        let year = acquisition_time.format("%Y").to_string();
        let with_year = format!("{}-{}", year, trimmed);

        // Try with milliseconds
        if let Ok(ndt) = NaiveDateTime::parse_from_str(&with_year, "%Y-%m-%d %H:%M:%S%.3f") {
            return Some(Utc.from_utc_datetime(&ndt));
        }

        // Try without milliseconds
        if let Ok(ndt) = NaiveDateTime::parse_from_str(&with_year, "%Y-%m-%d %H:%M:%S") {
            return Some(Utc.from_utc_datetime(&ndt));
        }

        None
    }

    /// Parse a boot-relative timestamp (seconds since device boot).
    fn parse_boot_relative(
        raw: &str,
        device_boot_time: Option<DateTime<Utc>>,
    ) -> Option<DateTime<Utc>> {
        let secs: f64 = raw.trim().parse().ok()?;
        let boot_time = device_boot_time?;
        let duration = chrono::Duration::milliseconds((secs * 1000.0) as i64);
        boot_time.checked_add_signed(duration)
    }

    /// Attempt to auto-detect the timestamp format.
    fn auto_detect(
        raw: &str,
        device_boot_time: Option<DateTime<Utc>>,
        acquisition_time: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        // Try ISO 8601 first (most unambiguous)
        if let Some(dt) = Self::parse_iso8601(raw) {
            return Some(dt);
        }

        // Try as numeric value
        let trimmed = raw.trim();
        if let Ok(num) = trimmed.parse::<i64>() {
            // Heuristic: if > 1e12, assume milliseconds; otherwise seconds
            if num > 1_000_000_000_000 {
                return Self::parse_unix_epoch_ms(trimmed);
            } else if num > 0 {
                return Self::parse_unix_epoch_s(trimmed);
            }
        }

        // Try boot-relative
        if let Ok(_secs) = trimmed.parse::<f64>() {
            if device_boot_time.is_some() {
                return Self::parse_boot_relative(trimmed, device_boot_time);
            }
        }

        // Try logcat format
        Self::parse_android_logcat(trimmed, acquisition_time)
    }

    /// Build a [`ForensicTimestamp`] with anomaly detection and clock skew computation.
    fn build_forensic_timestamp(
        raw_value: String,
        source_format: String,
        normalized_utc: DateTime<Utc>,
        acquisition_time: DateTime<Utc>,
    ) -> ForensicTimestamp {
        let (anomaly, confidence) =
            Self::detect_anomaly(&normalized_utc, &acquisition_time);

        let clock_skew = Self::compute_clock_skew(&normalized_utc, &acquisition_time);

        ForensicTimestamp {
            raw_value,
            source_format,
            normalized_utc,
            clock_skew_compensation_secs: clock_skew,
            anomaly,
            confidence,
        }
    }

    /// Detect timestamp anomalies.
    fn detect_anomaly(
        timestamp: &DateTime<Utc>,
        acquisition_time: &DateTime<Utc>,
    ) -> (TimestampAnomaly, f64) {
        // Check epoch default (1970-01-01T00:00:00Z)
        if timestamp.timestamp() == 0 {
            return (TimestampAnomaly::EpochDefault, 0.1);
        }

        // Check pre-Android era (before 2008)
        if timestamp.format("%Y").to_string().parse::<i32>().unwrap_or(0) < ANDROID_EPOCH_YEAR {
            return (TimestampAnomaly::PreAndroidEra, 0.2);
        }

        // Check future timestamp
        if timestamp > acquisition_time {
            // Allow a small tolerance (60 seconds) for clock differences during acquisition
            let delta = (*timestamp - *acquisition_time).num_seconds();
            if delta > 60 {
                return (TimestampAnomaly::Future, 0.3);
            }
        }

        // Check clock skew
        let skew = (*timestamp - *acquisition_time).num_seconds().unsigned_abs() as f64;
        if skew > CLOCK_SKEW_THRESHOLD_SECS {
            return (TimestampAnomaly::ClockSkewDetected, 0.7);
        }

        (TimestampAnomaly::None, 1.0)
    }

    /// Compute clock skew between the device timestamp and acquisition time.
    /// Returns `Some(skew_secs)` if skew exceeds the threshold.
    fn compute_clock_skew(
        timestamp: &DateTime<Utc>,
        acquisition_time: &DateTime<Utc>,
    ) -> Option<f64> {
        let skew_secs = (*timestamp - *acquisition_time).num_seconds() as f64;
        if skew_secs.abs() > CLOCK_SKEW_THRESHOLD_SECS {
            Some(skew_secs)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acq_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap()
    }

    #[test]
    fn test_unix_epoch_seconds() {
        let ts = TimestampNormalizer::normalize("1700000000", "unix_epoch_s", None, acq_time());
        assert_eq!(ts.normalized_utc.timestamp(), 1700000000);
        assert_eq!(ts.source_format, "unix_epoch_s");
    }

    #[test]
    fn test_unix_epoch_milliseconds() {
        let ts = TimestampNormalizer::normalize("1700000000000", "unix_epoch_ms", None, acq_time());
        assert_eq!(ts.normalized_utc.timestamp(), 1700000000);
        assert_eq!(ts.source_format, "unix_epoch_ms");
    }

    #[test]
    fn test_iso8601_with_timezone() {
        let ts = TimestampNormalizer::normalize(
            "2023-11-14T22:13:20Z",
            "iso8601",
            None,
            acq_time(),
        );
        assert_eq!(ts.normalized_utc.timestamp(), 1700000000);
    }

    #[test]
    fn test_iso8601_without_timezone() {
        let ts = TimestampNormalizer::normalize(
            "2023-11-14T22:13:20",
            "iso8601",
            None,
            acq_time(),
        );
        assert_eq!(ts.normalized_utc.timestamp(), 1700000000);
    }

    #[test]
    fn test_android_logcat_format() {
        // Logcat format lacks year — uses acquisition time year
        let acq = Utc.with_ymd_and_hms(2024, 3, 15, 10, 0, 0).unwrap();
        let ts = TimestampNormalizer::normalize("01-15 12:30:45.123", "android_logcat", None, acq);
        assert_eq!(
            ts.normalized_utc,
            Utc.with_ymd_and_hms(2024, 1, 15, 12, 30, 45).unwrap()
                + chrono::Duration::milliseconds(123)
        );
    }

    #[test]
    fn test_boot_relative() {
        let boot = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();
        let ts = TimestampNormalizer::normalize(
            "7200.0",
            "boot_relative_s",
            Some(boot),
            acq_time(),
        );
        // 7200 seconds = 2 hours after boot
        let expected = Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap();
        assert_eq!(ts.normalized_utc, expected);
    }

    #[test]
    fn test_boot_relative_no_boot_time() {
        let ts = TimestampNormalizer::normalize(
            "7200.0",
            "boot_relative_s",
            None,
            acq_time(),
        );
        assert_eq!(ts.anomaly, TimestampAnomaly::FormatAmbiguous);
        assert_eq!(ts.confidence, 0.0);
    }

    #[test]
    fn test_anomaly_epoch_default() {
        let ts = TimestampNormalizer::normalize("0", "unix_epoch_s", None, acq_time());
        assert_eq!(ts.anomaly, TimestampAnomaly::EpochDefault);
        assert!(ts.confidence < 0.5);
    }

    #[test]
    fn test_anomaly_pre_android_era() {
        // Year 2000 is before Android existed
        let ts = TimestampNormalizer::normalize("946684800", "unix_epoch_s", None, acq_time());
        assert_eq!(ts.anomaly, TimestampAnomaly::PreAndroidEra);
    }

    #[test]
    fn test_anomaly_future_timestamp() {
        // Far future: year ~2106
        let ts = TimestampNormalizer::normalize("4294967296", "unix_epoch_s", None, acq_time());
        assert_eq!(ts.anomaly, TimestampAnomaly::Future);
    }

    #[test]
    fn test_clock_skew_detection() {
        // Timestamp 1 hour behind acquisition time (3600 seconds > 300 threshold)
        let acq = Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap();
        let device_ts = (acq - chrono::Duration::hours(1)).timestamp().to_string();
        let ts = TimestampNormalizer::normalize(&device_ts, "unix_epoch_s", None, acq);
        assert_eq!(ts.anomaly, TimestampAnomaly::ClockSkewDetected);
        assert!(ts.clock_skew_compensation_secs.is_some());
    }

    #[test]
    fn test_no_anomaly_normal_timestamp() {
        let acq = Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap();
        let ts = TimestampNormalizer::normalize(
            &acq.timestamp().to_string(),
            "unix_epoch_s",
            None,
            acq,
        );
        assert_eq!(ts.anomaly, TimestampAnomaly::None);
        assert_eq!(ts.confidence, 1.0);
    }

    #[test]
    fn test_invalid_format_returns_ambiguous() {
        let ts = TimestampNormalizer::normalize("not_a_timestamp", "unix_epoch_s", None, acq_time());
        assert_eq!(ts.anomaly, TimestampAnomaly::FormatAmbiguous);
        assert_eq!(ts.confidence, 0.0);
    }

    #[test]
    fn test_unknown_format_auto_detects() {
        let ts = TimestampNormalizer::normalize(
            "2023-11-14T22:13:20Z",
            "unknown_format",
            None,
            acq_time(),
        );
        // Should auto-detect as ISO 8601
        assert_eq!(ts.normalized_utc.timestamp(), 1700000000);
    }

    #[test]
    fn test_auto_detect_large_number_as_ms() {
        let ts = TimestampNormalizer::normalize(
            "1700000000000",
            "auto",
            None,
            acq_time(),
        );
        assert_eq!(ts.normalized_utc.timestamp(), 1700000000);
    }
}
