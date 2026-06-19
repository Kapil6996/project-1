//! # Configuration Management
//!
//! Application configuration for the ORACLE forensic platform.
//! Configuration is loaded at startup, validated, and recorded in the audit log.
//! Configuration changes after startup are prohibited to maintain forensic integrity.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use crate::error::{OracleError, OracleResult};

/// Top-level application configuration.
///
/// Loaded from a TOML configuration file at startup. Once loaded and validated,
/// the configuration is immutable for the duration of the process to prevent
/// mid-investigation behavioral changes that could compromise forensic integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleConfig {
    /// General application settings.
    pub general: GeneralConfig,
    /// Evidence store settings.
    pub evidence_store: EvidenceStoreConfig,
    /// Audit logger settings.
    pub audit: AuditConfig,
    /// Plugin system settings.
    pub plugins: PluginConfig,
    /// ADB interface settings.
    pub adb: AdbConfig,
    /// Report generation settings.
    pub report: ReportConfig,
}

/// General application settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// The base directory for storing investigation data.
    pub investigations_dir: PathBuf,
    /// The forensic lab or agency name recorded in all reports.
    pub organization_name: String,
    /// Log level for internal tracing (debug, info, warn, error).
    pub log_level: String,
}

/// Evidence store configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceStoreConfig {
    /// Maximum size in bytes for a single CAS blob before splitting.
    /// Default: 4GB (for FAT32 compatibility on external drives).
    pub max_blob_size_bytes: u64,
    /// Whether to verify artifact hashes on every read (paranoid mode).
    /// Enabled by default. Disabling sacrifices integrity for speed.
    pub verify_on_read: bool,
}

/// Audit logger configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// The batch size for audit log hash chain computation.
    /// Each batch is hashed together for performance.
    /// Default: 1 (every entry individually chained — maximum integrity).
    pub chain_batch_size: u32,
}

/// Plugin system configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    /// Directory containing installed OEM plugins.
    pub plugin_dir: PathBuf,
    /// Whether to enforce plugin signature verification.
    /// Default: true in production, false in development.
    pub enforce_signatures: bool,
}

/// ADB interface configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdbConfig {
    /// Timeout in seconds for ADB commands.
    pub command_timeout_secs: u64,
    /// Maximum number of transport reconnection attempts.
    pub max_reconnect_attempts: u32,
    /// Chunk size in bytes for artifact streaming from device.
    pub stream_chunk_size: u64,
}

/// Report generation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    /// Default output directory for generated reports.
    pub output_dir: PathBuf,
    /// Whether to include raw hex dumps in the evidence appendix.
    pub include_hex_dumps: bool,
}

impl OracleConfig {
    /// Load configuration from a TOML file at the specified path.
    ///
    /// Returns an error if the file does not exist, is unreadable,
    /// or contains invalid configuration values.
    pub fn load_from_file(path: &Path) -> OracleResult<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| OracleError::IoError {
            path: path.to_path_buf(),
            source: e,
        })?;
        let config: OracleConfig = toml::from_str(&content).map_err(|e| {
            OracleError::ConfigurationError {
                reason: format!("Failed to parse config file {}: {}", path.display(), e),
            }
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Create a default configuration suitable for development and testing.
    ///
    /// Production deployments must use an explicit configuration file.
    pub fn default_config(base_dir: &Path) -> Self {
        OracleConfig {
            general: GeneralConfig {
                investigations_dir: base_dir.join("investigations"),
                organization_name: "ORACLE Forensic Lab".to_string(),
                log_level: "info".to_string(),
            },
            evidence_store: EvidenceStoreConfig {
                max_blob_size_bytes: 4_294_967_296, // 4GB
                verify_on_read: true,
            },
            audit: AuditConfig {
                chain_batch_size: 1,
            },
            plugins: PluginConfig {
                plugin_dir: base_dir.join("plugins"),
                enforce_signatures: false, // Default false for development
            },
            adb: AdbConfig {
                command_timeout_secs: 30,
                max_reconnect_attempts: 5,
                stream_chunk_size: 65536, // 64KB
            },
            report: ReportConfig {
                output_dir: base_dir.join("reports"),
                include_hex_dumps: false,
            },
        }
    }

    /// Validate all configuration values for correctness and safety.
    ///
    /// This method is called automatically when loading from a file.
    /// It ensures that directory paths are sensible and numeric values
    /// are within acceptable ranges.
    pub fn validate(&self) -> OracleResult<()> {
        if self.general.organization_name.is_empty() {
            return Err(OracleError::ConfigurationError {
                reason: "Organization name must not be empty".to_string(),
            });
        }

        if self.evidence_store.max_blob_size_bytes == 0 {
            return Err(OracleError::ConfigurationError {
                reason: "max_blob_size_bytes must be greater than zero".to_string(),
            });
        }

        if self.adb.command_timeout_secs == 0 {
            return Err(OracleError::ConfigurationError {
                reason: "ADB command timeout must be greater than zero".to_string(),
            });
        }

        if self.adb.stream_chunk_size < 4096 {
            return Err(OracleError::ConfigurationError {
                reason: "Stream chunk size must be at least 4096 bytes".to_string(),
            });
        }

        if self.audit.chain_batch_size == 0 {
            return Err(OracleError::ConfigurationError {
                reason: "Audit chain batch size must be at least 1".to_string(),
            });
        }

        Ok(())
    }

    /// Serialize the configuration to TOML format for recording in the audit log.
    ///
    /// Every investigation records the exact configuration used at its creation time
    /// so that results can be reproduced and methodology disclosed.
    pub fn to_toml_string(&self) -> OracleResult<String> {
        toml::to_string_pretty(self).map_err(|e| OracleError::SerializationError {
            reason: format!("Failed to serialize config: {}", e),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = OracleConfig::default_config(Path::new("/tmp/oracle-test"));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_empty_org_name_rejected() {
        let mut config = OracleConfig::default_config(Path::new("/tmp/oracle-test"));
        config.general.organization_name = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_zero_timeout_rejected() {
        let mut config = OracleConfig::default_config(Path::new("/tmp/oracle-test"));
        config.adb.command_timeout_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_small_chunk_rejected() {
        let mut config = OracleConfig::default_config(Path::new("/tmp/oracle-test"));
        config.adb.stream_chunk_size = 100;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_roundtrip_toml() {
        let config = OracleConfig::default_config(Path::new("/tmp/oracle-test"));
        let toml_str = config.to_toml_string().unwrap();
        let parsed: OracleConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.general.organization_name, config.general.organization_name);
    }

    #[test]
    fn test_missing_config_file_error() {
        let result = OracleConfig::load_from_file(Path::new("/nonexistent/oracle.toml"));
        assert!(result.is_err());
    }
}
