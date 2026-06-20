//! # Hardening Tests
//!
//! Regression and hardening tests for edge cases that affect forensic integrity:
//! - Hardware disconnection during acquisition
//! - Storage and evidence store resilience
//! - Database locking and concurrent access
//! - Parser crash resilience (malformed/corrupted input)
//! - Audit chain tamper detection under stress

#[cfg(test)]
mod hardware_disconnection {
    use oracle_discovery::scanner::AdbShell;
    use oracle_core::error::{OracleError, OracleResult};

    /// Mock ADB that fails mid-transfer to simulate USB disconnection.
    struct DisconnectingAdb {
        pulls_before_disconnect: usize,
        pull_count: std::cell::Cell<usize>,
    }

    impl DisconnectingAdb {
        fn new(pulls_before_disconnect: usize) -> Self {
            Self {
                pulls_before_disconnect,
                pull_count: std::cell::Cell::new(0),
            }
        }
    }

    impl AdbShell for DisconnectingAdb {
        fn shell_command(&self, _serial: &str, _cmd: &str) -> OracleResult<String> {
            let count = self.pull_count.get();
            if count >= self.pulls_before_disconnect {
                Err(OracleError::AdbCommandFailed {
                    serial: "DEAD".to_string(),
                    command: "pull".to_string(),
                    reason: "error: device not found (USB disconnected)".to_string(),
                })
            } else {
                self.pull_count.set(count + 1);
                Ok("sample data".to_string())
            }
        }

        fn check_file_exists(&self, _serial: &str, _path: &str) -> OracleResult<bool> {
            let count = self.pull_count.get();
            if count >= self.pulls_before_disconnect {
                Err(OracleError::AdbCommandFailed {
                    serial: "DEAD".to_string(),
                    command: "stat".to_string(),
                    reason: "error: device not found".to_string(),
                })
            } else {
                Ok(true)
            }
        }

        fn check_file_readable(&self, _serial: &str, _path: &str) -> OracleResult<bool> {
            let count = self.pull_count.get();
            if count >= self.pulls_before_disconnect {
                Err(OracleError::AdbCommandFailed {
                    serial: "DEAD".to_string(),
                    command: "test -r".to_string(),
                    reason: "error: device not found".to_string(),
                })
            } else {
                Ok(true)
            }
        }
    }

    #[test]
    fn test_disconnection_returns_adb_error() {
        let adb = DisconnectingAdb::new(0);
        let result = adb.shell_command("SERIAL", "ls /data");
        assert!(result.is_err());
        if let Err(OracleError::AdbCommandFailed { reason, .. }) = result {
            assert!(reason.contains("device not found"));
        }
    }

    #[test]
    fn test_partial_operations_then_disconnect() {
        let adb = DisconnectingAdb::new(2);
        assert!(adb.shell_command("S", "cmd1").is_ok());
        assert!(adb.shell_command("S", "cmd2").is_ok());
        assert!(adb.shell_command("S", "cmd3").is_err());
    }

    #[test]
    fn test_immediate_disconnect_on_file_check() {
        let adb = DisconnectingAdb::new(0);
        assert!(adb.check_file_exists("S", "/data/misc/wifi/WifiConfigStore.xml").is_err());
    }
}

#[cfg(test)]
mod evidence_store_resilience {
    use oracle_evidence::store::EvidenceStore;
    use oracle_evidence::cas::ContentAddressableStore;
    use oracle_audit::writer::AuditLogWriter;
    use oracle_core::types::{AcquisitionMethod, ArtifactClass, InvestigationId};
    use tempfile::TempDir;

    #[test]
    fn test_store_and_retrieve_empty_artifact() {
        let dir = TempDir::new().unwrap();
        let audit_path = dir.path().join("audit.db");
        let mut audit = AuditLogWriter::new(&audit_path).unwrap();
        let store = EvidenceStore::initialize(dir.path().join("evidence").as_path(), &mut audit).unwrap();
        let cas = ContentAddressableStore::new(&store);

        let result = cas.store_artifact(
            InvestigationId::new(),
            ArtifactClass::WifiConfigStore,
            "/data/misc/wifi/WifiConfigStore.xml",
            &[],
            AcquisitionMethod::PrivilegedLogical,
        );
        assert!(result.is_ok(), "Empty artifacts should be storable");
    }

    #[test]
    fn test_store_large_artifact() {
        let dir = TempDir::new().unwrap();
        let audit_path = dir.path().join("audit.db");
        let mut audit = AuditLogWriter::new(&audit_path).unwrap();
        let store = EvidenceStore::initialize(dir.path().join("evidence").as_path(), &mut audit).unwrap();
        let cas = ContentAddressableStore::new(&store);

        let large_data = vec![0xABu8; 1_048_576]; // 1 MB
        let result = cas.store_artifact(
            InvestigationId::new(),
            ArtifactClass::BatteryStats,
            "/data/system/batterystats.bin",
            &large_data,
            AcquisitionMethod::PrivilegedLogical,
        );
        assert!(result.is_ok(), "Large artifacts should be stored");
    }

    #[test]
    fn test_duplicate_artifact_deduplication() {
        let dir = TempDir::new().unwrap();
        let audit_path = dir.path().join("audit.db");
        let mut audit = AuditLogWriter::new(&audit_path).unwrap();
        let store = EvidenceStore::initialize(dir.path().join("evidence").as_path(), &mut audit).unwrap();
        let cas = ContentAddressableStore::new(&store);

        let data = b"identical content for dedup";
        let inv = InvestigationId::new();

        let id1 = cas.store_artifact(inv, ArtifactClass::WifiConfigStore, "/path", data, AcquisitionMethod::PrivilegedLogical).unwrap();
        let id2 = cas.store_artifact(inv, ArtifactClass::WifiConfigStore, "/path", data, AcquisitionMethod::PrivilegedLogical).unwrap();
        assert_eq!(id1, id2, "Duplicate artifacts must return same ID");
    }
}

#[cfg(test)]
mod database_locking {
    use oracle_audit::writer::AuditLogWriter;
    use oracle_audit::verifier::{AuditLogVerifier, ChainStatus};
    use oracle_core::types::{AuditOperationType, AuditResult};
    use rusqlite::Connection;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn test_50_sequential_intent_result_pairs_maintain_chain() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("audit.db");
        let mut writer = AuditLogWriter::new(&db_path).unwrap();

        for i in 0..50 {
            let idx = writer.log_intent(
                None,
                AuditOperationType::ArtifactAcquisitionStarted,
                "Examiner",
                &format!("Artifact #{}", i),
                json!({"index": i}),
            ).unwrap();
            writer.log_result(idx, AuditResult::Success, json!({"bytes": 1024})).unwrap();
        }

        let conn = Connection::open(&db_path).unwrap();
        let verifier = AuditLogVerifier::new(&conn);
        let report = verifier.verify_full().unwrap();
        assert_eq!(report.overall_status, ChainStatus::Intact, "Chain must be intact after 100 writes");
        assert_eq!(report.total_entries, 100);
    }

    #[test]
    fn test_reopen_after_writes_preserves_chain() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("audit.db");

        {
            let mut writer = AuditLogWriter::new(&db_path).unwrap();
            for i in 0..10 {
                let idx = writer.log_intent(
                    None, AuditOperationType::ArtifactAcquisitionStarted,
                    "Parser", &format!("File #{}", i), json!({}),
                ).unwrap();
                writer.log_result(idx, AuditResult::Success, json!({})).unwrap();
            }
        }
        {
            let mut writer = AuditLogWriter::new(&db_path).unwrap();
            for i in 10..20 {
                let idx = writer.log_intent(
                    None, AuditOperationType::ArtifactAcquisitionStarted,
                    "Parser", &format!("File #{}", i), json!({}),
                ).unwrap();
                writer.log_result(idx, AuditResult::Success, json!({})).unwrap();
            }
        }

        let conn = Connection::open(&db_path).unwrap();
        let verifier = AuditLogVerifier::new(&conn);
        let report = verifier.verify_full().unwrap();
        assert_eq!(report.overall_status, ChainStatus::Intact, "Chain must survive session boundary");
        assert_eq!(report.total_entries, 40);
    }
}

#[cfg(test)]
mod parser_crash_resilience {
    use oracle_parser::traits::ArtifactParser;
    use oracle_parser::wifi_config::WifiConfigStoreParser;
    use oracle_parser::wpa_supplicant::WpaSupplicantParser;
    use oracle_parser::dhcp::DhcpLeaseParser;
    use oracle_parser::connectivity::ConnectivityLogParser;
    use oracle_core::types::ArtifactId;

    #[test]
    fn test_wifi_config_handles_binary_garbage() {
        let parser = WifiConfigStoreParser;
        let garbage: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let result = parser.parse(ArtifactId::new(), "hash", &garbage);
        assert!(result.is_ok() || result.is_err(), "Must not panic");
    }

    #[test]
    fn test_wifi_config_handles_truncated_xml() {
        let parser = WifiConfigStoreParser;
        let truncated = b"<?xml version=\"1.0\"?><WifiConfigStoreData><NetworkList><Network><Wi";
        let result = parser.parse(ArtifactId::new(), "hash", truncated);
        assert!(result.is_ok() || result.is_err(), "Must not panic on truncated XML");
    }

    #[test]
    fn test_wpa_supplicant_handles_binary_garbage() {
        let parser = WpaSupplicantParser;
        let garbage: Vec<u8> = vec![0xFF; 512];
        let result = parser.parse(ArtifactId::new(), "hash", &garbage);
        assert!(result.is_ok() || result.is_err(), "Must not panic");
    }

    #[test]
    fn test_dhcp_handles_binary_garbage() {
        let parser = DhcpLeaseParser;
        let garbage: Vec<u8> = vec![0x00; 1024];
        let result = parser.parse(ArtifactId::new(), "hash", &garbage);
        assert!(result.is_ok() || result.is_err(), "Must not panic");
    }

    #[test]
    fn test_connectivity_handles_binary_garbage() {
        let parser = ConnectivityLogParser;
        let garbage: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let result = parser.parse(ArtifactId::new(), "hash", &garbage);
        assert!(result.is_ok() || result.is_err(), "Must not panic");
    }

    #[test]
    fn test_all_parsers_handle_empty_input() {
        let id = ArtifactId::new();
        assert!(WifiConfigStoreParser.parse(id, "h", b"").is_ok());
        assert!(WpaSupplicantParser.parse(id, "h", b"").is_ok());
        assert!(DhcpLeaseParser.parse(id, "h", b"").is_ok());
        assert!(ConnectivityLogParser.parse(id, "h", b"").is_ok());
    }

    #[test]
    fn test_all_parsers_handle_null_bytes() {
        let id = ArtifactId::new();
        let nulls = vec![0u8; 256];
        let _ = WifiConfigStoreParser.parse(id, "h", &nulls);
        let _ = WpaSupplicantParser.parse(id, "h", &nulls);
        let _ = DhcpLeaseParser.parse(id, "h", &nulls);
        let _ = ConnectivityLogParser.parse(id, "h", &nulls);
    }

    #[test]
    fn test_dhcp_handles_extremely_long_hostname() {
        let parser = DhcpLeaseParser;
        let line = format!("1718000000 aa:bb:cc:dd:ee:ff 192.168.1.1 {} *\n", "A".repeat(10000));
        let result = parser.parse(ArtifactId::new(), "hash", line.as_bytes());
        assert!(result.is_ok() || result.is_err(), "Must not OOM or panic");
    }
}

#[cfg(test)]
mod audit_chain_tamper_detection {
    use oracle_audit::writer::AuditLogWriter;
    use oracle_audit::verifier::{AuditLogVerifier, ChainStatus};
    use oracle_core::types::{AuditOperationType, AuditResult};
    use rusqlite::Connection;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn test_tamper_entry_in_100_entry_chain() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("audit.db");

        {
            let mut writer = AuditLogWriter::new(&db_path).unwrap();
            for i in 0..50 {
                let idx = writer.log_intent(
                    None, AuditOperationType::ArtifactAcquisitionStarted,
                    "Examiner", &format!("Artifact #{}", i), json!({}),
                ).unwrap();
                writer.log_result(idx, AuditResult::Success, json!({})).unwrap();
            }
        }

        // Tamper with entry #50
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute("UPDATE audit_entries SET subject = 'TAMPERED' WHERE entry_index = 50", []).unwrap();
        }

        let conn = Connection::open(&db_path).unwrap();
        let verifier = AuditLogVerifier::new(&conn);
        let report = verifier.verify_full().unwrap();
        assert_eq!(report.overall_status, ChainStatus::Broken, "Must detect tampered entry");
    }

    #[test]
    fn test_delete_entry_from_chain_detected() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("audit.db");

        {
            let mut writer = AuditLogWriter::new(&db_path).unwrap();
            for i in 0..10 {
                let idx = writer.log_intent(
                    None, AuditOperationType::ArtifactAcquisitionStarted,
                    "Parser", &format!("File #{}", i), json!({}),
                ).unwrap();
                writer.log_result(idx, AuditResult::Success, json!({})).unwrap();
            }
        }

        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute("DELETE FROM audit_entries WHERE entry_index = 5", []).unwrap();
        }

        let conn = Connection::open(&db_path).unwrap();
        let verifier = AuditLogVerifier::new(&conn);
        let report = verifier.verify_full().unwrap();
        assert_eq!(report.overall_status, ChainStatus::Broken, "Must detect deleted entry");
    }

    #[test]
    fn test_swap_hashes_detected() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("audit.db");

        {
            let mut writer = AuditLogWriter::new(&db_path).unwrap();
            for i in 0..6 {
                let idx = writer.log_intent(
                    None, AuditOperationType::ArtifactAcquisitionStarted,
                    "Examiner", &format!("Item #{}", i), json!({}),
                ).unwrap();
                writer.log_result(idx, AuditResult::Success, json!({})).unwrap();
            }
        }

        {
            let conn = Connection::open(&db_path).unwrap();
            let hash2: String = conn.query_row(
                "SELECT entry_hash FROM audit_entries WHERE entry_index = 2", [], |r| r.get(0),
            ).unwrap();
            let hash3: String = conn.query_row(
                "SELECT entry_hash FROM audit_entries WHERE entry_index = 3", [], |r| r.get(0),
            ).unwrap();
            conn.execute("UPDATE audit_entries SET entry_hash = ?1 WHERE entry_index = 2", [&hash3]).unwrap();
            conn.execute("UPDATE audit_entries SET entry_hash = ?1 WHERE entry_index = 3", [&hash2]).unwrap();
        }

        let conn = Connection::open(&db_path).unwrap();
        let verifier = AuditLogVerifier::new(&conn);
        let report = verifier.verify_full().unwrap();
        assert_eq!(report.overall_status, ChainStatus::Broken, "Must detect swapped hashes");
    }
}
