//! # ORACLE CLI
//!
//! Command-line interface for the ORACLE Android Network Forensics Platform.
//!
//! This binary provides the primary user interface for conducting forensic
//! investigations, managing evidence, and generating court-ready reports.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

/// ORACLE — Android Network Forensics Platform
///
/// A forensic analysis tool for extracting, correlating, and reporting
/// network activity evidence from Android devices.
#[derive(Parser, Debug)]
#[command(
    name = "oracle",
    version,
    author,
    about = "ORACLE Android Network Forensics Platform",
    long_about = "ORACLE is a forensic analysis platform for extracting, correlating, \
                  and reporting network activity evidence from Android devices. \
                  All operations maintain cryptographic chain of custody."
)]
struct Cli {
    /// Path to the ORACLE configuration file.
    ///
    /// If not specified, ORACLE will look for `config/default.toml` relative
    /// to the current working directory, then fall back to built-in defaults.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Enable verbose debug logging (overrides config log level).
    #[arg(short, long)]
    verbose: bool,

    /// The subcommand to execute.
    #[command(subcommand)]
    command: Commands,
}

/// Available ORACLE subcommands.
#[derive(Subcommand, Debug)]
enum Commands {
    /// Create a new forensic investigation.
    ///
    /// Initializes a new investigation workspace with a unique ID,
    /// sets up the evidence store, and begins the audit trail.
    #[command(name = "new-investigation")]
    NewInvestigation {
        /// Human-readable case identifier (e.g., "CASE-2026-0042").
        #[arg(short = 'n', long)]
        case_name: String,

        /// Name of the forensic examiner conducting the investigation.
        #[arg(short, long)]
        examiner: String,

        /// Optional case notes or description.
        #[arg(short = 'd', long)]
        description: Option<String>,
    },

    /// Ingest forensic artifacts from a device or filesystem image.
    ///
    /// Connects to an Android device (or reads a filesystem dump),
    /// discovers available artifacts, and ingests them into the
    /// evidence store with full chain-of-custody tracking.
    Ingest {
        /// Investigation ID to ingest artifacts into.
        #[arg(short, long)]
        investigation_id: String,

        /// Source path (device serial, ADB address, or filesystem path).
        #[arg(short, long)]
        source: String,
    },

    /// Verify the integrity of an investigation's evidence and audit trail.
    ///
    /// Re-computes SHA-256 hashes for all stored artifacts and validates
    /// the audit log hash chain. Reports any integrity violations.
    Verify {
        /// Investigation ID to verify.
        #[arg(short, long)]
        investigation_id: String,
    },
}

/// Print the ORACLE startup banner to the terminal.
fn print_banner() {
    eprintln!(
        r#"
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║    ██████╗ ██████╗  █████╗  ██████╗██╗     ███████╗       ║
  ║   ██╔═══██╗██╔══██╗██╔══██╗██╔════╝██║     ██╔════╝       ║
  ║   ██║   ██║██████╔╝███████║██║     ██║     █████╗         ║
  ║   ██║   ██║██╔══██╗██╔══██║██║     ██║     ██╔══╝         ║
  ║   ╚██████╔╝██║  ██║██║  ██║╚██████╗███████╗███████╗       ║
  ║    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚══════╝       ║
  ║                                                           ║
  ║   Android Network Forensics Platform   v{:<17} ║
  ║   All operations are cryptographically audited.           ║
  ║                                                           ║
  ╚═══════════════════════════════════════════════════════════╝
"#,
        env!("CARGO_PKG_VERSION")
    );
}

/// Initialize the tracing subscriber for structured logging.
///
/// Respects the `ORACLE_LOG` environment variable if set, otherwise
/// uses the log level from the configuration file.
fn init_tracing(log_level: &str, verbose: bool) {
    let filter = if verbose {
        "debug".to_string()
    } else {
        std::env::var("ORACLE_LOG").unwrap_or_else(|_| log_level.to_string())
    };

    let subscriber = fmt()
        .with_env_filter(
            EnvFilter::try_new(&filter).unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set global tracing subscriber");
}

/// Load the ORACLE configuration from the specified path or defaults.
///
/// Resolution order:
/// 1. Explicit `--config` path (error if not found)
/// 2. `config/default.toml` in the current working directory
/// 3. Built-in default configuration
fn load_config(config_path: Option<&PathBuf>) -> Result<oracle_core::OracleConfig> {
    if let Some(path) = config_path {
        info!(path = %path.display(), "Loading configuration from explicit path");
        oracle_core::OracleConfig::load_from_file(path)
            .context(format!("Failed to load config from {}", path.display()))
    } else {
        let default_path = PathBuf::from("config/default.toml");
        if default_path.exists() {
            info!("Loading configuration from config/default.toml");
            oracle_core::OracleConfig::load_from_file(&default_path)
                .context("Failed to load config from config/default.toml")
        } else {
            info!("No configuration file found, using built-in defaults");
            let base_dir = std::env::current_dir()
                .context("Failed to determine current working directory")?;
            Ok(oracle_core::OracleConfig::default_config(&base_dir))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load configuration before printing the banner so we can
    // fail fast on configuration errors.
    let config = load_config(cli.config.as_ref())?;

    // Initialize tracing with the resolved log level.
    init_tracing(&config.general.log_level, cli.verbose);

    print_banner();

    info!(
        organization = %config.general.organization_name,
        investigations_dir = %config.general.investigations_dir.display(),
        "ORACLE initialized"
    );

    match cli.command {
        Commands::NewInvestigation {
            case_name,
            examiner,
            description,
        } => {
            info!(
                case_name = %case_name,
                examiner = %examiner,
                description = ?description,
                "Creating new investigation"
            );
            // Investigation creation will be implemented in a future milestone.
            // For now, confirm the command was parsed correctly.
            eprintln!("Investigation creation is not yet implemented.");
            eprintln!("  Case:     {}", case_name);
            eprintln!("  Examiner: {}", examiner);
            if let Some(desc) = description {
                eprintln!("  Notes:    {}", desc);
            }
        }
        Commands::Ingest {
            investigation_id,
            source,
        } => {
            info!(
                investigation_id = %investigation_id,
                source = %source,
                "Starting artifact ingestion"
            );
            // Ingestion pipeline will be implemented in a future milestone.
            eprintln!("Artifact ingestion is not yet implemented.");
            eprintln!("  Investigation: {}", investigation_id);
            eprintln!("  Source:         {}", source);
        }
        Commands::Verify { investigation_id } => {
            info!(
                investigation_id = %investigation_id,
                "Starting integrity verification"
            );
            // Integrity verification will be implemented in a future milestone.
            eprintln!("Integrity verification is not yet implemented.");
            eprintln!("  Investigation: {}", investigation_id);
        }
    }

    info!("ORACLE shutting down cleanly");
    Ok(())
}
