use clap::Parser;
use harborshield::{check_kernel_version, parse_duration, shutdown_signal, RuleManager, VERSION};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[command(author, version, about = "Automate management of firewall rules for Docker containers", long_about = None)]
struct Args {
    /// Remove all firewall rules created by harborshield
    #[arg(long)]
    clear: bool,

    /// Directory to store state in
    #[arg(short = 'd', long, default_value = ".")]
    data_dir: PathBuf,

    /// Enable debug logging
    #[arg(long)]
    debug: bool,

    /// Path to log to (use "stdout" or "stderr" for console output)
    #[arg(short = 'l', long, default_value = "stdout")]
    log_path: String,

    /// Timeout for Docker API requests
    #[arg(short = 't', long, default_value = "10s", value_parser = parse_duration)]
    timeout: Duration,

    /// Enable health check server on specified address (e.g., "127.0.0.1:8080")
    #[arg(long)]
    health_server: Option<String>,

    /// Print version and build information and exit
    #[arg(long = "version-info")]
    version_info: bool,
}

#[tokio::main]
async fn main() {
    // Load .env file if it exists
    if let Err(e) = dotenvy::dotenv() {
        // It's ok if .env doesn't exist, but log other errors
        if e.not_found() {
            // Silent - .env is optional
        } else {
            eprintln!("Error loading .env file: {}", e);
        }
    }

    let args = Args::parse();

    if args.version_info {
        println!("harborshield {}", VERSION);
        // Note: RUSTC_VERSION would need to be set at build time
        println!("harborshield-rust (Rust port)");
        return;
    }

    // Initialize logging
    let env_filter = if args.debug {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    let subscriber = tracing_subscriber::registry().with(env_filter);

    if args.log_path == "stdout" || args.log_path == "stderr" {
        let subscriber = subscriber.with(fmt::layer());
        tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set tracing subscriber");
    } else {
        let file_appender = tracing_appender::rolling::never("", &args.log_path);
        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
        let subscriber = subscriber.with(fmt::layer().with_writer(non_blocking));
        tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set tracing subscriber");
    }

    // Check kernel version
    check_kernel_version();

    // Check for required capabilities
    #[cfg(target_os = "linux")]
    {
        if let Err(e) = harborshield::security::check_capabilities() {
            error!("Capability check failed: {}", e);

            // The error message already includes remediation information
            // from the SecurityError::MissingCapability Display implementation

            std::process::exit(1);
        }
        info!("All required capabilities are present");
    }

    // Get absolute path for data directory
    let data_dir = match args.data_dir.canonicalize() {
        Ok(path) => path,
        Err(e) => {
            error!("Failed to get absolute path for data directory: {}", e);
            std::process::exit(1);
        }
    };

    let db_path = data_dir.join("db.sqlite");

    // Create rule manager with optional health server
    let rule_manager = match RuleManager::builder()
        .db_path(&db_path)
        .timeout(args.timeout)
        .maybe_health_server_addr(args.health_server.as_deref())
        .build()
        .await
    {
        Ok(manager) => manager,
        Err(e) => {
            error!("Failed to initialize rule manager: {}", e);
            std::process::exit(1);
        }
    };

    // Apply security restrictions
    let log_path = if args.log_path != "stdout" && args.log_path != "stderr" {
        Some(PathBuf::from(&args.log_path))
    } else {
        None
    };

    #[cfg(target_os = "linux")]
    {
        // Apply security restrictions
        if let Err(e) = harborshield::security::apply_restrictions(&db_path, log_path.as_deref()) {
            error!("Failed to apply security restrictions: {}", e);
            std::process::exit(1);
        }
    }

    // Handle clear mode
    if args.clear {
        info!("Clearing all harborshield rules");
        if let Err(e) = rule_manager.clear().await {
            error!("Failed to clear rules: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // Log version info
    info!("Starting harborshield v{}", VERSION);

    // Start the rule manager
    let rule_manager = match rule_manager.start().await {
        Ok(started_manager) => started_manager,
        Err(e) => {
            error!("Failed to start rule manager: {}", e);
            std::process::exit(1);
        }
    };

    // Wait for shutdown signal
    shutdown_signal().await;
    info!("Shutting down");

    // Stop the rule manager
    rule_manager.stop().await;
}
