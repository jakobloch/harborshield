pub mod database;
pub mod docker;
pub mod error;
pub mod manager;
pub mod nftables;

#[cfg(target_os = "linux")]
pub mod security;
pub mod server;

pub use error::{Error, Result};
pub use manager::RuleManager;
use std::time::Duration;
use tokio::signal;
use tracing::{error, warn};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn parse_duration(s: &str) -> std::result::Result<Duration, String> {
    let s = s.trim();

    if let Some(stripped) = s.strip_suffix("ms") {
        stripped
            .parse::<u64>()
            .map(Duration::from_millis)
            .map_err(|e| format!("Invalid milliseconds: {}", e))
    } else if let Some(stripped) = s.strip_suffix('s') {
        stripped
            .parse::<u64>()
            .map(Duration::from_secs)
            .map_err(|e| format!("Invalid seconds: {}", e))
    } else if let Some(stripped) = s.strip_suffix('m') {
        stripped
            .parse::<u64>()
            .map(|m| Duration::from_secs(m * 60))
            .map_err(|e| format!("Invalid minutes: {}", e))
    } else {
        // Default to seconds if no suffix
        s.parse::<u64>()
            .map(Duration::from_secs)
            .map_err(|e| format!("Invalid duration: {}", e))
    }
}

pub async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

pub fn check_kernel_version() {
    use std::process::Command;

    let output = match Command::new("uname").arg("-r").output() {
        Ok(output) => output,
        Err(e) => {
            error!("Failed to check kernel version: {}", e);
            return;
        }
    };

    if !output.status.success() {
        error!("Failed to get kernel version");
        return;
    }

    let version = String::from_utf8_lossy(&output.stdout);
    let version = version.trim();

    // Parse major.minor version
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() >= 2 {
        if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
            if major < 5 || (major == 5 && minor < 10) {
                warn!(
                    "Current kernel version {} is unsupported, 5.10 or greater is required; harborshield will probably not work correctly",
                    version
                );
            }
        }
    }
}
