#[cfg(target_os = "linux")]
pub mod capabilities;
#[cfg(target_os = "linux")]
pub mod landlock;
#[cfg(target_os = "linux")]
pub mod seccomp;

pub mod error;

pub use error::{Result, SecurityError};
use std::path::Path;

/// Check if the process has all required capabilities
pub fn check_capabilities() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        capabilities::check_required_capabilities()?;
    }

    #[cfg(not(target_os = "linux"))]
    {
        tracing::debug!("Capability checking is only available on Linux");
    }

    Ok(())
}

pub fn apply_restrictions(db_path: &Path, log_path: Option<&Path>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Apply landlock restrictions
        landlock::apply_landlock_rules(db_path, log_path)?;

        // Apply seccomp filters
        seccomp::apply_seccomp_filters()?;
    }

    #[cfg(not(target_os = "linux"))]
    {
        tracing::warn!("Security restrictions are only available on Linux");
        let _ = (db_path, log_path); // Avoid unused variable warnings
    }

    Ok(())
}
