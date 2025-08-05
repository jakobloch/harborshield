use super::error::{Result, SecurityError};
use landlock::{ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus};
use std::path::Path;
use tracing::{info, warn};

pub fn apply_landlock_rules(db_path: &Path, log_path: Option<&Path>) -> Result<()> {
    let abi = ABI::V1;

    let mut ruleset = match Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| {
            SecurityError::landlock(format!("Failed to create landlock ruleset: {}", e), Some(e))
        })?
        .create()
    {
        Ok(r) => r,
        Err(e) => {
            return Err(SecurityError::landlock(
                format!("Failed to create landlock ruleset: {}", e),
                Some(e),
            ));
        }
    };

    // Allow read/write access to the database directory
    if let Some(db_dir) = db_path.parent() {
        if let Ok(dir_fd) = std::fs::File::open(db_dir) {
            ruleset = match ruleset.add_rule(landlock::PathBeneath::new(
                dir_fd,
                AccessFs::ReadDir | AccessFs::ReadFile | AccessFs::WriteFile,
            )) {
                Ok(r) => r,
                Err(e) => {
                    return Err(SecurityError::rule_addition(
                        format!("Failed to add landlock rule: {}", e),
                        Some(e),
                    ));
                }
            };
        }
    }

    // Allow access to database files
    let db_path_str = db_path.to_string_lossy();
    if let Ok(db_fd) = std::fs::File::open(db_path) {
        ruleset = match ruleset.add_rule(landlock::PathBeneath::new(
            db_fd,
            AccessFs::ReadFile | AccessFs::WriteFile,
        )) {
            Ok(r) => r,
            Err(e) => {
                return Err(SecurityError::rule_addition(
                    format!("Failed to add landlock rule: {}", e),
                    Some(e),
                ));
            }
        };
    }

    // Add rules for WAL and SHM files
    let wal_path_string = format!("{}-wal", db_path_str);
    let wal_path = Path::new(&wal_path_string);
    if wal_path.exists() {
        if let Ok(wal_fd) = std::fs::File::open(wal_path) {
            ruleset = match ruleset.add_rule(landlock::PathBeneath::new(
                wal_fd,
                AccessFs::ReadFile | AccessFs::WriteFile,
            )) {
                Ok(r) => r,
                Err(e) => {
                    return Err(SecurityError::rule_addition(
                        format!("Failed to add landlock rule: {}", e),
                        Some(e),
                    ));
                }
            };
        }
    }

    let shm_path_string = format!("{}-shm", db_path_str);
    let shm_path = Path::new(&shm_path_string);
    if shm_path.exists() {
        if let Ok(shm_fd) = std::fs::File::open(shm_path) {
            ruleset = match ruleset.add_rule(landlock::PathBeneath::new(
                shm_fd,
                AccessFs::ReadFile | AccessFs::WriteFile,
            )) {
                Ok(r) => r,
                Err(e) => {
                    return Err(SecurityError::rule_addition(
                        format!("Failed to add landlock rule: {}", e),
                        Some(e),
                    ));
                }
            };
        }
    }

    // Allow write access to log file if specified
    if let Some(log_path) = log_path {
        if let Ok(log_fd) = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(log_path)
        {
            ruleset =
                match ruleset.add_rule(landlock::PathBeneath::new(log_fd, AccessFs::WriteFile)) {
                    Ok(r) => r,
                    Err(e) => {
                        return Err(SecurityError::rule_addition(
                            format!("Failed to add landlock rule for log file: {}", e),
                            Some(e),
                        ));
                    }
                };
        }
    }

    // Allow read access to system files that Go's runtime might need
    let system_files = [
        "/etc/protocols",
        "/etc/services",
        "/etc/localtime",
        "/etc/nsswitch.conf",
        "/etc/resolv.conf",
        "/etc/hosts",
    ];

    // Allow execute access to nft binary (needed for nftables operations)
    let nft_paths = ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"];

    for nft_path in &nft_paths {
        let path = Path::new(nft_path);
        if path.exists() {
            if let Ok(nft_fd) = std::fs::File::open(path) {
                ruleset = match ruleset.add_rule(landlock::PathBeneath::new(
                    nft_fd,
                    AccessFs::ReadFile | AccessFs::Execute,
                )) {
                    Ok(r) => r,
                    Err(e) => {
                        return Err(SecurityError::rule_addition(
                            format!("Failed to add landlock rule for nft binary: {}", e),
                            Some(e),
                        ));
                    }
                };
                break; // Found and added nft, no need to check other paths
            }
        }
    }

    // Allow access to shared libraries and system files needed for process execution
    let execution_paths = [
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/usr/lib/x86_64-linux-gnu",
        "/lib/x86_64-linux-gnu",
        "/proc",
        "/dev/null",
        "/dev/urandom",
        "/dev/random",
        "/tmp",
        "/var/run",
        "/run",
        "/sys/fs/cgroup",
        "/etc/nftables",
        "/etc/nftables.conf",
        "/usr/share/nftables",
    ];

    for exec_path in &execution_paths {
        let path = Path::new(exec_path);
        if path.exists() {
            if let Ok(fd) = std::fs::File::open(path) {
                let access_rights =
                    if exec_path.starts_with("/lib") || exec_path.starts_with("/usr/lib") {
                        AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute
                    } else if exec_path == &"/tmp" {
                        AccessFs::ReadFile
                            | AccessFs::WriteFile
                            | AccessFs::ReadDir
                            | AccessFs::RemoveFile
                            | AccessFs::MakeReg
                    } else {
                        AccessFs::ReadFile | AccessFs::ReadDir
                    };

                ruleset = match ruleset.add_rule(landlock::PathBeneath::new(fd, access_rights)) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("Failed to add landlock rule for {}: {}", exec_path, e);
                        return Err(SecurityError::rule_addition(
                            format!("Failed to add landlock rule for {}: {}", exec_path, e),
                            Some(e),
                        ));
                    }
                };
            }
        }
    }

    // Build a vector of file descriptors and paths that exist
    let mut system_file_fds = Vec::new();
    for file in &system_files {
        let path = Path::new(file);
        if path.exists() {
            if let Ok(file_fd) = std::fs::File::open(path) {
                system_file_fds.push((file_fd, *file));
            }
        }
    }

    // Now add all the rules, handling errors appropriately
    for (file_fd, file_path) in system_file_fds {
        match ruleset.add_rule(landlock::PathBeneath::new(file_fd, AccessFs::ReadFile)) {
            Ok(r) => {
                ruleset = r;
            }
            Err(e) => {
                warn!("Failed to add landlock rule for {}: {}", file_path, e);
                // Since add_rule consumed the ruleset, we need to return an error
                return Err(SecurityError::rule_addition(
                    format!("Failed to add landlock rule for {}: {}", file_path, e),
                    Some(e),
                ));
            }
        }
    }

    // Apply the ruleset
    let status = ruleset.restrict_self().map_err(|e| {
        SecurityError::ApplicationFailed(format!("Failed to apply landlock rules: {}", e))
    })?;

    match status.ruleset {
        RulesetStatus::NotEnforced => {
            warn!("Landlock rules could not be enforced. Kernel support may be missing.");
        }
        RulesetStatus::PartiallyEnforced => {
            info!("Landlock rules partially enforced");
        }
        RulesetStatus::FullyEnforced => {
            info!("Landlock rules fully enforced");
        }
    }

    Ok(())
}
