use caps::{CapSet, Capability};
use tracing::{debug, warn};

use super::{Result, SecurityError};

/// Check if the current process has the required capabilities
pub fn check_required_capabilities() -> Result<()> {
    debug!("Checking for required capabilities");

    // Check for CAP_NET_ADMIN capability
    if let Err(e) = check_capability(Capability::CAP_NET_ADMIN) {
        // Log current capabilities for debugging
        if let Ok(cap_list) = list_current_capabilities() {
            warn!("Current process capabilities:\n{}", cap_list);
        }
        return Err(e);
    }

    debug!("All required capabilities are present");
    Ok(())
}

/// Check if a specific capability is available in both permitted and effective sets
fn check_capability(cap: Capability) -> Result<()> {
    let cap_name = format!("{:?}", cap);

    // Check if the capability is in the permitted set
    let has_permitted = caps::has_cap(None, CapSet::Permitted, cap).map_err(|e| {
        SecurityError::CapabilityCheck {
            capability: cap_name.clone(),
            message: format!("Failed to check permitted capabilities: {}", e),
        }
    })?;

    if !has_permitted {
        return Err(SecurityError::MissingCapability {
            capability: cap_name.clone(),
            capability_set: "Permitted".to_string(),
            remediation: format!(
                "Grant the capability using: sudo setcap 'cap_net_admin=+ep' /path/to/harborshield\n\
                 Or run with appropriate privileges (e.g., as root or with sudo)"
            ),
        });
    }

    // Check if the capability is in the effective set
    let has_effective = caps::has_cap(None, CapSet::Effective, cap).map_err(|e| {
        SecurityError::CapabilityCheck {
            capability: cap_name.clone(),
            message: format!("Failed to check effective capabilities: {}", e),
        }
    })?;

    if !has_effective {
        return Err(SecurityError::MissingCapability {
            capability: cap_name.clone(),
            capability_set: "Effective".to_string(),
            remediation: format!(
                "The capability is in the permitted set but not in the effective set.\n\
                 This might be due to the process dropping privileges.\n\
                 Ensure the capability is preserved when dropping privileges."
            ),
        });
    }

    debug!(
        "Capability {} is present in both permitted and effective sets",
        cap_name
    );
    Ok(())
}

/// Get a human-readable list of all current capabilities
pub fn list_current_capabilities() -> Result<String> {
    let mut output = String::new();

    // List all capability sets
    let sets = [
        ("Permitted", CapSet::Permitted),
        ("Effective", CapSet::Effective),
        ("Inheritable", CapSet::Inheritable),
    ];

    for (name, set) in &sets {
        match caps::read(None, *set) {
            Ok(caps) => {
                output.push_str(&format!("{} capabilities: ", name));
                if caps.is_empty() {
                    output.push_str("(none)");
                } else {
                    let cap_names: Vec<String> = caps.iter().map(|c| format!("{:?}", c)).collect();
                    output.push_str(&cap_names.join(", "));
                }
                output.push('\n');
            }
            Err(e) => {
                output.push_str(&format!("{} capabilities: (error reading: {})\n", name, e));
            }
        }
    }

    Ok(output)
}
