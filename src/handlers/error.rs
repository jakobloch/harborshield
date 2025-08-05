use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ManagerError {
    // Initialization errors
    #[error("Manager initialization failed: {reason}")]
    InitializationFailed {
        reason: String,
        component: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Health server failed to start on {address}: {reason}")]
    HealthServerStartFailed {
        address: String,
        reason: String,
        #[source]
        source: std::io::Error,
    },

    // Rule management errors
    #[error("Rule application failed for container '{container_id}': {reason}")]
    RuleApplicationFailed {
        container_id: String,
        reason: String,
        rule_type: String,
        rule_details: Option<String>,
    },

    #[error("Rule removal failed for container '{container_id}': {reason}")]
    RuleRemovalFailed {
        container_id: String,
        reason: String,
        rules_removed: usize,
        rules_failed: usize,
    },

    #[error("Rule conflict detected: {description}")]
    RuleConflict {
        description: String,
        existing_rule: String,
        new_rule: String,
        resolution: Option<String>,
    },

    #[error("Rule parsing failed for container '{container_id}': {reason}")]
    RuleParsingFailed {
        container_id: String,
        reason: String,
        raw_rules: String,
        line: Option<usize>,
    },

    // Synchronization errors
    #[error("Container sync failed: {reason}")]
    ContainerSyncFailed {
        reason: String,
        containers_synced: usize,
        containers_failed: usize,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("State inconsistency detected: {description}")]
    StateInconsistency {
        description: String,
        expected_state: String,
        actual_state: String,
        affected_containers: Vec<String>,
    },

    // Event handling errors
    #[error("Event processing failed: {event_type} - {reason}")]
    EventProcessingFailed {
        event_type: String,
        reason: String,
        event_data: Option<String>,
        container_id: Option<String>,
    },

    #[error("Event stream lost: {reason}")]
    EventStreamLost {
        reason: String,
        duration_since_last_event: Duration,
        reconnect_attempts: u32,
    },

    // Cleanup errors
    #[error("Cleanup failed for container '{container_id}': {reason}")]
    CleanupFailed {
        container_id: String,
        reason: String,
        resources_cleaned: Vec<String>,
        resources_failed: Vec<String>,
    },

    #[error("Orphaned resources detected: {count} resources without containers")]
    OrphanedResources {
        count: usize,
        resource_types: Vec<String>,
        cleanup_attempted: bool,
        cleanup_successful: bool,
    },

    // Shutdown errors
    #[error("Shutdown timeout after {duration:?}: {pending_operations} operations pending")]
    ShutdownTimeout {
        duration: Duration,
        pending_operations: usize,
        forced: bool,
    },

    #[error("Graceful shutdown failed: {reason}")]
    GracefulShutdownFailed {
        reason: String,
        cleanup_completed: bool,
        state_saved: bool,
    },

    // Task management errors
    #[error("Task '{task_name}' failed: {reason}")]
    TaskFailed {
        task_name: String,
        reason: String,
        restart_attempted: bool,
        restart_count: u32,
    },

    #[error("Task spawn failed: {task_name} - {reason}")]
    TaskSpawnFailed { task_name: String, reason: String },

    // Metrics errors
    #[error("Metrics collection failed: {reason}")]
    MetricsCollectionFailed {
        reason: String,
        metric_type: String,
        last_successful_collection: Option<chrono::DateTime<chrono::Utc>>,
    },

    // Configuration errors
    #[error("Configuration reload failed: {reason}")]
    ConfigReloadFailed {
        reason: String,
        config_path: Option<String>,
        validation_errors: Vec<String>,
    },

    // Network management errors
    #[error("Network setup failed for container '{container_id}': {reason}")]
    NetworkSetupFailed {
        container_id: String,
        reason: String,
        network_id: Option<String>,
    },

    #[error("Network isolation breach detected: {description}")]
    NetworkIsolationBreach {
        description: String,
        source_container: String,
        target_container: String,
        blocked: bool,
    },
}

impl ManagerError {
    // Helper constructors
    pub fn initialization_failed(reason: impl Into<String>, component: impl Into<String>) -> Self {
        Self::InitializationFailed {
            reason: reason.into(),
            component: component.into(),
            source: None,
        }
    }

    pub fn rule_application_failed(
        container_id: impl Into<String>,
        reason: impl Into<String>,
        rule_type: impl Into<String>,
    ) -> Self {
        Self::RuleApplicationFailed {
            container_id: container_id.into(),
            reason: reason.into(),
            rule_type: rule_type.into(),
            rule_details: None,
        }
    }

    pub fn container_sync_failed(reason: impl Into<String>, synced: usize, failed: usize) -> Self {
        Self::ContainerSyncFailed {
            reason: reason.into(),
            containers_synced: synced,
            containers_failed: failed,
            source: None,
        }
    }

    pub fn event_processing_failed(
        event_type: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::EventProcessingFailed {
            event_type: event_type.into(),
            reason: reason.into(),
            event_data: None,
            container_id: None,
        }
    }

    pub fn cleanup_failed(container_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::CleanupFailed {
            container_id: container_id.into(),
            reason: reason.into(),
            resources_cleaned: Vec::new(),
            resources_failed: Vec::new(),
        }
    }

    pub fn task_failed(task_name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::TaskFailed {
            task_name: task_name.into(),
            reason: reason.into(),
            restart_attempted: false,
            restart_count: 0,
        }
    }

    // Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::EventStreamLost { .. }
                | Self::TaskFailed {
                    restart_attempted: true,
                    ..
                }
                | Self::MetricsCollectionFailed { .. }
        )
    }

    // Check if error is critical (requires immediate attention)
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::StateInconsistency { .. }
                | Self::NetworkIsolationBreach { .. }
                | Self::InitializationFailed { .. }
                | Self::ShutdownTimeout { .. }
        )
    }

    // Get suggested action for the error
    pub fn suggested_action(&self) -> Option<&str> {
        match self {
            Self::EventStreamLost { .. } => {
                Some("Check Docker daemon connectivity and restart event monitoring")
            }
            Self::StateInconsistency { .. } => {
                Some("Run full synchronization to restore consistency")
            }
            Self::OrphanedResources { .. } => {
                Some("Run cleanup command to remove orphaned resources")
            }
            Self::ConfigReloadFailed { .. } => {
                Some("Check configuration file syntax and permissions")
            }
            Self::NetworkIsolationBreach { .. } => {
                Some("Review network policies and container configurations")
            }
            _ => None,
        }
    }
}
