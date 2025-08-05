use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DockerError {
    // Connection errors
    #[error("Failed to connect to Docker daemon at {endpoint}: {reason}")]
    ConnectionFailed {
        endpoint: String,
        reason: String,
        #[source]
        source: bollard::errors::Error,
    },

    #[error("Docker API version mismatch: expected {expected}, got {actual}")]
    ApiVersionMismatch { expected: String, actual: String },

    #[error("Docker daemon not responding after {duration:?}")]
    DaemonNotResponding { duration: Duration },

    #[error("TLS configuration error: {reason}")]
    TlsConfigError {
        reason: String,
        cert_path: Option<String>,
    },

    // Container operation errors
    #[error("Container operation failed for '{container_id}': {operation} - {reason}")]
    ContainerOperationFailed {
        container_id: String,
        operation: String,
        reason: String,
        #[source]
        source: Option<bollard::errors::Error>,
    },

    #[error("Container '{container_id}' not found")]
    ContainerNotFound { container_id: String },

    #[error("Container '{container_id}' already exists")]
    ContainerAlreadyExists { container_id: String },

    #[error(
        "Container '{container_id}' in wrong state for operation: expected {expected}, got {actual}"
    )]
    ContainerWrongState {
        container_id: String,
        expected: String,
        actual: String,
    },

    #[error("Container '{container_id}' start failed: {reason}")]
    ContainerStartFailed {
        container_id: String,
        reason: String,
        exit_code: Option<i32>,
    },

    #[error("Container '{container_id}' stop timeout after {duration:?}")]
    ContainerStopTimeout {
        container_id: String,
        duration: Duration,
    },

    // Network errors
    #[error("Network '{network_id}' not found")]
    NetworkNotFound { network_id: String },

    #[error("Failed to connect container '{container_id}' to network '{network_id}': {reason}")]
    NetworkConnectionFailed {
        container_id: String,
        network_id: String,
        reason: String,
    },

    #[error("Network '{network_id}' configuration error: {reason}")]
    NetworkConfigError { network_id: String, reason: String },

    #[error("IP address conflict in network '{network_id}': {ip} already assigned")]
    IpAddressConflict {
        network_id: String,
        ip: String,
        assigned_to: Option<String>,
    },

    #[error("IP address not found in network '{network_id}'")]
    IpAddressNotFound { network_id: String },

    // Image errors
    #[error("Image '{image}' not found")]
    ImageNotFound { image: String },

    #[error("Image pull failed for '{image}': {reason}")]
    ImagePullFailed {
        image: String,
        reason: String,
        registry: Option<String>,
    },

    #[error("Image build failed: {reason}")]
    ImageBuildFailed {
        reason: String,
        dockerfile_path: Option<String>,
        build_args: Option<String>,
    },

    // Volume errors
    #[error("Volume '{volume_name}' not found")]
    VolumeNotFound { volume_name: String },

    #[error("Volume mount failed for '{volume_name}' at '{mount_path}': {reason}")]
    VolumeMountFailed {
        volume_name: String,
        mount_path: String,
        reason: String,
    },

    // Resource errors
    #[error("Resource limit exceeded: {resource} - {details}")]
    ResourceLimitExceeded { resource: String, details: String },

    #[error("Insufficient disk space: {available} bytes available, {required} bytes required")]
    InsufficientDiskSpace { available: u64, required: u64 },

    #[error(
        "Memory limit exceeded for container '{container_id}': limit {limit} MB, requested {requested} MB"
    )]
    MemoryLimitExceeded {
        container_id: String,
        limit: u64,
        requested: u64,
    },

    // Event stream errors
    #[error("Docker event stream error: {reason}")]
    EventStreamError {
        reason: String,
        last_event_id: Option<String>,
    },

    #[error("Event stream disconnected after {duration:?}")]
    EventStreamDisconnected {
        duration: Duration,
        reconnect_attempts: u32,
    },

    // Label errors
    #[error("Invalid label format for container '{container_id}': {label} - {reason}")]
    InvalidLabel {
        container_id: String,
        label: String,
        reason: String,
    },

    #[error("Required label '{label}' missing on container '{container_id}'")]
    RequiredLabelMissing { container_id: String, label: String },

    // Permission errors
    #[error("Permission denied for Docker operation: {operation} - {details}")]
    PermissionDenied { operation: String, details: String },

    #[error("Docker socket permission error: {socket_path}")]
    SocketPermissionError { socket_path: String },

    // Timeout errors
    #[error("Docker operation timeout: {operation} exceeded {duration:?}")]
    OperationTimeout {
        operation: String,
        duration: Duration,
    },

    // Miscellaneous errors
    #[error("Docker configuration error: {reason}")]
    ConfigurationError { reason: String },

    #[error("Unsupported Docker feature: {feature} (minimum version: {min_version})")]
    UnsupportedFeature {
        feature: String,
        min_version: String,
    },
}

impl DockerError {
    // Helper constructors
    pub fn connection_failed(
        endpoint: impl Into<String>,
        reason: impl Into<String>,
        source: bollard::errors::Error,
    ) -> Self {
        Self::ConnectionFailed {
            endpoint: endpoint.into(),
            reason: reason.into(),
            source,
        }
    }

    pub fn container_operation_failed(
        container_id: impl Into<String>,
        operation: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::ContainerOperationFailed {
            container_id: container_id.into(),
            operation: operation.into(),
            reason: reason.into(),
            source: None,
        }
    }

    pub fn container_operation_failed_with_source(
        container_id: impl Into<String>,
        operation: impl Into<String>,
        reason: impl Into<String>,
        source: bollard::errors::Error,
    ) -> Self {
        Self::ContainerOperationFailed {
            container_id: container_id.into(),
            operation: operation.into(),
            reason: reason.into(),
            source: Some(source),
        }
    }

    pub fn container_not_found(container_id: impl Into<String>) -> Self {
        Self::ContainerNotFound {
            container_id: container_id.into(),
        }
    }

    pub fn network_not_found(network_id: impl Into<String>) -> Self {
        Self::NetworkNotFound {
            network_id: network_id.into(),
        }
    }

    pub fn image_not_found(image: impl Into<String>) -> Self {
        Self::ImageNotFound {
            image: image.into(),
        }
    }

    pub fn operation_timeout(operation: impl Into<String>, duration: Duration) -> Self {
        Self::OperationTimeout {
            operation: operation.into(),
            duration,
        }
    }

    pub fn invalid_label(
        container_id: impl Into<String>,
        label: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::InvalidLabel {
            container_id: container_id.into(),
            label: label.into(),
            reason: reason.into(),
        }
    }

    // Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::DaemonNotResponding { .. }
                | Self::EventStreamDisconnected { .. }
                | Self::OperationTimeout { .. }
                | Self::NetworkConnectionFailed { .. }
        )
    }

    // Get suggested retry delay
    pub fn retry_delay(&self) -> Option<Duration> {
        match self {
            Self::DaemonNotResponding { .. } => Some(Duration::from_secs(2)),
            Self::EventStreamDisconnected {
                reconnect_attempts, ..
            } => {
                // Exponential backoff based on reconnect attempts
                let delay = std::cmp::min(60, 2_u64.pow(*reconnect_attempts));
                Some(Duration::from_secs(delay))
            }
            Self::OperationTimeout { .. } => Some(Duration::from_secs(1)),
            Self::NetworkConnectionFailed { .. } => Some(Duration::from_millis(500)),
            _ => None,
        }
    }
}
