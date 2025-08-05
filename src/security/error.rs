use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Landlock error: {message}")]
    Landlock {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Seccomp error: {message}")]
    Seccomp {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Security feature not supported: {feature}")]
    NotSupported { feature: String },

    #[error("Invalid security configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Failed to apply security restrictions: {0}")]
    ApplicationFailed(String),

    #[error("File access error: {path}")]
    FileAccess {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Ruleset creation failed: {0}")]
    RulesetCreation(String),

    #[error("Rule addition failed: {rule}")]
    RuleAddition {
        rule: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error(
        "Missing capability: {capability} in {capability_set} set\n\nRemediation:\n{remediation}"
    )]
    MissingCapability {
        capability: String,
        capability_set: String,
        remediation: String,
    },

    #[error("Capability check failed for {capability}: {message}")]
    CapabilityCheck { capability: String, message: String },
}

impl SecurityError {
    pub fn landlock<E>(message: impl Into<String>, source: Option<E>) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Landlock {
            message: message.into(),
            source: source.map(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
        }
    }

    pub fn seccomp<E>(message: impl Into<String>, source: Option<E>) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Seccomp {
            message: message.into(),
            source: source.map(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
        }
    }

    pub fn file_access(path: impl Into<String>, source: std::io::Error) -> Self {
        Self::FileAccess {
            path: path.into(),
            source,
        }
    }

    pub fn rule_addition<E>(rule: impl Into<String>, source: Option<E>) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::RuleAddition {
            rule: rule.into(),
            source: source.map(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
        }
    }
}

pub type Result<T> = std::result::Result<T, SecurityError>;
