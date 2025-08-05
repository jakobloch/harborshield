use std::ffi::OsString;
use std::io::Error as IoError;
use std::string::FromUtf8Error;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, NftablesError>;

#[derive(Error, Debug)]
pub enum NftablesError {
    #[error("Failed to execute nftables command '{}'", program.to_string_lossy())]
    NftExecution {
        program: OsString,
        #[source]
        inner: IoError,
    },

    #[error("Invalid UTF-8 output from nftables command '{}'", program.to_string_lossy())]
    NftOutputEncoding {
        program: OsString,
        #[source]
        inner: FromUtf8Error,
    },

    #[error("Invalid JSON response from nftables")]
    NftInvalidJson(#[source] serde_json::Error),

    #[error("nftables command '{}' failed: {hint}", program.to_string_lossy())]
    NftFailed {
        program: OsString,
        hint: String,
        stdout: String,
        stderr: String,
    },

    #[error("Chain '{chain}' not found in table '{table}'")]
    ChainNotFound { table: String, chain: String },

    #[error("Table '{table}' not found")]
    TableNotFound { table: String },

    #[error("Rule not found: {description}")]
    RuleNotFound { description: String },

    #[error("Permission denied: {context}")]
    PermissionDenied { context: String },

    #[error("Transaction failed: {message}")]
    TransactionFailed { message: String },

    #[error("Invalid rule syntax: {rule}")]
    InvalidRuleSyntax { rule: String, reason: String },

    #[error("Lock acquisition failed for nftables operation")]
    LockFailed,

    #[error("nftables service not available: {reason}")]
    ServiceUnavailable { reason: String },

    #[error("Rollback failed: {reason}")]
    RollbackFailed { reason: String },

    #[error("Operation timeout: {operation}")]
    Timeout { operation: String },
}

impl NftablesError {
    pub fn execution(program: impl Into<OsString>, error: IoError) -> Self {
        Self::NftExecution {
            program: program.into(),
            inner: error,
        }
    }

    pub fn encoding(program: impl Into<OsString>, error: FromUtf8Error) -> Self {
        Self::NftOutputEncoding {
            program: program.into(),
            inner: error,
        }
    }

    pub fn invalid_json(error: serde_json::Error) -> Self {
        Self::NftInvalidJson(error)
    }

    pub fn command_failed(
        program: impl Into<OsString>,
        hint: impl Into<String>,
        stdout: impl Into<String>,
        stderr: impl Into<String>,
    ) -> Self {
        Self::NftFailed {
            program: program.into(),
            hint: hint.into(),
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    pub fn chain_not_found(table: impl Into<String>, chain: impl Into<String>) -> Self {
        Self::ChainNotFound {
            table: table.into(),
            chain: chain.into(),
        }
    }

    pub fn table_not_found(table: impl Into<String>) -> Self {
        Self::TableNotFound {
            table: table.into(),
        }
    }

    pub fn rule_not_found(description: impl Into<String>) -> Self {
        Self::RuleNotFound {
            description: description.into(),
        }
    }

    pub fn permission_denied(context: impl Into<String>) -> Self {
        Self::PermissionDenied {
            context: context.into(),
        }
    }

    pub fn transaction_failed(message: impl Into<String>) -> Self {
        Self::TransactionFailed {
            message: message.into(),
        }
    }

    pub fn invalid_rule(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidRuleSyntax {
            rule: rule.into(),
            reason: reason.into(),
        }
    }

    pub fn lock_failed() -> Self {
        Self::LockFailed
    }

    pub fn service_unavailable(reason: impl Into<String>) -> Self {
        Self::ServiceUnavailable {
            reason: reason.into(),
        }
    }

    pub fn rollback_failed(reason: impl Into<String>) -> Self {
        Self::RollbackFailed {
            reason: reason.into(),
        }
    }

    pub fn timeout(operation: impl Into<String>) -> Self {
        Self::Timeout {
            operation: operation.into(),
        }
    }

    pub fn is_permission_error(&self) -> bool {
        matches!(self, Self::PermissionDenied { .. })
            || matches!(self, Self::NftFailed { stderr, .. } if stderr.contains("Operation not permitted"))
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::LockFailed | Self::Timeout { .. } | Self::ServiceUnavailable { .. }
        )
    }

    pub fn exit_code(&self) -> Option<i32> {
        match self {
            Self::NftFailed { stderr, .. } => {
                if stderr.contains("Operation not permitted") {
                    Some(1)
                } else if stderr.contains("No such") {
                    Some(2)
                } else {
                    Some(3)
                }
            }
            _ => None,
        }
    }
}

impl From<nftables::helper::NftablesError> for NftablesError {
    fn from(err: nftables::helper::NftablesError) -> Self {
        match err {
            nftables::helper::NftablesError::NftExecution { program, inner } => {
                Self::execution(program, inner)
            }
            nftables::helper::NftablesError::NftOutputEncoding { program, inner } => {
                Self::encoding(program, inner)
            }
            nftables::helper::NftablesError::NftInvalidJson(e) => Self::invalid_json(e),
            nftables::helper::NftablesError::NftFailed {
                program,
                hint,
                stdout,
                stderr,
            } => Self::command_failed(program, hint, stdout, stderr),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_conversions() {
        let nft_err = nftables::helper::NftablesError::NftFailed {
            program: OsString::from("nft"),
            hint: "Test hint".to_string(),
            stdout: "Test stdout".to_string(),
            stderr: "Operation not permitted".to_string(),
        };

        let our_err: NftablesError = nft_err.into();
        assert!(our_err.is_permission_error());
        assert_eq!(our_err.exit_code(), Some(1));
    }

    #[test]
    fn test_error_helpers() {
        let err = NftablesError::permission_denied("test context");
        assert!(err.is_permission_error());
        assert!(!err.is_recoverable());

        let err = NftablesError::timeout("test operation");
        assert!(err.is_recoverable());
        assert!(!err.is_permission_error());

        let err = NftablesError::service_unavailable("nftables not running");
        assert!(err.is_recoverable());
    }
}
