use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DatabaseError {
    // Connection errors
    #[error("Failed to connect to database at {path}: {reason}")]
    ConnectionFailed {
        path: PathBuf,
        reason: String,
        #[source]
        source: sqlx::Error,
    },

    #[error("Database connection pool exhausted (max connections: {max})")]
    PoolExhausted { max: usize },

    // Transaction errors
    #[error("Transaction {id} failed: {reason}")]
    TransactionFailed {
        id: String,
        reason: String,
        operations_completed: usize,
        operations_failed: usize,
    },

    #[error("Transaction {id} rollback failed: {reason}")]
    RollbackFailed {
        id: String,
        reason: String,
        #[source]
        source: sqlx::Error,
    },

    #[error("Deadlock detected in transaction {id} after {duration:?}")]
    Deadlock {
        id: String,
        duration: std::time::Duration,
        conflicting_resource: Option<String>,
    },

    // Query errors
    #[error("Query failed: {query_type} - {reason}")]
    QueryFailed {
        query_type: String,
        reason: String,
        query: Option<String>,
        parameters: Option<String>,
        #[source]
        source: sqlx::Error,
    },

    #[error("No rows returned for {query_type} with {criteria}")]
    NotFound {
        query_type: String,
        criteria: String,
    },

    #[error("Constraint violation: {constraint} - {details}")]
    ConstraintViolation {
        constraint: String,
        details: String,
        table: String,
        column: Option<String>,
    },

    // Schema errors
    #[error("Schema migration failed from version {from} to {to}: {reason}")]
    MigrationFailed {
        from: u32,
        to: u32,
        reason: String,
        rollback_successful: bool,
    },

    #[error("Schema version mismatch: expected {expected}, found {found}")]
    VersionMismatch { expected: u32, found: u32 },

    // Data integrity errors
    #[error("Data integrity check failed for {table}: {reason}")]
    IntegrityCheckFailed {
        table: String,
        reason: String,
        affected_rows: usize,
    },

    #[error("Duplicate entry for {table}.{column}: {value}")]
    DuplicateEntry {
        table: String,
        column: String,
        value: String,
    },

    // Resource errors
    #[error("Database locked after {duration:?} (holder: {holder:?})")]
    DatabaseLocked {
        duration: std::time::Duration,
        holder: Option<String>,
    },

    #[error(
        "Database disk space exhausted: {available} bytes available, {required} bytes required"
    )]
    DiskSpaceExhausted { available: u64, required: u64 },

    // Serialization errors
    #[error("Failed to serialize {data_type} for storage: {reason}")]
    SerializationFailed {
        data_type: String,
        reason: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Failed to deserialize {data_type} from storage: {reason}")]
    DeserializationFailed {
        data_type: String,
        reason: String,
        column: String,
        row_id: Option<i64>,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    // Backup/Restore errors
    #[error("Database backup failed to {destination}: {reason}")]
    BackupFailed {
        destination: PathBuf,
        reason: String,
        progress: f32,
    },

    #[error("Database restore failed from {source_path}: {reason}")]
    RestoreFailed {
        source_path: PathBuf,
        reason: String,
        tables_restored: usize,
        tables_failed: usize,
    },
}

impl DatabaseError {
    // Helper constructors
    pub fn connection_failed(
        path: PathBuf,
        reason: impl Into<String>,
        source: sqlx::Error,
    ) -> Self {
        Self::ConnectionFailed {
            path,
            reason: reason.into(),
            source,
        }
    }

    pub fn query_failed(
        query_type: impl Into<String>,
        reason: impl Into<String>,
        source: sqlx::Error,
    ) -> Self {
        Self::QueryFailed {
            query_type: query_type.into(),
            reason: reason.into(),
            query: None,
            parameters: None,
            source,
        }
    }

    pub fn query_failed_with_details(
        query_type: impl Into<String>,
        reason: impl Into<String>,
        query: impl Into<String>,
        parameters: impl Into<String>,
        source: sqlx::Error,
    ) -> Self {
        Self::QueryFailed {
            query_type: query_type.into(),
            reason: reason.into(),
            query: Some(query.into()),
            parameters: Some(parameters.into()),
            source,
        }
    }

    pub fn not_found(query_type: impl Into<String>, criteria: impl Into<String>) -> Self {
        Self::NotFound {
            query_type: query_type.into(),
            criteria: criteria.into(),
        }
    }

    pub fn constraint_violation(
        constraint: impl Into<String>,
        details: impl Into<String>,
        table: impl Into<String>,
    ) -> Self {
        Self::ConstraintViolation {
            constraint: constraint.into(),
            details: details.into(),
            table: table.into(),
            column: None,
        }
    }

    pub fn duplicate_entry(
        table: impl Into<String>,
        column: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self::DuplicateEntry {
            table: table.into(),
            column: column.into(),
            value: value.into(),
        }
    }

    pub fn database_locked(duration: std::time::Duration) -> Self {
        Self::DatabaseLocked {
            duration,
            holder: None,
        }
    }

    pub fn transaction_failed(
        id: impl Into<String>,
        reason: impl Into<String>,
        completed: usize,
        failed: usize,
    ) -> Self {
        Self::TransactionFailed {
            id: id.into(),
            reason: reason.into(),
            operations_completed: completed,
            operations_failed: failed,
        }
    }

    // Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::DatabaseLocked { .. } | Self::Deadlock { .. } | Self::PoolExhausted { .. }
        )
    }

    // Get suggested retry delay
    pub fn retry_delay(&self) -> Option<std::time::Duration> {
        match self {
            Self::DatabaseLocked { .. } => Some(std::time::Duration::from_millis(100)),
            Self::Deadlock { .. } => Some(std::time::Duration::from_millis(250)),
            Self::PoolExhausted { .. } => Some(std::time::Duration::from_secs(1)),
            _ => None,
        }
    }
}
