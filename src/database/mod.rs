pub mod error;
pub mod models;
pub mod operations;

#[cfg(test)]
mod tests;

use crate::{Error, Result};
use bon::{Builder, bon};
use sqlx::{Sqlite, SqlitePool, Transaction};
use std::path::Path;

pub use models::*;
pub use operations::{DbOp, DbOpResult, execute_op};

/// Database connection pool
pub struct DB {
    pool: SqlitePool,
}
#[bon]
impl DB {
    #[builder]
    /// Create a new database connection pool
    pub async fn new(db_path: &Path) -> Result<Self> {
        // Build database URL
        let db_url = format!("sqlite:{}?mode=rwc", db_path.display());

        // Create pool with configuration
        let pool = SqlitePool::connect_with(
            db_url
                .parse::<sqlx::sqlite::SqliteConnectOptions>()
                .map_err(|e| Error::Database(format!("Failed to parse database URL: {}", e)))?
                .create_if_missing(true)
                .foreign_keys(true)
                .busy_timeout(std::time::Duration::from_secs(1))
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal),
        )
        .await
        .map_err(|e| Error::Database(format!("Failed to create database pool: {}", e)))?;

        // Run migrations
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| Error::Database(format!("Failed to run migrations: {}", e)))?;

        Ok(Self { pool })
    }

    pub fn transaction(&mut self) -> TransactionBuilder<'_> {
        TransactionBuilder { db: self }
    }

    /// Get a reference to the connection pool
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Execute a single database operation
    pub async fn execute(&self, op: &DbOp<'_>) -> Result<DbOpResult> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Error::Database(format!("Failed to begin transaction: {}", e)))?;

        let result = execute_op(&mut tx, op).await?;

        tx.commit()
            .await
            .map_err(|e| Error::Database(format!("Failed to commit transaction: {}", e)))?;

        Ok(result)
    }

    /// Close the database pool
    pub async fn close(self) -> Result<()> {
        self.pool.close().await;
        Ok(())
    }
}

pub struct TransactionBuilder<'db> {
    db: &'db mut DB,
}

#[derive(Builder)]
pub struct ExecutedTransaction<R> {
    tx: Transaction<'static, Sqlite>,
    result: R,
}

pub struct CommittedTransaction<R> {
    result: R,
}

impl<'db> TransactionBuilder<'db> {
    pub async fn execute_ops(
        self,
        ops: &[DbOp<'_>],
    ) -> Result<ExecutedTransaction<Vec<DbOpResult>>> {
        let mut tx = self
            .db
            .pool
            .begin()
            .await
            .map_err(|e| Error::Database(format!("{}", e)))?;

        let mut results = Vec::new();

        for op in ops {
            let result = execute_op(&mut tx, op).await?;
            results.push(result);
        }

        Ok(ExecutedTransaction {
            tx,
            result: results,
        })
    }
}

impl<R> ExecutedTransaction<R> {
    pub async fn commit(self) -> Result<CommittedTransaction<R>> {
        self.tx
            .commit()
            .await
            .map_err(|e| Error::Database(format!("{}", e)))?;
        Ok(CommittedTransaction {
            result: self.result,
        })
    }

    pub async fn rollback(self) -> Result<()> {
        // Transaction auto-rolls back on drop
        Ok(())
    }

    pub async fn and_then<F, Fut, T>(mut self, f: F) -> Result<ExecutedTransaction<T>>
    where
        F: FnOnce(R, &mut sqlx::Transaction<'_, Sqlite>) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
        T: Send + 'static,
    {
        let new_result = f(self.result, &mut self.tx).await?;

        Ok(ExecutedTransaction {
            tx: self.tx,
            result: new_result,
        })
    }

    pub fn result(&self) -> &R {
        &self.result
    }
}

impl<R> CommittedTransaction<R> {
    pub fn into_result(self) -> R {
        self.result
    }

    pub fn result(&self) -> &R {
        &self.result
    }
}
