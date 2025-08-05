use sqlx::{Sqlite, Transaction, query, query_as};

use crate::{
    Error, Result,
    database::{Addr, ContainerAlias, ContainerIdentifiers, EstContainer, WaitingContainerRule},
};

/// Database operations that can be executed
#[derive(Debug, Clone)]
pub enum DbOp<'a> {
    // ContainerIdentifiers operations
    InsertContainer(&'a ContainerIdentifiers),
    ListContainers,
    GetContainer(&'a str),
    GetContainerByName(&'a str),
    DeleteContainer(&'a str),
    UpdateContainerName {
        id: &'a str,
        new_name: &'a str,
    },

    // Address operations
    InsertAddr(&'a Addr),
    GetAddrsByContainer(&'a str),
    DeleteAddrsByContainer(&'a str),

    // ContainerIdentifiers alias operations
    InsertContainerAlias(&'a ContainerAlias),
    GetContainerByAlias(&'a str),
    DeleteContainerAliases(&'a str),

    // Established container operations
    InsertEstContainer(&'a EstContainer),
    DeleteEstContainers(&'a str),

    // Waiting rule operations
    InsertWaitingRule(&'a WaitingContainerRule),
    GetWaitingRulesForContainer(&'a str),
    DeleteWaitingRules(&'a str),
    DeleteWaitingRule {
        src_container_id: &'a str,
        dst_container_name: &'a str,
    },
}

/// Result of a database operation
#[derive(Debug)]
pub enum DbOpResult {
    Unit,
    Containers(Vec<ContainerIdentifiers>),
    ContainerIdentifiers(Option<ContainerIdentifiers>),
    Addrs(Vec<Addr>),
    WaitingRules(Vec<WaitingContainerRule>),
}

/// Execute a database operation
pub async fn execute_op(tx: &mut Transaction<'_, Sqlite>, op: &DbOp<'_>) -> Result<DbOpResult> {
    match op {
        // ContainerIdentifiers operations
        DbOp::InsertContainer(container) => {
            query!(
                "INSERT OR IGNORE INTO containers (id, name) VALUES (?, ?)",
                container.id,
                container.name
            )
            .execute(&mut **tx)
            .await
            .map_err(|e| Error::Database(format!("Failed to insert container: {}", e)))?;
            Ok(DbOpResult::Unit)
        }

        DbOp::ListContainers => {
            let containers = query_as!(ContainerIdentifiers, "SELECT id, name FROM containers")
                .fetch_all(&mut **tx)
                .await
                .map_err(|e| Error::Database(format!("Failed to list containers: {}", e)))?;
            Ok(DbOpResult::Containers(containers))
        }

        DbOp::GetContainer(id) => {
            let container = query_as!(
                ContainerIdentifiers,
                "SELECT id, name FROM containers WHERE id = ?",
                id
            )
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| Error::Database(format!("Failed to get container: {}", e)))?;
            Ok(DbOpResult::ContainerIdentifiers(container))
        }

        DbOp::GetContainerByName(name) => {
            let container = query_as!(
                ContainerIdentifiers,
                "SELECT id, name FROM containers WHERE name = ?",
                name
            )
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| Error::Database(format!("Failed to get container by name: {}", e)))?;
            Ok(DbOpResult::ContainerIdentifiers(container))
        }

        DbOp::DeleteContainer(id) => {
            query!("DELETE FROM containers WHERE id = ?", id)
                .execute(&mut **tx)
                .await
                .map_err(|e| Error::Database(format!("Failed to delete container: {}", e)))?;
            Ok(DbOpResult::Unit)
        }

        DbOp::UpdateContainerName { id, new_name } => {
            query!("UPDATE containers SET name = ? WHERE id = ?", new_name, id)
                .execute(&mut **tx)
                .await
                .map_err(|e| Error::Database(format!("Failed to update container name: {}", e)))?;
            Ok(DbOpResult::Unit)
        }

        // Address operations
        DbOp::InsertAddr(addr) => {
            query!(
                "INSERT OR IGNORE INTO addrs (addr, container_id) VALUES (?, ?)",
                addr.addr,
                addr.container_id
            )
            .execute(&mut **tx)
            .await
            .map_err(|e| Error::Database(format!("Failed to insert address: {}", e)))?;
            Ok(DbOpResult::Unit)
        }

        DbOp::GetAddrsByContainer(container_id) => {
            let addrs = query_as!(
                Addr,
                "SELECT addr, container_id FROM addrs WHERE container_id = ?",
                container_id
            )
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| Error::Database(format!("Failed to get addresses: {}", e)))?;
            Ok(DbOpResult::Addrs(addrs))
        }

        DbOp::DeleteAddrsByContainer(container_id) => {
            query!("DELETE FROM addrs WHERE container_id = ?", container_id)
                .execute(&mut **tx)
                .await
                .map_err(|e| Error::Database(format!("Failed to delete addresses: {}", e)))?;
            Ok(DbOpResult::Unit)
        }

        // ContainerIdentifiers alias operations
        DbOp::InsertContainerAlias(alias) => {
            query!(
                "INSERT OR IGNORE INTO container_aliases (container_id, container_alias) VALUES (?, ?)",
                alias.container_id,
                alias.container_alias
            )
            .execute(&mut **tx)
            .await
            .map_err(|e| Error::Database(format!("Failed to insert container alias: {}", e)))?;
            Ok(DbOpResult::Unit)
        }

        DbOp::GetContainerByAlias(alias) => {
            let container = query_as!(
                ContainerIdentifiers,
                r#"SELECT c.id, c.name 
                   FROM containers c 
                   JOIN container_aliases ca ON c.id = ca.container_id 
                   WHERE ca.container_alias = ?"#,
                alias
            )
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| Error::Database(format!("Failed to get container by alias: {}", e)))?;
            Ok(DbOpResult::ContainerIdentifiers(container))
        }

        DbOp::DeleteContainerAliases(container_id) => {
            query!(
                "DELETE FROM container_aliases WHERE container_id = ?",
                container_id
            )
            .execute(&mut **tx)
            .await
            .map_err(|e| Error::Database(format!("Failed to delete container aliases: {}", e)))?;
            Ok(DbOpResult::Unit)
        }

        // Established container operations
        DbOp::InsertEstContainer(est) => {
            query!(
                "INSERT INTO est_containers (src_container_id, dst_container_id) VALUES (?, ?)",
                est.src_container_id,
                est.dst_container_id
            )
            .execute(&mut **tx)
            .await
            .map_err(|e| {
                Error::Database(format!("Failed to insert established container: {}", e))
            })?;
            Ok(DbOpResult::Unit)
        }

        DbOp::DeleteEstContainers(container_id) => {
            query!(
                "DELETE FROM est_containers WHERE src_container_id = ? OR dst_container_id = ?",
                container_id,
                container_id
            )
            .execute(&mut **tx)
            .await
            .map_err(|e| {
                Error::Database(format!("Failed to delete established containers: {}", e))
            })?;
            Ok(DbOpResult::Unit)
        }

        // Waiting rule operations
        DbOp::InsertWaitingRule(rule) => {
            query!(
                "INSERT OR IGNORE INTO waiting_container_rules (src_container_id, dst_container_name, rule) VALUES (?, ?, ?)",
                rule.src_container_id,
                rule.dst_container_name,
                rule.rule
            )
            .execute(&mut **tx)
            .await
            .map_err(|e| Error::Database(format!("Failed to insert waiting rule: {}", e)))?;
            Ok(DbOpResult::Unit)
        }

        DbOp::GetWaitingRulesForContainer(dst_container_name) => {
            let rules = query_as!(
                WaitingContainerRule,
                "SELECT src_container_id, dst_container_name, rule FROM waiting_container_rules WHERE dst_container_name = ?",
                dst_container_name
            )
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| Error::Database(format!("Failed to get waiting rules: {}", e)))?;
            Ok(DbOpResult::WaitingRules(rules))
        }

        DbOp::DeleteWaitingRules(src_container_id) => {
            query!(
                "DELETE FROM waiting_container_rules WHERE src_container_id = ?",
                src_container_id
            )
            .execute(&mut **tx)
            .await
            .map_err(|e| Error::Database(format!("Failed to delete waiting rules: {}", e)))?;
            Ok(DbOpResult::Unit)
        }

        DbOp::DeleteWaitingRule {
            src_container_id,
            dst_container_name,
        } => {
            query!(
                "DELETE FROM waiting_container_rules WHERE src_container_id = ? AND dst_container_name = ?",
                src_container_id,
                dst_container_name
            )
            .execute(&mut **tx)
            .await
            .map_err(|e| Error::Database(format!("Failed to delete waiting rule: {}", e)))?;
            Ok(DbOpResult::Unit)
        }
    }
}
