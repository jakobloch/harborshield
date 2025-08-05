pub mod cleanup;
pub mod crud;
pub mod error;
pub mod event;
pub mod status;
#[cfg(test)]
mod tests;
pub mod utils;

use crate::{
    Result,
    database::{ContainerIdentifiers, DbOp},
    nftables::transaction::NftablesTransaction,
};
use bollard::models::EventMessage;
use futures::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{debug, error, info};

use super::{ENABLED_LABEL, Harborshield};

impl Harborshield {
    pub(super) fn spawn_event_listener(&self, manager: Arc<Harborshield>) -> JoinHandle<()> {
        let manager = Arc::clone(&manager);

        tokio::spawn(async move {
            let mut retry_count = 0;
            const MAX_RETRIES: u32 = 5;
            const RETRY_DELAY: Duration = Duration::from_secs(2);

            loop {
                let mut event_stream = match manager.docker_client.events().await {
                    Ok(stream) => {
                        retry_count = 0; // Reset retry count on success
                        stream
                    }
                    Err(e) => {
                        error!("Failed to create Docker event stream: {}", e);

                        if retry_count >= MAX_RETRIES {
                            error!("Max retries reached for Docker event stream, exiting");
                            return;
                        }

                        retry_count += 1;
                        error!(
                            "Retrying Docker event stream connection in {:?} (attempt {})",
                            RETRY_DELAY, retry_count
                        );
                        tokio::time::sleep(RETRY_DELAY).await;
                        continue;
                    }
                };

                let mut shutdown_rx = manager.shutdown_rx.lock().await;

                loop {
                    tokio::select! {
                        Some(event_result) = event_stream.next() => {
                            match event_result {
                                Ok(event) => {
                                    if let Err(e) = manager.handle_event(
                                        event
                                    ).await {
                                        error!("Error handling Docker event: {}", e);
                                    }
                                }
                                Err(e) => {
                                    error!("Error receiving Docker event: {}", e);
                                    // Break inner loop to retry connection
                                    break;
                                }
                            }
                        }
                        _ = shutdown_rx.recv() => {
                            info!("Event listener received shutdown signal");
                            return;
                        }
                    }
                }
            }
        })
    }

    pub(super) async fn handle_event(&self, event: EventMessage) -> Result<()> {
        debug!("Handling event: {:#?}", event);

        let Some(ref actor) = event.actor else {
            return Ok(());
        };
        let Some(ref id) = actor.id else {
            return Ok(());
        };
        let Some(ref action) = event.action else {
            return Ok(());
        };

        match action.as_str() {
            "create" => self.handle_container_create(id).await?,
            "start" => self.handle_container_start(id).await?,
            "die" => self.handle_container_stop(id).await?,
            "pause" => self.handle_container_pause(id).await?,
            "unpause" => self.handle_container_unpause(id).await?,
            "rename" => self.handle_container_rename(id, &actor.attributes).await?,
            "connect" | "disconnect" => {
                self.handle_network_event(id, action, &actor.attributes)
                    .await?
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle container create event
    pub(super) async fn handle_container_create(&self, container_id: &str) -> Result<()> {
        info!(container_id = %container_id, "Container created");

        // Inspect the container to see if it has harborshield enabled and check its rules
        match self
            .docker_client
            .try_get_container_by_id(container_id)
            .await
        {
            Ok(container) => {
                // Check if harborshield is enabled
                let enabled = container
                    .labels
                    .get(ENABLED_LABEL)
                    .map(|v| v == "true")
                    .unwrap_or(false);

                if enabled {
                    info!(
                        "Container {:#?} created with harborshield enabled",
                        container
                    );

                    // Check if this container has output rules that reference other containers
                    if let Some(config) = &container.config {
                        for output_rule in &config.output {
                            if !output_rule.container.is_empty() {
                                info!(
                                    "Container {:#?} wants to connect to {:#?}",
                                    container.name, output_rule.container
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                // Container might be in a transitional state
                tracing::debug!(
                    "Could not inspect container {} during create event: {}",
                    container_id,
                    e
                );
            }
        }

        Ok(())
    }

    /// Handle container start event
    pub(super) async fn handle_container_start(&self, container_id: &str) -> Result<()> {
        let container = self
            .docker_client
            .try_get_container_by_id(container_id)
            .await?;

        info!("Container starting: {:#?}", container);

        // Always track the container for C2C rule resolution
        self.docker_client
            .container_tracker
            .add_container(container.clone())?;

        // Check if harborshield is enabled
        let enabled = container
            .labels
            .get(ENABLED_LABEL)
            .map(|v| v == "true")
            .unwrap_or(false);

        if enabled {
            // Store in database
            super::Harborshield::store_container_in_database(&container, &self.db).await?;

            // Apply firewall rules using direct config translation
            self.create_container_rules(
                &container, None, // cancellation_token
            )
            .await?;
        }

        // ALWAYS process waiting rules for this container
        // This is needed for containers that receive C2C rules from other containers
        self.process_waiting_rules_for_container(&container.name, &container.id)
            .await?;

        // With the named set approach, IPs are added when the container chain is created
        // so we don't need to rebuild anything here

        Ok(())
    }

    /// Handle container stop event
    pub async fn handle_container_stop(&self, container_id: &str) -> Result<()> {
        info!(container_id = %container_id, "Container stopped");

        // Check if this container failed to start due to connection issues
        // We can detect this by checking if it has output rules that reference other containers
        if let Ok(container) = self
            .docker_client
            .try_get_container_by_id(container_id)
            .await
        {
            info!("Container stopped: {:#?}", container);
            debug!(
                "Checking if stopped container {} needs restart due to connection issues...",
                container.name
            );

            if container.is_whalewall_enabled() {
                // Check if container has rules that reference other containers
                if let Some(config) = &container.config {
                    let has_container_refs = config.output.iter().any(|r| !r.container.is_empty());

                    debug!(
                        "Container {} has container references: {}",
                        container.name, has_container_refs
                    );

                    if has_container_refs {
                        // Check if all referenced containers now have their chains set up
                        let mut all_refs_ready = true;
                        for output_rule in &config.output {
                            if !output_rule.container.is_empty() {
                                // Check if the referenced container has a chain
                                if let Some(ref_container) = self
                                    .docker_client
                                    .container_tracker
                                    .find_container(&output_rule.container)
                                {
                                    let chain_name = format!(
                                        "hs-{}-{}",
                                        ref_container.name.replace(['_', '.', '/'], "-"),
                                        &ref_container.id[..12.min(ref_container.id.len())]
                                    );
                                    // For now, assume the chain exists if the container is tracked
                                    debug!(
                                        "Container {} references {} which has chain {}",
                                        container.name, output_rule.container, chain_name
                                    );
                                } else {
                                    debug!(
                                        "Container {} references {} but that container is not tracked yet",
                                        container.name, output_rule.container
                                    );
                                    all_refs_ready = false;
                                    break;
                                }
                            }
                        }

                        if all_refs_ready {
                            info!(
                                "Container {} stopped but all referenced containers are ready. \
                                This container may have failed to start due to firewall rules not being ready in time. \
                                Attempting to restart the container.",
                                container.name
                            );

                            // Attempt to restart the container
                            match self.docker_client.start_container(container_id).await {
                                Ok(_) => {
                                    info!(
                                        "Successfully restarted container {} after firewall rules were applied",
                                        container.name
                                    );
                                    // Don't remove from tracker or database - the container is restarting
                                    return Ok(());
                                }
                                Err(e) => {
                                    error!("Failed to restart container {}: {}", container.name, e);
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some(details) = self
            .docker_client
            .container_tracker
            .remove_container(container_id)?
        {
            // Container IPs will be automatically removed when verdict maps are rebuilt

            // Remove from database
            self.remove_container_from_database(container_id).await?;

            // Now we can safely remove the container chain
            let mut transaction = NftablesTransaction::builder().build();
            transaction.remove_container_rules(container_id, &details.name)?;
            transaction.commit().await?;
        }
        Ok(())
    }

    /// Handle container pause event
    pub async fn handle_container_pause(&self, container_id: &str) -> Result<()> {
        info!("Container {:#?} paused", container_id);

        // Mark container as paused and disable its rules
        if let Some(mut details) = self
            .docker_client
            .container_tracker
            .get_container(container_id)
        {
            details.paused = true;
            self.docker_client
                .container_tracker
                .update_container(details.clone())?;

            // Disable firewall rules for paused container
            let mut nftables = self.nftables_client.lock().await;
            let mut transaction = NftablesTransaction::builder().build();
            nftables.disable_container_rules(&mut transaction, container_id, &details.name)?;
            transaction.commit().await?;

            info!(container_id = %container_id, "Disabled firewall rules for paused container");
        }
        Ok(())
    }

    /// Handle container unpause event
    pub async fn handle_container_unpause(&self, container_id: &str) -> Result<()> {
        info!("Container {} unpaused", container_id);

        // Mark container as unpaused and re-enable its rules
        if let Some(mut details) = self
            .docker_client
            .container_tracker
            .get_container(container_id)
        {
            details.paused = false;
            self.docker_client
                .container_tracker
                .update_container(details.clone())?;

            // Only re-enable rules if the container is enabled
            if details.enabled {
                // Recreate the container's rules using direct config translation
                // This ensures the container's rules are properly restored after unpause
                if let Err(e) = self.create_container_rules(&details, None).await {
                    error!(
                        "Failed to re-enable rules for unpaused container {}: {}",
                        container_id, e
                    );
                } else {
                    info!(container_id = %container_id, "Re-enabled firewall rules for unpaused container");
                }
            }
        }
        Ok(())
    }

    /// Process waiting rules when a target container starts
    pub(super) async fn process_waiting_rules_for_container(
        &self,
        container_name: &str,
        container_id: &str,
    ) -> Result<()> {
        tracing::info!(
            "Processing waiting rules for container {} ({})",
            container_name,
            container_id
        );
        // Define the waiting rule data structure once
        #[derive(Debug, serde::Deserialize, serde::Serialize)]
        struct WaitingRuleData {
            protocol: String,
            dst_ports: Vec<u16>,
            log_prefix: Option<String>,
        }
        // Get waiting rules for this container (check both name and aliases)
        let mut all_waiting_rules = Vec::new();

        {
            let db_lock = self.db.lock().await;

            // Get rules for the container name
            let mut rules = match db_lock
                .execute(&DbOp::GetWaitingRulesForContainer(container_name))
                .await?
            {
                crate::database::DbOpResult::WaitingRules(rules) => rules,
                _ => vec![],
            };
            all_waiting_rules.append(&mut rules);

            // Get rules for any aliases
            if let Some(container) = self
                .docker_client
                .container_tracker
                .find_container(container_id)
            {
                for alias in &container.aliases {
                    let mut alias_rules = match db_lock
                        .execute(&DbOp::GetWaitingRulesForContainer(alias))
                        .await?
                    {
                        crate::database::DbOpResult::WaitingRules(rules) => rules,
                        _ => vec![],
                    };
                    all_waiting_rules.append(&mut alias_rules);
                }
            }
        }

        if !all_waiting_rules.is_empty() {
            info!(
                "Found {} waiting rules for container {} ({})",
                all_waiting_rules.len(),
                container_name,
                container_id
            );

            // Get the target container's details
            let target_container = self
                .docker_client
                .container_tracker
                .find_container(container_id)
                .ok_or_else(|| {
                    crate::Error::invalid_state(
                        "Target container not found in tracker",
                        "tracked",
                        "not found",
                    )
                })?;

            // Extract all IPs from the target container
            let mut target_ips = Vec::new();
            for (_, network) in &target_container.networks {
                target_ips.extend(network.ip_addresses.clone());
            }

            // When a container starts, we need to recreate rules for source containers
            // that were waiting for this destination. This will add OUTPUT rules to the
            // source containers' chains to allow them to connect to this target container.

            // Process each waiting rule to create OUTPUT rules in source containers
            let mut rules_applied = 0;
            let mut processed_containers = std::collections::HashSet::new();

            for waiting_rule in &all_waiting_rules {
                // Skip if we already processed this source container
                if processed_containers.contains(&waiting_rule.src_container_id) {
                    continue;
                }

                // Get the source container
                if let Some(src_container) = self
                    .docker_client
                    .container_tracker
                    .find_container(&waiting_rule.src_container_id)
                {
                    // Only process if the source container has harborshield enabled
                    if !src_container.enabled {
                        continue;
                    }

                    // Recreate the source container's rules - now that the target container exists,
                    // the output rules that reference it will resolve to actual IPs
                    if let Err(e) = self.create_container_rules(&src_container, None).await {
                        error!(
                            "Failed to recreate rules for source container {} after target {} started: {}",
                            src_container.name, container_name, e
                        );
                    } else {
                        info!(
                            "Recreated OUTPUT rules for source container {} now that target {} is available",
                            src_container.name, container_name
                        );
                        rules_applied += 1;
                        processed_containers.insert(waiting_rule.src_container_id.clone());
                    }
                }
            }

            // Remove processed waiting rules from database
            let mut db_lock = self.db.lock().await;

            let mut ops = vec![];
            for waiting_rule in &all_waiting_rules {
                ops.push(DbOp::DeleteWaitingRule {
                    src_container_id: &waiting_rule.src_container_id,
                    dst_container_name: &waiting_rule.dst_container_name,
                });
            }

            if !ops.is_empty() {
                db_lock
                    .transaction()
                    .execute_ops(&ops)
                    .await?
                    .commit()
                    .await?;
            }

            info!(
                "Successfully processed waiting rules for container {}: {} source containers updated with OUTPUT rules",
                container_name, rules_applied
            );
        } else {
            tracing::info!(
                "No waiting rules found for container {} ({})",
                container_name,
                container_id
            );
        }

        Ok(())
    }

    /// Get containers from database
    pub(super) async fn get_database_containers(
        &self,
    ) -> Result<HashMap<String, ContainerIdentifiers>> {
        let db = self.db.lock().await;
        use crate::database::{DbOp, DbOpResult};

        let db_containers = match db.execute(&DbOp::ListContainers).await? {
            DbOpResult::Containers(containers) => containers,
            _ => vec![],
        };

        Ok(db_containers
            .into_iter()
            .map(|c| (c.id.clone(), c))
            .collect())
    }

    /// Clean up rules for containers that are no longer running
    pub(super) async fn cleanup_stopped_containers(
        &self,
        db_container_ids: HashMap<String, ContainerIdentifiers>,
    ) -> Result<()> {
        for (id, identifiers) in db_container_ids {
            info!(container_id = %id, "Removing rules for stopped container");
            self.delete_container_rules(&id, &identifiers.name).await?;
        }
        Ok(())
    }
}
