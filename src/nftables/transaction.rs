use crate::Result;
use crate::docker::config::{Config, RuleContext, ToNftablesRule};
use crate::nftables::FILTER_TABLE;
use crate::nftables::common::helpers::family_to_string;
use bon::Builder;
use bon::builder;
use nftables::schema::{FlushObject, NfCmd};
use nftables::{
    batch::Batch,
    helper::{NftablesError, get_current_ruleset_raw},
    schema::{Chain, NfListObject, Rule},
    stmt::{Counter, Log, LogLevel, Statement},
    types::NfFamily,
};
use serde_json;
use std::borrow::Cow;
use tracing::{debug, info};

#[derive(Builder)]
/// Transaction wrapper for atomic operations
pub struct NftablesTransaction {
    #[builder(default = Batch::new())]
    pub batch: Batch<'static>,
    #[builder(default = NfFamily::IP)]
    pub family: NfFamily,
    #[builder(default = Vec::new())]
    pub deferred_drop_rules: Vec<Rule<'static>>,
}

impl NftablesTransaction {
    /// Delete an nftables object
    pub fn delete(&mut self, obj: NfListObject<'static>) {
        // Dump ruleset for the specific object being deleted
        let args = match &obj {
            NfListObject::Chain(chain) => {
                // For chains, dump the specific chain rules
                vec![
                    "list".to_string(),
                    "chain".to_string(),
                    family_to_string(&chain.family).to_string(),
                    chain.table.to_string(),
                    chain.name.to_string(),
                ]
            }
            NfListObject::Rule(rule) => {
                // For rules, dump the chain containing the rule
                vec![
                    "list".to_string(),
                    "chain".to_string(),
                    family_to_string(&rule.family).to_string(),
                    rule.table.to_string(),
                    rule.chain.to_string(),
                ]
            }
            NfListObject::Table(table) => {
                // For tables, dump the entire table
                vec![
                    "list".to_string(),
                    "table".to_string(),
                    family_to_string(&table.family).to_string(),
                    table.name.to_string(),
                ]
            }
            _ => {
                // For other objects, just dump the full ruleset
                vec!["list".to_string(), "ruleset".to_string()]
            }
        };

        match get_current_ruleset_raw::<String, String, _>(None, &args) {
            Ok(ruleset) => {
                debug!(
                    "Ruleset dump for item being deleted - {:#?}:\n{:#?}",
                    obj, ruleset
                );
            }
            Err(e) => {
                debug!("Failed to get ruleset dump before deletion: {:#?}", e);
            }
        }

        self.batch.delete(obj);
    }

    /// Flush a chain
    pub fn flush_chain(&mut self, table: &str, chain: &str) {
        // To flush a chain, we delete it and recreate it
        self.batch.add_cmd(NfCmd::Flush(FlushObject::Chain(Chain {
            family: self.family,
            table: Cow::Owned(table.to_string()),
            name: Cow::Owned(chain.to_string()),
            newname: None,
            handle: None,
            _type: None,
            hook: None,
            prio: None,
            dev: None,
            policy: None,
        })));
    }

    /// Commit the transaction
    pub async fn commit(mut self) -> Result<()> {
        info!(
            "Committing nftables transaction with {} deferred DROP rules",
            self.deferred_drop_rules.len()
        );

        // Add all deferred DROP rules at the end
        for drop_rule in self.deferred_drop_rules {
            tracing::debug!("Adding deferred DROP rule for chain: {}", drop_rule.chain);
            self.batch.add(NfListObject::Rule(drop_rule));
        }

        let nftables_obj = self.batch.to_nftables();
        match serde_json::to_string_pretty(&nftables_obj) {
            Ok(json) => tracing::debug!("NFTables JSON to apply: {:#?}", json),
            Err(e) => tracing::error!("Failed to serialize nftables object: {:#?}", e),
        }

        // Use apply_and_return_ruleset for better error details
        match nftables::helper::apply_and_return_ruleset(&nftables_obj) {
            Ok(_ruleset) => {
                // Log success
                tracing::debug!("Successfully applied nftables transaction");
                Ok(())
            }
            Err(e) => {
                // Get more detailed error information
                let error_msg = match &e {
                    NftablesError::NftFailed {
                        program,
                        hint,
                        stdout,
                        stderr,
                    } => {
                        format!(
                            "nft command failed - program: {:?}, hint: {}, stdout: '{}', stderr: '{}'",
                            program, hint, stdout, stderr
                        )
                    }
                    _ => format!("Failed to apply nftables transaction: {:?}", e),
                };

                tracing::error!("{}", error_msg);

                // Check if this is a "chain doesn't exist" error during deletion
                if error_msg.contains("No such file or directory")
                    || error_msg.contains("does not exist")
                {
                    // Log this as a warning instead of an error for cleanup operations
                    tracing::warn!(
                        "Ignoring deletion error (object may not exist): {}",
                        error_msg
                    );
                    // For now, we'll still return an error, but we could make this configurable
                }

                Err(crate::Error::Config {
                    message: error_msg,
                    location: "nftables".to_string(),
                    suggestion: Some("Check nftables permissions and syntax".to_string()),
                })
            }
        }
    }

    /// Remove container chain and vmap rules
    pub fn remove_container_rules(
        &mut self,
        container_id: &str,
        container_name: &str,
    ) -> Result<()> {
        let chain_name = format!(
            "hs-{}-{}",
            container_name.replace(['_', '.', '/'], "-"),
            &container_id[..12.min(container_id.len())]
        );

        // Delete container chain
        self.delete(NfListObject::Chain(Chain {
            family: self.family,
            table: Cow::Borrowed(FILTER_TABLE),
            name: Cow::Owned(chain_name),
            newname: None,
            handle: None,
            _type: None,
            hook: None,
            prio: None,
            dev: None,
            policy: None,
        }));

        // Note: vmap rules will be removed when we re-create them with updated IPs

        Ok(())
    }

    /// Add container chain to a transaction
    pub fn add_container_chain_to_transaction(
        family: NfFamily,
        transaction: &mut NftablesTransaction,
        container_id: &str,
        container_name: &str,
    ) -> Result<String> {
        let chain_name = format!(
            "hs-{}-{}",
            container_name.replace(['_', '.', '/'], "-"),
            &container_id[..12.min(container_id.len())]
        );

        transaction.batch.add(NfListObject::Chain(Chain {
            family: family,
            table: Cow::Borrowed(FILTER_TABLE),
            name: Cow::Owned(chain_name.clone()),
            newname: None,
            handle: None,
            _type: None,
            hook: None,
            prio: None,
            dev: None,
            policy: None,
        }));

        Ok(chain_name)
    }

    /// Add DROP rule to a transaction
    pub fn add_container_drop_rule_to_transaction(
        family: NfFamily,
        transaction: &mut NftablesTransaction,
        container_id: &str,
        container_name: &str,
    ) -> Result<()> {
        let chain_name = format!(
            "hs-{}-{}",
            container_name.replace(['_', '.', '/'], "-"),
            &container_id[..12.min(container_id.len())]
        );

        let drop_rule = Rule {
            family: family,
            table: Cow::Borrowed(FILTER_TABLE),
            chain: Cow::Owned(chain_name.clone()),
            expr: Cow::Owned(vec![
                Statement::Counter(Counter::Anonymous(None)),
                Statement::Log(Some(Log {
                    prefix: Some(Cow::Owned(format!("{} DROP: ", chain_name))),
                    level: Some(LogLevel::Info),
                    flags: None,
                    group: None,
                    queue_threshold: None,
                    snaplen: None,
                })),
                Statement::Drop(None),
            ]),
            handle: None,
            index: None,
            comment: Some(Cow::Owned(format!(
                "Default DROP for container {}",
                container_name
            ))),
        };

        transaction.deferred_drop_rules.push(drop_rule);

        Ok(())
    }

    /// Add container rules to a transaction (this method remains for compatibility but now delegates to config-based method)
    pub fn add_container_rules_to_transaction(
        family: NfFamily,
        transaction: &mut NftablesTransaction,
        container_id: &str,
        container_name: &str,
        container_ips: &[std::net::IpAddr],
        container_ports: &[(u16, String)],
        config: &Config,
    ) -> Result<()> {
        let chain_name = format!(
            "hs-{}-{}",
            container_name.replace(['_', '.', '/'], "-"),
            &container_id[..12.min(container_id.len())]
        );

        let ctx = RuleContext {
            container_id,
            container_name,
            container_ips,
            container_ports,
            chain_name: &chain_name,
            table_name: FILTER_TABLE,
            family: family,
        };

        // Add mapped port rules - create individual rules for each container port
        if config.mapped_ports.localhost.allow || config.mapped_ports.external.allow {
            tracing::debug!(
                "Creating mapped port rules for container {}: ports={:?}",
                container_name,
                container_ports
            );

            // Group ports by protocol
            let mut tcp_ports = Vec::new();
            let mut udp_ports = Vec::new();

            for (port, protocol) in container_ports {
                match protocol.as_str() {
                    "tcp" => tcp_ports.push(*port),
                    "udp" => udp_ports.push(*port),
                    _ => {} // Ignore other protocols for now
                }
            }

            // Create localhost rules for each port
            if config.mapped_ports.localhost.allow {
                tracing::debug!("Creating localhost rules for TCP ports: {:?}", tcp_ports);
                for port in &tcp_ports {
                    let mut statements = Vec::new();

                    // Match source IP as localhost
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_src_ip(
                            "127.0.0.1",
                        ),
                    );

                    // Match protocol and destination port
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_protocol(
                            "tcp",
                        ),
                    );
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_dst_port(
                            "tcp", *port,
                        ),
                    );

                    // Add counter
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::counter_statement(),
                    );

                    // Add log if configured
                    if !config.mapped_ports.localhost.log_prefix.is_empty() {
                        statements.push(
                            <crate::docker::config::LocalRules as ToNftablesRule>::log_statement(
                                Some(&config.mapped_ports.localhost.log_prefix),
                            ),
                        );
                    }

                    // Add verdict
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::verdict_to_statement(
                            &config.mapped_ports.localhost.verdict,
                        ),
                    );

                    let rule = Rule {
                        family: ctx.family,
                        table: Cow::Owned(ctx.table_name.to_string()),
                        chain: Cow::Owned(ctx.chain_name.to_string()),
                        expr: Cow::Owned(statements),
                        handle: None,
                        index: None,
                        comment: Some(Cow::Owned(format!(
                            "Localhost access to port {} for {}",
                            port, container_name
                        ))),
                    };

                    transaction.batch.add(NfListObject::Rule(rule));
                }

                for port in &udp_ports {
                    let mut statements = Vec::new();

                    // Match source IP as localhost
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_src_ip(
                            "127.0.0.1",
                        ),
                    );

                    // Match protocol and destination port
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_protocol(
                            "udp",
                        ),
                    );
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_dst_port(
                            "udp", *port,
                        ),
                    );

                    // Add counter
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::counter_statement(),
                    );

                    // Add log if configured
                    if !config.mapped_ports.localhost.log_prefix.is_empty() {
                        statements.push(
                            <crate::docker::config::LocalRules as ToNftablesRule>::log_statement(
                                Some(&config.mapped_ports.localhost.log_prefix),
                            ),
                        );
                    }

                    // Add verdict
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::verdict_to_statement(
                            &config.mapped_ports.localhost.verdict,
                        ),
                    );

                    let rule = Rule {
                        family: ctx.family,
                        table: Cow::Owned(ctx.table_name.to_string()),
                        chain: Cow::Owned(ctx.chain_name.to_string()),
                        expr: Cow::Owned(statements),
                        handle: None,
                        index: None,
                        comment: Some(Cow::Owned(format!(
                            "Localhost access to UDP port {} for {}",
                            port, container_name
                        ))),
                    };

                    transaction.batch.add(NfListObject::Rule(rule));
                }
            }

            // Create external rules for each port
            if config.mapped_ports.external.allow {
                for port in &tcp_ports {
                    let mut statements = Vec::new();

                    // Match source IPs if specified
                    if !config.mapped_ports.external.ips.is_empty() {
                        // For simplicity, handle the first IP only for now
                        if let Some(first_ip) = config.mapped_ports.external.ips.first() {
                            match first_ip {
                                crate::docker::config::AddrOrRange::Addr(ip) => {
                                    statements.push(<crate::docker::config::ExternalRules as ToNftablesRule>::match_src_ip(&ip.to_string()));
                                }
                                crate::docker::config::AddrOrRange::Net(net) => {
                                    statements.push(<crate::docker::config::ExternalRules as ToNftablesRule>::match_src_ip(&net.to_string()));
                                }
                                _ => {} // Handle ranges later
                            }
                        }
                    }

                    // Match protocol and destination port
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_protocol(
                            "tcp",
                        ),
                    );
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_dst_port(
                            "tcp", *port,
                        ),
                    );

                    // Add counter
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::counter_statement(),
                    );

                    // Add log if configured
                    if !config.mapped_ports.external.log_prefix.is_empty() {
                        statements.push(
                            <crate::docker::config::ExternalRules as ToNftablesRule>::log_statement(
                                Some(&config.mapped_ports.external.log_prefix),
                            ),
                        );
                    }

                    // Add verdict
                    statements.push(<crate::docker::config::ExternalRules as ToNftablesRule>::verdict_to_statement(&config.mapped_ports.external.verdict));

                    let rule = Rule {
                        family: ctx.family,
                        table: Cow::Owned(ctx.table_name.to_string()),
                        chain: Cow::Owned(ctx.chain_name.to_string()),
                        expr: Cow::Owned(statements),
                        handle: None,
                        index: None,
                        comment: Some(Cow::Owned(format!(
                            "External access to port {} for {}",
                            port, container_name
                        ))),
                    };

                    transaction.batch.add(NfListObject::Rule(rule));
                }

                for port in &udp_ports {
                    let mut statements = Vec::new();

                    // Match source IPs if specified
                    if !config.mapped_ports.external.ips.is_empty() {
                        // For simplicity, handle the first IP only for now
                        if let Some(first_ip) = config.mapped_ports.external.ips.first() {
                            match first_ip {
                                crate::docker::config::AddrOrRange::Addr(ip) => {
                                    statements.push(<crate::docker::config::ExternalRules as ToNftablesRule>::match_src_ip(&ip.to_string()));
                                }
                                crate::docker::config::AddrOrRange::Net(net) => {
                                    statements.push(<crate::docker::config::ExternalRules as ToNftablesRule>::match_src_ip(&net.to_string()));
                                }
                                _ => {} // Handle ranges later
                            }
                        }
                    }

                    // Match protocol and destination port
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_protocol(
                            "udp",
                        ),
                    );
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::match_dst_port(
                            "udp", *port,
                        ),
                    );

                    // Add counter
                    statements.push(
                        <crate::docker::config::LocalRules as ToNftablesRule>::counter_statement(),
                    );

                    // Add log if configured
                    if !config.mapped_ports.external.log_prefix.is_empty() {
                        statements.push(
                            <crate::docker::config::ExternalRules as ToNftablesRule>::log_statement(
                                Some(&config.mapped_ports.external.log_prefix),
                            ),
                        );
                    }

                    // Add verdict
                    statements.push(<crate::docker::config::ExternalRules as ToNftablesRule>::verdict_to_statement(&config.mapped_ports.external.verdict));

                    let rule = Rule {
                        family: ctx.family,
                        table: Cow::Owned(ctx.table_name.to_string()),
                        chain: Cow::Owned(ctx.chain_name.to_string()),
                        expr: Cow::Owned(statements),
                        handle: None,
                        index: None,
                        comment: Some(Cow::Owned(format!(
                            "External access to UDP port {} for {}",
                            port, container_name
                        ))),
                    };

                    transaction.batch.add(NfListObject::Rule(rule));
                }
            }
        }

        // Add output rules
        for (i, output_rule) in config.output.iter().enumerate() {
            if !output_rule.skip {
                let rule = output_rule.to_nftables_rule(
                    &ctx,
                    Some(format!("Output rule {} for {}", i + 1, container_name)),
                )?;
                transaction.batch.add(NfListObject::Rule(rule));
            }
        }

        Ok(())
    }
}
