use crate::{Result, docker::config::ConfigVerdict};
use nftables::{
    expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField},
    schema::Rule,
    stmt::{Counter, JumpTarget, Log, LogLevel, Match, Operator, Queue, Statement},
    types::NfFamily,
};
use std::borrow::Cow;
use std::net::IpAddr;

/// Context needed for rule generation
pub struct RuleContext<'a> {
    pub container_id: &'a str,
    pub container_name: &'a str,
    pub container_ips: &'a [IpAddr],
    pub container_ports: &'a [(u16, String)], // (port, protocol)
    pub chain_name: &'a str,
    pub table_name: &'a str,
    pub family: NfFamily,
}

/// Trait for converting config types directly to nftables rules
pub trait ToNftablesRule {
    /// Convert this configuration to nftables statements
    fn to_nftables_statements(&self) -> Result<Vec<Statement<'static>>>;

    /// Convert to a complete nftables rule
    fn to_nftables_rule(
        &self,
        ctx: &RuleContext,
        comment: Option<String>,
    ) -> Result<Rule<'static>> {
        let statements = self.to_nftables_statements()?;

        Ok(Rule {
            family: ctx.family,
            table: Cow::Owned(ctx.table_name.to_string()),
            chain: Cow::Owned(ctx.chain_name.to_string()),
            expr: Cow::Owned(statements),
            handle: None,
            index: None,
            comment: comment.map(Cow::Owned),
        })
    }

    /// Create a protocol match statement
    fn match_protocol(protocol: &str) -> Statement<'static> {
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta {
                key: MetaKey::L4proto,
            })),
            right: Expression::Number(match protocol.to_lowercase().as_str() {
                "tcp" => 6,
                "udp" => 17,
                "icmp" => 1,
                "icmpv6" => 58,
                _ => 6, // Default to TCP
            }),
            op: Operator::EQ,
        })
    }

    /// Create a destination port match statement
    fn match_dst_port(protocol: &str, port: u16) -> Statement<'static> {
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: Cow::Owned(protocol.to_string()),
                    field: Cow::Borrowed("dport"),
                },
            ))),
            right: Expression::Number(port as u32),
            op: Operator::EQ,
        })
    }

    /// Create a destination port range match statement
    fn match_dst_port_range(protocol: &str, start: u16, end: u16) -> Statement<'static> {
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: Cow::Owned(protocol.to_string()),
                    field: Cow::Borrowed("dport"),
                },
            ))),
            right: Expression::Range(Box::new(nftables::expr::Range {
                range: [
                    Expression::Number(start as u32),
                    Expression::Number(end as u32),
                ],
            })),
            op: Operator::EQ,
        })
    }

    /// Create a source port match statement
    fn match_src_port(protocol: &str, port: u16) -> Statement<'static> {
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: Cow::Owned(protocol.to_string()),
                    field: Cow::Borrowed("sport"),
                },
            ))),
            right: Expression::Number(port as u32),
            op: Operator::EQ,
        })
    }

    /// Create a source IP match statement
    fn match_src_ip(ip: &str) -> Statement<'static> {
        let protocol = if ip.contains(':') { "ip6" } else { "ip" };
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: Cow::Borrowed(protocol),
                    field: Cow::Borrowed("saddr"),
                },
            ))),
            right: Expression::String(Cow::Owned(ip.to_string())),
            op: Operator::EQ,
        })
    }

    /// Create a destination IP match statement
    fn match_dst_ip(ip: &str) -> Statement<'static> {
        let protocol = if ip.contains(':') { "ip6" } else { "ip" };
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: Cow::Borrowed(protocol),
                    field: Cow::Borrowed("daddr"),
                },
            ))),
            right: Expression::String(Cow::Owned(ip.to_string())),
            op: Operator::EQ,
        })
    }

    /// Create a log statement with optional prefix
    fn log_statement(prefix: Option<&str>) -> Statement<'static> {
        Statement::Log(Some(Log {
            prefix: prefix.map(|p| Cow::Owned(p.to_string())),
            group: None,
            snaplen: None,
            queue_threshold: None,
            level: Some(LogLevel::Info),
            flags: None,
        }))
    }

    /// Create a counter statement
    fn counter_statement() -> Statement<'static> {
        Statement::Counter(Counter::Anonymous(None))
    }

    /// Convert ConfigVerdict to nftables statement
    fn verdict_to_statement(verdict: &ConfigVerdict) -> Statement<'static> {
        if !verdict.chain.is_empty() {
            // Jump to another chain
            Statement::Jump(JumpTarget {
                target: Cow::Owned(verdict.chain.clone()),
            })
        } else if verdict.queue > 0 {
            // Queue to userspace
            Statement::Queue(Queue {
                num: Expression::Number(verdict.queue as u32),
                flags: None,
            })
        } else if verdict.drop {
            // Drop the packet
            Statement::Drop(None)
        } else {
            // Default to accept
            Statement::Accept(None)
        }
    }
}
