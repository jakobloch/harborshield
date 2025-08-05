use crate::Result;
use crate::docker::config::ToNftablesRule;
use bon::Builder;
use nftables::expr::{Expression, NamedExpression, Payload, PayloadField};
use nftables::stmt::{Match, Operator, Statement};
use serde::{Deserialize, Deserializer, Serialize};
use std::borrow::Cow;

#[derive(Debug, Clone, Default, Serialize, Builder)]
pub struct ExternalRules {
    #[serde(default)]
    #[builder(default)]
    pub allow: bool,
    #[serde(default)]
    #[builder(default)]
    pub log_prefix: String,
    #[serde(default)]
    #[builder(default)]
    pub ips: Vec<super::AddrOrRange>,
    #[serde(default)]
    #[builder(default)]
    pub verdict: super::ConfigVerdict,
}

// Custom Deserialize for ExternalRules with validation
impl<'de> Deserialize<'de> for ExternalRules {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct TempExternalRules {
            #[serde(default)]
            allow: bool,
            #[serde(default)]
            log_prefix: String,
            #[serde(default)]
            ips: Vec<super::AddrOrRange>,
            #[serde(default)]
            verdict: super::ConfigVerdict,
        }

        let temp = TempExternalRules::deserialize(deserializer)?;

        // Validate log prefix if present
        if temp.allow && !temp.log_prefix.is_empty() {
            if temp.log_prefix.len() > 64 {
                return Err(serde::de::Error::custom(
                    super::ValidationError::InvalidFieldValue {
                        field: "log_prefix".to_string(),
                        reason: "Log prefix too long (max 64 characters)".to_string(),
                        value: temp.log_prefix.clone(),
                        expected_format: Some("String with max 64 characters".to_string()),
                    },
                ));
            }
        }

        Ok(ExternalRules {
            allow: temp.allow,
            log_prefix: temp.log_prefix,
            ips: temp.ips,
            verdict: temp.verdict,
        })
    }
}

/// Implementation for ExternalRules (external mapped ports)
impl ToNftablesRule for ExternalRules {
    fn to_nftables_statements(&self) -> Result<Vec<Statement<'static>>> {
        let mut statements = Vec::new();

        // Match source IPs if specified
        if !self.ips.is_empty() {
            // Create a set expression for multiple IPs
            let mut ip_exprs = Vec::new();

            for addr_or_range in &self.ips {
                match addr_or_range {
                    super::AddrOrRange::Addr(ip) => {
                        ip_exprs.push(Expression::String(Cow::Owned(ip.to_string())));
                    }
                    super::AddrOrRange::Range(start, end) => {
                        ip_exprs.push(Expression::Range(Box::new(nftables::expr::Range {
                            range: [
                                Expression::String(Cow::Owned(start.to_string())),
                                Expression::String(Cow::Owned(end.to_string())),
                            ],
                        })));
                    }
                    super::AddrOrRange::Net(net) => {
                        // Parse CIDR notation to create a prefix expression
                        let addr = net.addr();
                        let prefix_len = net.prefix_len() as u32;

                        ip_exprs.push(Expression::Named(NamedExpression::Prefix(
                            nftables::expr::Prefix {
                                addr: Box::new(Expression::String(Cow::Owned(addr.to_string()))),
                                len: prefix_len,
                            },
                        )));
                    }
                }
            }

            // Determine protocol based on first IP
            let protocol = match self.ips.first() {
                Some(super::AddrOrRange::Addr(ip)) => {
                    if ip.is_ipv4() {
                        "ip"
                    } else {
                        "ip6"
                    }
                }
                Some(super::AddrOrRange::Range(start, _)) => {
                    if start.is_ipv4() {
                        "ip"
                    } else {
                        "ip6"
                    }
                }
                Some(super::AddrOrRange::Net(net)) => {
                    if net.addr().is_ipv4() {
                        "ip"
                    } else {
                        "ip6"
                    }
                }
                _ => "ip",
            };

            if ip_exprs.len() == 1 {
                // Single IP/range/prefix - use direct match
                statements.push(Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed(protocol),
                            field: Cow::Borrowed("saddr"),
                        },
                    ))),
                    right: ip_exprs.into_iter().next().unwrap(),
                    op: Operator::EQ,
                }));
            } else {
                // Multiple IPs - use anonymous set
                let set_items: Vec<nftables::expr::SetItem> = ip_exprs
                    .into_iter()
                    .map(|expr| nftables::expr::SetItem::Element(expr))
                    .collect();

                statements.push(Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                        PayloadField {
                            protocol: Cow::Borrowed(protocol),
                            field: Cow::Borrowed("saddr"),
                        },
                    ))),
                    right: Expression::Named(NamedExpression::Set(set_items)),
                    op: Operator::EQ,
                }));
            }
        }

        // Add counter
        statements.push(Self::counter_statement());

        // Add log if configured
        if !self.log_prefix.is_empty() {
            statements.push(Self::log_statement(Some(&self.log_prefix)));
        }

        // Add verdict
        let verdict = if self.allow {
            Self::verdict_to_statement(&self.verdict)
        } else {
            Statement::Drop(None)
        };
        statements.push(verdict);

        Ok(statements)
    }
}
