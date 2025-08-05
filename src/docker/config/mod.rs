mod external;
mod localhost;
pub mod nftables_convert;
mod rule;
#[cfg(test)]
mod tests;
pub mod validation;
mod verdict;

use crate::{Error, Result};
use bon::Builder;
pub use external::ExternalRules;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
pub use localhost::LocalRules;
pub use nftables_convert::{RuleContext, ToNftablesRule};
pub use rule::RuleConfig;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use validation::error::ValidationError;
pub use verdict::ConfigVerdict;

#[derive(Debug, Clone, Serialize, Builder)]
pub struct Config {
    #[serde(default)]
    #[builder(default)]
    pub mapped_ports: MappedPorts,
    #[serde(default)]
    #[builder(default)]
    pub output: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, Builder)]
pub struct MappedPorts {
    #[serde(default)]
    #[builder(default)]
    pub localhost: LocalRules,
    #[serde(default)]
    #[builder(default)]
    pub external: ExternalRules,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone)]
pub enum AddrOrRange {
    Addr(IpAddr),
    Range(IpAddr, IpAddr),
    Net(IpNet),
}

impl Serialize for AddrOrRange {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AddrOrRange {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for AddrOrRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddrOrRange::Addr(addr) => write!(f, "{}", addr),
            AddrOrRange::Range(start, end) => write!(f, "{}-{}", start, end),
            AddrOrRange::Net(net) => write!(f, "{}", net),
        }
    }
}

impl FromStr for AddrOrRange {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        // Check for invalid "0.0.0.0/0" which causes nftables to fail
        if s == "0.0.0.0/0" {
            return Err(Error::invalid_ip(
                s,
                "0.0.0.0/0 is not supported by nftables. Use specific IP addresses or ranges instead",
            ));
        }

        if s.contains('/') {
            // CIDR notation
            if let Ok(net) = s.parse::<Ipv4Net>() {
                return Ok(AddrOrRange::Net(IpNet::V4(net)));
            }
            if let Ok(net) = s.parse::<Ipv6Net>() {
                return Ok(AddrOrRange::Net(IpNet::V6(net)));
            }
            return Err(Error::invalid_ip(s, "Invalid CIDR notation"));
        } else if s.contains('-') {
            // Range notation
            let parts: Vec<&str> = s.split('-').collect();
            if parts.len() != 2 {
                return Err(Error::invalid_ip(
                    s,
                    "Range must have exactly two parts separated by '-'",
                ));
            }

            let start = parts[0]
                .parse::<IpAddr>()
                .map_err(|_| Error::invalid_ip(parts[0], "Invalid IP address in range start"))?;
            let end = parts[1]
                .parse::<IpAddr>()
                .map_err(|_| Error::invalid_ip(parts[1], "Invalid IP address in range end"))?;

            return Ok(AddrOrRange::Range(start, end));
        }

        // Single address
        s.parse::<IpAddr>()
            .map(AddrOrRange::Addr)
            .map_err(|_| Error::invalid_ip(s, "Invalid IP address"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RulePorts {
    Single(u16),
    Range(u16, u16),
}

impl Serialize for RulePorts {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for RulePorts {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for RulePorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RulePorts::Single(port) => write!(f, "{}", port),
            RulePorts::Range(start, end) => write!(f, "{}-{}", start, end),
        }
    }
}

impl FromStr for RulePorts {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.contains('-') {
            let parts: Vec<&str> = s.split('-').collect();
            if parts.len() != 2 {
                return Err(Error::config(format!("Invalid port range: {}", s)));
            }

            let start = parts[0]
                .parse::<u16>()
                .map_err(|_| Error::config(format!("Invalid port: {}", parts[0])))?;
            let end = parts[1]
                .parse::<u16>()
                .map_err(|_| Error::config(format!("Invalid port: {}", parts[1])))?;

            if start > end {
                return Err(Error::config(format!(
                    "Invalid port range: start {} > end {}",
                    start, end
                )));
            }

            Ok(RulePorts::Range(start, end))
        } else {
            let port = s
                .parse::<u16>()
                .map_err(|_| Error::config(format!("Invalid port: {}", s)))?;
            Ok(RulePorts::Single(port))
        }
    }
}

impl Config {
    pub fn new() -> Self {
        Self {
            mapped_ports: MappedPorts::default(),
            output: Vec::new(),
        }
    }

    pub fn with_mapped_ports(mut self, mapped_ports: MappedPorts) -> Self {
        self.mapped_ports = mapped_ports;
        self
    }

    pub fn with_output(mut self, output: Vec<RuleConfig>) -> Self {
        self.output = output;
        self
    }

    pub fn add_output_rule(mut self, rule: RuleConfig) -> Self {
        self.output.push(rule);
        self
    }

    pub fn validate(&self) -> Result<()> {
        // Validate output rules
        for (i, rule) in self.output.iter().enumerate() {
            Self::validate_rule(rule, i)?;
        }

        // Validate mapped ports
        Self::validate_mapped_ports(&self.mapped_ports)?;

        // Verdicts are already validated in their custom deserializers

        Ok(())
    }

    fn validate_rule(rule: &RuleConfig, index: usize) -> Result<()> {
        if rule.ips.is_empty()
            && rule.container.is_empty()
            && rule.src_ports.is_empty()
            && rule.dst_ports.is_empty()
        {
            return Err(Error::config(format!("Output rule #{} is empty", index)));
        }

        if !rule.ips.is_empty() && !rule.container.is_empty() {
            return Err(Error::config(format!(
                "Output rule #{}: 'ips' and 'container' are mutually exclusive",
                index
            )));
        }

        if rule.network.is_empty() && !rule.container.is_empty() {
            return Err(Error::config(format!(
                "Output rule #{}: 'network' must be set when 'container' is set",
                index
            )));
        }

        // Validate IP family consistency
        if !rule.ips.is_empty() {
            Self::validate_ip_family_consistency(&rule.ips, &format!("Output rule #{}", index))?;
        }

        if !rule.src_ports.is_empty() && rule.dst_ports.is_empty() {
            return Err(Error::config(format!(
                "Output rule #{}: 'dst_ports' must be set when 'src_ports' is set",
                index
            )));
        }

        if rule.dst_ports.is_empty() {
            return Err(Error::config(format!(
                "Output rule #{}: 'dst_ports' must be set when 'proto' is set",
                index
            )));
        }

        Self::validate_verdict(&rule.verdict)?;

        Ok(())
    }

    fn validate_verdict(verdict: &ConfigVerdict) -> Result<()> {
        if !verdict.chain.is_empty() && verdict.queue != 0 {
            return Err(Error::config(
                "'chain' and 'queue' are mutually exclusive".to_string(),
            ));
        }

        if verdict.queue == 0 && verdict.input_est_queue != 0 {
            return Err(Error::config(
                "'queue' must be set when 'input_est_queue' is set".to_string(),
            ));
        }

        if verdict.queue == 0 && verdict.output_est_queue != 0 {
            return Err(Error::config(
                "'queue' must be set when 'output_est_queue' is set".to_string(),
            ));
        }

        if verdict.input_est_queue == 0 && verdict.output_est_queue != 0 {
            return Err(Error::config(
                "'input_est_queue' must be set when 'output_est_queue' is set".to_string(),
            ));
        }

        if verdict.output_est_queue == 0 && verdict.input_est_queue != 0 {
            return Err(Error::config(
                "'output_est_queue' must be set when 'input_est_queue' is set".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_mapped_ports(mapped_ports: &MappedPorts) -> Result<()> {
        // Validate external IPs consistency
        if !mapped_ports.external.ips.is_empty() {
            Self::validate_ip_family_consistency(
                &mapped_ports.external.ips,
                "External mapped ports",
            )?;
        }

        // Note: localhost should not have IPs field per the spec
        // This is enforced by not having an ips field in LocalRules struct

        Ok(())
    }

    fn validate_ip_family_consistency(ips: &[AddrOrRange], context: &str) -> Result<()> {
        if ips.is_empty() {
            return Ok(());
        }

        // Determine the family of the first IP
        let first_is_ipv4 = match &ips[0] {
            AddrOrRange::Addr(addr) => addr.is_ipv4(),
            AddrOrRange::Range(start, _) => start.is_ipv4(),
            AddrOrRange::Net(net) => match net {
                IpNet::V4(_) => true,
                IpNet::V6(_) => false,
            },
        };

        // Check that all subsequent IPs match the first family
        for ip in ips.iter().skip(1) {
            let is_ipv4 = match ip {
                AddrOrRange::Addr(addr) => addr.is_ipv4(),
                AddrOrRange::Range(start, _) => start.is_ipv4(),
                AddrOrRange::Net(net) => match net {
                    IpNet::V4(_) => true,
                    IpNet::V6(_) => false,
                },
            };

            if is_ipv4 != first_is_ipv4 {
                return Err(Error::config(format!(
                    "{}: Mixed IPv4 and IPv6 addresses are not supported. {} is {}, but {} is {}",
                    context,
                    ips[0],
                    if first_is_ipv4 { "IPv4" } else { "IPv6" },
                    ip,
                    if is_ipv4 { "IPv4" } else { "IPv6" }
                )));
            }
        }

        Ok(())
    }
}

// Custom Deserialize implementation with validation
impl<'de> Deserialize<'de> for Config {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // First deserialize to a temporary structure
        #[derive(Deserialize)]
        struct TempConfig {
            #[serde(default)]
            mapped_ports: MappedPorts,
            #[serde(default)]
            output: Vec<RuleConfig>,
        }

        let temp = TempConfig::deserialize(deserializer)?;

        // Create the actual Config
        let config = Config {
            mapped_ports: temp.mapped_ports,
            output: temp.output,
        };

        // Basic structural validation - component types handle their own field validation
        config.validate().map_err(serde::de::Error::custom)?;

        Ok(config)
    }
}
