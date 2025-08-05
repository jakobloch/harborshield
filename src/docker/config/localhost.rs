use crate::Result;
use crate::docker::config::ToNftablesRule;
use bon::Builder;
use nftables::stmt::Statement;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Default, Serialize, Builder)]
pub struct LocalRules {
    #[serde(default)]
    #[builder(default)]
    pub allow: bool,
    #[serde(default)]
    #[builder(default)]
    pub log_prefix: String,
    #[serde(default)]
    #[builder(default)]
    pub verdict: super::ConfigVerdict,
    #[serde(default = "default_true")]
    #[builder(default = true)]
    pub include_gateway_ips: bool,
    #[serde(default = "default_true")]
    #[builder(default = true)]
    pub enable_nat: bool,
}

// Custom Deserialize for LocalRules with validation
impl<'de> Deserialize<'de> for LocalRules {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct TempLocalRules {
            #[serde(default)]
            allow: bool,
            #[serde(default)]
            log_prefix: String,
            #[serde(default)]
            verdict: super::ConfigVerdict,
            #[serde(default = "super::default_true")]
            include_gateway_ips: bool,
            #[serde(default = "super::default_true")]
            enable_nat: bool,
        }

        let temp = TempLocalRules::deserialize(deserializer)?;

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

        Ok(LocalRules {
            allow: temp.allow,
            log_prefix: temp.log_prefix,
            verdict: temp.verdict,
            include_gateway_ips: temp.include_gateway_ips,
            enable_nat: temp.enable_nat,
        })
    }
}

/// Implementation for LocalRules (localhost mapped ports)
impl ToNftablesRule for LocalRules {
    fn to_nftables_statements(&self) -> Result<Vec<Statement<'static>>> {
        let mut statements = Vec::new();

        // Match source IP as localhost
        statements.push(Self::match_src_ip("127.0.0.1"));

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
