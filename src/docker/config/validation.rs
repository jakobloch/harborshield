pub mod error {
    use std::net::IpAddr;
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum ValidationError {
        // Configuration validation errors
        #[error("Invalid configuration at line {line}: {message}")]
        InvalidConfig {
            line: usize,
            message: String,
            field: Option<String>,
            suggestion: Option<String>,
        },

        #[error("Missing required field '{field}' in {context}")]
        MissingRequiredField { field: String, context: String },

        #[error("Invalid field value for '{field}': {reason}")]
        InvalidFieldValue {
            field: String,
            reason: String,
            value: String,
            expected_format: Option<String>,
        },

        #[error("Configuration schema error: {message}")]
        SchemaError {
            message: String,
            schema_version: Option<String>,
        },

        // Rule validation errors
        #[error("Invalid rule: {message}")]
        InvalidRule {
            message: String,
            rule_type: String,
            rule_text: String,
            position: Option<usize>,
        },

        #[error("Rule limit exceeded: {current} rules (max: {limit}) for {context}")]
        RuleLimitExceeded {
            current: usize,
            limit: usize,
            context: String,
        },

        #[error("Conflicting rules detected: {description}")]
        ConflictingRules {
            description: String,
            rule1: String,
            rule2: String,
            conflict_type: String,
        },

        #[error("Invalid rule syntax at position {position}: {message}")]
        InvalidRuleSyntax {
            position: usize,
            message: String,
            rule_text: String,
            expected: Option<String>,
        },

        // Network validation errors
        #[error("Invalid IP address '{input}': {reason}")]
        InvalidIpAddress {
            input: String,
            reason: String,
            expected_format: String,
        },

        #[error("Invalid port number {port}: {reason}")]
        InvalidPort { port: String, reason: String },

        #[error("Invalid port range {range}: {reason}")]
        InvalidPortRange { range: String, reason: String },

        #[error("Blocked IP address: {ip} is in blocked range {range}")]
        BlockedIpAddress { ip: IpAddr, range: String },

        #[error("Invalid network CIDR '{cidr}': {reason}")]
        InvalidCidr { cidr: String, reason: String },

        #[error("Network overlap detected: {network1} overlaps with {network2}")]
        NetworkOverlap { network1: String, network2: String },

        // Container validation errors
        #[error("Invalid container label '{label}': {reason}")]
        InvalidContainerLabel {
            label: String,
            reason: String,
            container_id: Option<String>,
        },

        #[error("Container name '{name}' invalid: {reason}")]
        InvalidContainerName { name: String, reason: String },

        #[error("Container '{container}' missing required label '{label}'")]
        MissingContainerLabel { container: String, label: String },

        // Security validation errors
        #[error("Security policy violation: {policy} - {violation}")]
        SecurityPolicyViolation {
            policy: String,
            violation: String,
            severity: String,
        },

        #[error("Privileged operation not allowed: {operation}")]
        PrivilegedOperationDenied {
            operation: String,
            required_capability: Option<String>,
        },

        #[error("Insecure configuration detected: {issue}")]
        InsecureConfiguration {
            issue: String,
            recommendation: String,
            risk_level: String,
        },

        // Permission validation errors
        #[error("Insufficient permissions for {resource}: requires {required}, has {actual}")]
        InsufficientPermissions {
            resource: String,
            required: String,
            actual: String,
        },

        #[error("Invalid permission string '{permission}': {reason}")]
        InvalidPermission { permission: String, reason: String },

        // Resource validation errors
        #[error("Resource limit validation failed for {resource}: {reason}")]
        ResourceLimitInvalid {
            resource: String,
            reason: String,
            requested: String,
            available: String,
        },

        #[error("Invalid resource specification '{spec}': {reason}")]
        InvalidResourceSpec { spec: String, reason: String },

        // Protocol validation errors
        #[error("Invalid protocol '{protocol}': {reason}")]
        InvalidProtocol {
            protocol: String,
            reason: String,
            supported_protocols: Vec<String>,
        },

        #[error("Protocol mismatch: expected {expected}, got {actual}")]
        ProtocolMismatch { expected: String, actual: String },

        // General validation errors
        #[error("Validation failed: {message}")]
        General { message: String },

        #[error("Multiple validation errors: {count} errors found")]
        Multiple {
            count: usize,
            errors: Vec<String>,
            first_error: String,
        },
    }

    impl ValidationError {
        // Helper constructors
        pub fn invalid_config(line: usize, message: impl Into<String>) -> Self {
            Self::InvalidConfig {
                line,
                message: message.into(),
                field: None,
                suggestion: None,
            }
        }

        pub fn invalid_config_with_suggestion(
            line: usize,
            message: impl Into<String>,
            field: impl Into<String>,
            suggestion: impl Into<String>,
        ) -> Self {
            Self::InvalidConfig {
                line,
                message: message.into(),
                field: Some(field.into()),
                suggestion: Some(suggestion.into()),
            }
        }

        pub fn invalid_rule(
            message: impl Into<String>,
            rule_type: impl Into<String>,
            rule_text: impl Into<String>,
        ) -> Self {
            Self::InvalidRule {
                message: message.into(),
                rule_type: rule_type.into(),
                rule_text: rule_text.into(),
                position: None,
            }
        }

        pub fn invalid_ip_address(input: impl Into<String>, reason: impl Into<String>) -> Self {
            Self::InvalidIpAddress {
                input: input.into(),
                reason: reason.into(),
                expected_format: "Valid IPv4 (e.g., 192.168.1.1) or IPv6 address".to_string(),
            }
        }

        pub fn security_violation(
            policy: impl Into<String>,
            violation: impl Into<String>,
            severity: impl Into<String>,
        ) -> Self {
            Self::SecurityPolicyViolation {
                policy: policy.into(),
                violation: violation.into(),
                severity: severity.into(),
            }
        }

        pub fn multiple_errors(errors: Vec<String>) -> Self {
            let count = errors.len();
            let first_error = errors
                .first()
                .cloned()
                .unwrap_or_else(|| "No errors".to_string());
            Self::Multiple {
                count,
                errors,
                first_error,
            }
        }

        // Check if error is security-related
        pub fn is_security_related(&self) -> bool {
            matches!(
                self,
                Self::SecurityPolicyViolation { .. }
                    | Self::PrivilegedOperationDenied { .. }
                    | Self::InsecureConfiguration { .. }
                    | Self::BlockedIpAddress { .. }
            )
        }

        // Get error severity
        pub fn severity(&self) -> &str {
            match self {
                Self::SecurityPolicyViolation { severity, .. } => severity,
                Self::InsecureConfiguration { risk_level, .. } => risk_level,
                Self::PrivilegedOperationDenied { .. } => "high",
                Self::BlockedIpAddress { .. } => "high",
                Self::ConflictingRules { .. } => "medium",
                Self::RuleLimitExceeded { .. } => "medium",
                _ => "low",
            }
        }
    }
}
