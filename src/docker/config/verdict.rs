use bon::Builder;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Default, Serialize, Builder)]
pub struct ConfigVerdict {
    #[serde(default)]
    #[builder(default)]
    pub chain: String,
    #[serde(default)]
    #[builder(default)]
    pub queue: u16,
    #[serde(default)]
    #[builder(default)]
    pub input_est_queue: u16,
    #[serde(default)]
    #[builder(default)]
    pub output_est_queue: u16,

    #[serde(skip)]
    #[builder(default = false)]
    pub drop: bool,
}
// Custom Deserialize for ConfigVerdict with validation
impl<'de> Deserialize<'de> for ConfigVerdict {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct TempConfigVerdict {
            #[serde(default)]
            chain: String,
            #[serde(default)]
            queue: u16,
            #[serde(default)]
            input_est_queue: u16,
            #[serde(default)]
            output_est_queue: u16,
            #[serde(skip)]
            drop: bool,
        }

        let temp = TempConfigVerdict::deserialize(deserializer)?;

        // Validate verdict configuration
        if !temp.chain.is_empty() && temp.queue != 0 {
            return Err(serde::de::Error::custom(
                super::ValidationError::InvalidFieldValue {
                    field: "verdict".to_string(),
                    reason: "'chain' and 'queue' are mutually exclusive".to_string(),
                    value: format!("chain: '{}', queue: {}", temp.chain, temp.queue),
                    expected_format: Some("Either 'chain' or 'queue', not both".to_string()),
                },
            ));
        }

        if temp.queue == 0 && temp.input_est_queue != 0 {
            return Err(serde::de::Error::custom(
                super::ValidationError::MissingRequiredField {
                    field: "queue".to_string(),
                    context: "verdict with input_est_queue set".to_string(),
                },
            ));
        }

        if temp.queue == 0 && temp.output_est_queue != 0 {
            return Err(serde::de::Error::custom(
                super::ValidationError::MissingRequiredField {
                    field: "queue".to_string(),
                    context: "verdict with output_est_queue set".to_string(),
                },
            ));
        }

        if temp.input_est_queue == 0 && temp.output_est_queue != 0 {
            return Err(serde::de::Error::custom(
                super::ValidationError::InvalidFieldValue {
                    field: "verdict".to_string(),
                    reason: "'input_est_queue' must be set when 'output_est_queue' is set"
                        .to_string(),
                    value: format!("output_est_queue: {}", temp.output_est_queue),
                    expected_format: Some(
                        "Both input_est_queue and output_est_queue, or neither".to_string(),
                    ),
                },
            ));
        }

        if temp.output_est_queue == 0 && temp.input_est_queue != 0 {
            return Err(serde::de::Error::custom(
                super::ValidationError::InvalidFieldValue {
                    field: "verdict".to_string(),
                    reason: "'output_est_queue' must be set when 'input_est_queue' is set"
                        .to_string(),
                    value: format!("input_est_queue: {}", temp.input_est_queue),
                    expected_format: Some(
                        "Both input_est_queue and output_est_queue, or neither".to_string(),
                    ),
                },
            ));
        }

        Ok(ConfigVerdict {
            chain: temp.chain,
            queue: temp.queue,
            input_est_queue: temp.input_est_queue,
            output_est_queue: temp.output_est_queue,
            drop: temp.drop,
        })
    }
}
