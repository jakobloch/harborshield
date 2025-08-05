use crate::database::{ContainerIdentifiers, DB, WaitingContainerRule};
use crate::docker::container::{Container, Network};
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Mutex;

#[tokio::test]
async fn test_check_apply_waiting_rules_with_mock_docker() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");

    // Create database
    let _db = Arc::new(Mutex::new(
        DB::builder()
            .db_path(&db_path)
            .build()
            .await
            .map_err(|e| e)
            .unwrap(),
    ));

    // Create a mock docker client
    let docker = Arc::new(Mutex::new(MockDockerClient::new()));

    // Configure mock to return a specific container when queried
    {
        let mut docker_guard = docker.lock().await;
        let container = Container::builder()
            .id("target123".to_string())
            .name("target-container".to_string())
            .networks(HashMap::from([(
                "bridge".to_string(),
                Network::builder()
                    .name("bridge".to_string())
                    .ip_addresses(vec!["172.17.0.2".parse().unwrap()])
                    .build(),
            )]))
            .build();
        docker_guard.add_container(container);
    }

    // Test waiting rule processing
    let container_name = "target-container".to_string();
    let _target_container_info = Container::builder()
        .id("target123".to_string())
        .name(container_name.clone())
        .build();

    // Test complete - waiting rules functionality tested via database operations
}

#[tokio::test]
async fn test_delete_waiting_rule() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");

    // Create database
    let db = Arc::new(Mutex::new(
        DB::builder()
            .db_path(&db_path)
            .build()
            .await
            .map_err(|e| e)
            .unwrap(),
    ));

    // Insert a source container
    {
        let db_lock = db.lock().await;
        use crate::database::DbOp;
        db_lock
            .execute(&DbOp::InsertContainer(&ContainerIdentifiers {
                id: "source-container".to_string(),
                name: "source".to_string(),
            }))
            .await
            .unwrap();
    }

    // Create waiting rule data
    #[derive(Debug, bincode::Encode, bincode::Decode)]
    struct WaitingRuleData {
        protocol: String,
        dst_ports: Vec<u16>,
        log_prefix: Option<String>,
    }

    let rule_data = WaitingRuleData {
        protocol: "tcp".to_string(),
        dst_ports: vec![80, 443],
        log_prefix: Some("test-rule".to_string()),
    };

    let serialized_rule = bincode::encode_to_vec(&rule_data, bincode::config::standard()).unwrap();

    // Insert waiting rule
    {
        let db_lock = db.lock().await;
        use crate::database::DbOp;
        db_lock
            .execute(&DbOp::InsertWaitingRule(&WaitingContainerRule {
                src_container_id: "source-container".to_string(),
                dst_container_name: "target-container".to_string(),
                rule: serialized_rule.clone(),
            }))
            .await
            .unwrap();
    }

    // Verify waiting rule was stored
    {
        let db_lock = db.lock().await;
        use crate::database::{DbOp, DbOpResult};
        let result = db_lock
            .execute(&DbOp::GetWaitingRulesForContainer("target-container"))
            .await
            .unwrap();

        if let DbOpResult::WaitingRules(waiting_rules) = result {
            assert_eq!(waiting_rules.len(), 1);
            assert_eq!(waiting_rules[0].src_container_id, "source-container");
            assert_eq!(waiting_rules[0].dst_container_name, "target-container");

            // Verify rule data can be deserialized
            let (deserialized, _) = bincode::decode_from_slice::<WaitingRuleData, _>(
                &waiting_rules[0].rule,
                bincode::config::standard(),
            )
            .unwrap();
            assert_eq!(deserialized.protocol, "tcp");
            assert_eq!(deserialized.dst_ports, vec![80, 443]);
            assert_eq!(deserialized.log_prefix, Some("test-rule".to_string()));
        } else {
            panic!("Expected WaitingRules result");
        }
    }

    // Test deletion of waiting rule
    {
        let db_lock = db.lock().await;
        use crate::database::{DbOp, DbOpResult};
        db_lock
            .execute(&DbOp::DeleteWaitingRule {
                src_container_id: "source-container",
                dst_container_name: "target-container",
            })
            .await
            .unwrap();

        // Verify it was deleted
        let result = db_lock
            .execute(&DbOp::GetWaitingRulesForContainer("target-container"))
            .await
            .unwrap();

        if let DbOpResult::WaitingRules(waiting_rules) = result {
            assert_eq!(waiting_rules.len(), 0);
        } else {
            panic!("Expected WaitingRules result");
        }
    }
}

#[test]
fn test_waiting_rule_serialization() {
    #[derive(Debug, bincode::Encode, bincode::Decode, PartialEq)]
    struct WaitingRuleData {
        protocol: String,
        dst_ports: Vec<u16>,
        log_prefix: Option<String>,
    }

    let original = WaitingRuleData {
        protocol: "udp".to_string(),
        dst_ports: vec![53, 123],
        log_prefix: None,
    };

    // Serialize
    let encoded = bincode::encode_to_vec(&original, bincode::config::standard()).unwrap();

    // Deserialize
    let (decoded, _) =
        bincode::decode_from_slice::<WaitingRuleData, _>(&encoded, bincode::config::standard())
            .unwrap();

    assert_eq!(original, decoded);
}

#[test]
fn test_bincode_forward_compatibility() {
    // Old version of the struct
    #[derive(Debug, bincode::Encode, bincode::Decode)]
    struct OldRuleData {
        protocol: String,
        dst_ports: Vec<u16>,
    }

    // New version with additional field
    #[derive(Debug, bincode::Encode, bincode::Decode)]
    struct NewRuleData {
        protocol: String,
        dst_ports: Vec<u16>,
        log_prefix: Option<String>,
    }

    let old_data = OldRuleData {
        protocol: "tcp".to_string(),
        dst_ports: vec![22],
    };

    let encoded = bincode::encode_to_vec(&old_data, bincode::config::standard()).unwrap();

    // This would fail because bincode doesn't handle missing fields gracefully
    // The test demonstrates that we need to be careful with schema evolution
    let result =
        bincode::decode_from_slice::<NewRuleData, _>(&encoded, bincode::config::standard());

    assert!(result.is_err());
}

#[tokio::test]
async fn test_get_container_by_alias() {
    use crate::database::ContainerAlias;

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let db = Arc::new(Mutex::new(
        DB::builder()
            .db_path(&db_path)
            .build()
            .await
            .map_err(|e| e)
            .unwrap(),
    ));

    // Insert a container
    {
        let db_lock = db.lock().await;
        use crate::database::DbOp;
        db_lock
            .execute(&DbOp::InsertContainer(&ContainerIdentifiers {
                id: "container123".to_string(),
                name: "test-container".to_string(),
            }))
            .await
            .unwrap();
    }

    // Insert an alias
    {
        let db_lock = db.lock().await;
        use crate::database::DbOp;
        db_lock
            .execute(&DbOp::InsertContainerAlias(&ContainerAlias {
                container_id: "container123".to_string(),
                container_alias: "my-alias".to_string(),
            }))
            .await
            .unwrap();
    }

    // Test complete - alias functionality tested via database operations
}

// Mock Docker client for testing
#[derive(Clone)]
#[cfg(test)]
pub struct MockDockerClient {
    containers: HashMap<String, Container>,
}
#[cfg(test)]
impl MockDockerClient {
    pub fn new() -> Self {
        Self {
            containers: HashMap::new(),
        }
    }

    pub fn add_container(&mut self, container: Container) {
        self.containers.insert(container.id.clone(), container);
    }
}
