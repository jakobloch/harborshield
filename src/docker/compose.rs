use petgraph::algo::{is_cyclic_directed, toposort};
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;
use tracing::warn;

/// Docker Compose label constants
pub const COMPOSE_PROJECT_LABEL: &str = "com.docker.compose.project";
pub const COMPOSE_SERVICE_LABEL: &str = "com.docker.compose.service";
pub const COMPOSE_CONTAINER_NUMBER_LABEL: &str = "com.docker.compose.container-number";
pub const COMPOSE_DEPENDS_ON_LABEL: &str = "com.docker.compose.depends_on";
pub const COMPOSE_VERSION_LABEL: &str = "com.docker.compose.version";
pub const COMPOSE_ONEOFF_LABEL: &str = "com.docker.compose.oneoff";
pub const COMPOSE_CONFIG_HASH_LABEL: &str = "com.docker.compose.config-hash";
pub const COMPOSE_PROJECT_CONFIG_FILES_LABEL: &str = "com.docker.compose.project.config_files";
pub const COMPOSE_PROJECT_WORKING_DIR_LABEL: &str = "com.docker.compose.project.working_dir";

/// Information extracted from Docker Compose labels
#[derive(Debug, Clone, Default)]
pub struct ComposeInfo {
    pub project: Option<String>,
    pub service: Option<String>,
    pub container_number: Option<u32>,
    pub depends_on: Vec<String>,
    pub version: Option<String>,
    pub is_oneoff: bool,
}

impl ComposeInfo {
    /// Extract compose information from container labels
    pub fn from_labels(labels: &HashMap<String, String>) -> Self {
        let mut info = Self::default();

        // Extract basic compose information
        info.project = labels.get(COMPOSE_PROJECT_LABEL).cloned();
        info.service = labels.get(COMPOSE_SERVICE_LABEL).cloned();

        // Parse container number
        if let Some(num_str) = labels.get(COMPOSE_CONTAINER_NUMBER_LABEL) {
            info.container_number = num_str.parse().ok();
        }

        // Parse dependencies
        if let Some(deps_str) = labels.get(COMPOSE_DEPENDS_ON_LABEL) {
            info.depends_on = deps_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        // Extract version
        info.version = labels.get(COMPOSE_VERSION_LABEL).cloned();

        // Check if it's a one-off container
        info.is_oneoff = labels
            .get(COMPOSE_ONEOFF_LABEL)
            .map(|v| v == "True" || v == "true")
            .unwrap_or(false);

        info
    }

    /// Generate aliases based on compose information
    pub fn generate_aliases(&self) -> Vec<String> {
        let mut aliases = Vec::new();

        if let Some(service) = &self.service {
            // Add the service name as an alias
            aliases.push(service.clone());

            // Add project-qualified service name if project is specified
            if let Some(project) = &self.project {
                aliases.push(format!("{}.{}", service, project));
                aliases.push(format!("{}_{}", project, service));
            }

            // Add numbered service name if container number is specified and > 1
            if let Some(num) = self.container_number {
                if num > 1 {
                    aliases.push(format!("{}_{}", service, num));

                    if let Some(project) = &self.project {
                        aliases.push(format!("{}_{}_{}", project, service, num));
                    }
                }
            }
        }

        aliases
    }

    /// Check if this container has dependencies
    pub fn has_dependencies(&self) -> bool {
        !self.depends_on.is_empty()
    }

    /// Get a display name for the container
    pub fn display_name(&self) -> String {
        match (&self.project, &self.service, self.container_number) {
            (Some(project), Some(service), Some(num)) if num > 1 => {
                format!("{}_{}_{}", project, service, num)
            }
            (Some(project), Some(service), _) => {
                format!("{}_{}", project, service)
            }
            (None, Some(service), Some(num)) if num > 1 => {
                format!("{}_{}", service, num)
            }
            (None, Some(service), _) => service.clone(),
            _ => String::new(),
        }
    }
}

/// Sort containers by their Docker Compose dependencies using topological sort
pub fn sort_by_dependencies(containers: &mut [bollard::models::ContainerSummary]) {
    // Build a graph of container dependencies
    let mut graph = DiGraph::<String, ()>::new();
    let mut service_to_node: HashMap<String, NodeIndex> = HashMap::new();
    let mut node_to_index: HashMap<NodeIndex, usize> = HashMap::new();

    // First pass: add all containers as nodes
    for (index, container) in containers.iter().enumerate() {
        let labels = container.labels.as_ref().cloned().unwrap_or_default();
        let info = ComposeInfo::from_labels(&labels);

        if let Some(service) = &info.service {
            let node = graph.add_node(service.clone());
            service_to_node.insert(service.clone(), node);
            node_to_index.insert(node, index);
        }
    }

    // Second pass: add edges for dependencies
    for container in containers.iter() {
        let labels = container.labels.as_ref().cloned().unwrap_or_default();
        let info = ComposeInfo::from_labels(&labels);

        if let Some(service) = &info.service {
            if let Some(&from_node) = service_to_node.get(service) {
                for dep in &info.depends_on {
                    if let Some(&to_node) = service_to_node.get(dep) {
                        // Edge direction: from dependent to dependency
                        // This ensures dependencies come before dependents in topological sort
                        graph.add_edge(from_node, to_node, ());
                    } else {
                        warn!(
                            "Container '{}' depends on '{}', but '{}' was not found in the container list",
                            service, dep, dep
                        );
                    }
                }
            }
        }
    }

    // Check for circular dependencies
    if is_cyclic_directed(&graph) {
        warn!(
            "Circular dependencies detected in Docker Compose containers. Falling back to simple sort."
        );
        // Fall back to the simple sort
        sort_by_dependencies_simple(containers);
        return;
    }

    // Perform topological sort
    match toposort(&graph, None) {
        Ok(sorted_nodes) => {
            // Create a new order based on the topological sort
            let mut sorted_containers = Vec::with_capacity(containers.len());
            let mut processed_indices = std::collections::HashSet::new();

            // Add containers in topologically sorted order (reversed because dependencies should come first)
            for node in sorted_nodes.into_iter().rev() {
                if let Some(&index) = node_to_index.get(&node) {
                    sorted_containers.push(containers[index].clone());
                    processed_indices.insert(index);
                }
            }

            // Add any containers that weren't in the graph (e.g., containers without compose labels)
            for (index, container) in containers.iter().enumerate() {
                if !processed_indices.contains(&index) {
                    sorted_containers.push(container.clone());
                }
            }

            // Replace the original vector with the sorted one
            containers.clone_from_slice(&sorted_containers);
        }
        Err(_) => {
            warn!("Failed to perform topological sort. This should not happen after cycle check.");
            sort_by_dependencies_simple(containers);
        }
    }
}

/// Simple sort implementation (original behavior)
fn sort_by_dependencies_simple(containers: &mut [bollard::models::ContainerSummary]) {
    containers.sort_by(|a, b| {
        let a_labels = a.labels.as_ref().cloned().unwrap_or_default();
        let b_labels = b.labels.as_ref().cloned().unwrap_or_default();

        let a_info = ComposeInfo::from_labels(&a_labels);
        let b_info = ComposeInfo::from_labels(&b_labels);

        match (a_info.has_dependencies(), b_info.has_dependencies()) {
            (false, true) => std::cmp::Ordering::Less, // No deps come first
            (true, false) => std::cmp::Ordering::Greater, // Has deps come later
            _ => std::cmp::Ordering::Equal,
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compose_info_from_labels() {
        let mut labels = HashMap::new();
        labels.insert(COMPOSE_PROJECT_LABEL.to_string(), "myproject".to_string());
        labels.insert(COMPOSE_SERVICE_LABEL.to_string(), "web".to_string());
        labels.insert(COMPOSE_CONTAINER_NUMBER_LABEL.to_string(), "2".to_string());
        labels.insert(
            COMPOSE_DEPENDS_ON_LABEL.to_string(),
            "db, cache".to_string(),
        );
        labels.insert(COMPOSE_VERSION_LABEL.to_string(), "2.4".to_string());
        labels.insert(COMPOSE_ONEOFF_LABEL.to_string(), "False".to_string());

        let info = ComposeInfo::from_labels(&labels);

        assert_eq!(info.project, Some("myproject".to_string()));
        assert_eq!(info.service, Some("web".to_string()));
        assert_eq!(info.container_number, Some(2));
        assert_eq!(info.depends_on, vec!["db", "cache"]);
        assert_eq!(info.version, Some("2.4".to_string()));
        assert!(!info.is_oneoff);
    }

    #[test]
    fn test_generate_aliases() {
        let info = ComposeInfo {
            project: Some("myproject".to_string()),
            service: Some("web".to_string()),
            container_number: Some(2),
            ..Default::default()
        };

        let aliases = info.generate_aliases();
        assert!(aliases.contains(&"web".to_string()));
        assert!(aliases.contains(&"web.myproject".to_string()));
        assert!(aliases.contains(&"myproject_web".to_string()));
        assert!(aliases.contains(&"web_2".to_string()));
        assert!(aliases.contains(&"myproject_web_2".to_string()));
    }

    #[test]
    fn test_generate_aliases_single_container() {
        let info = ComposeInfo {
            project: Some("myproject".to_string()),
            service: Some("db".to_string()),
            container_number: Some(1),
            ..Default::default()
        };

        let aliases = info.generate_aliases();
        assert!(aliases.contains(&"db".to_string()));
        assert!(aliases.contains(&"db.myproject".to_string()));
        assert!(aliases.contains(&"myproject_db".to_string()));
        // Should not contain numbered aliases for container_number = 1
        assert!(!aliases.contains(&"db_1".to_string()));
    }

    #[test]
    fn test_display_name() {
        let info1 = ComposeInfo {
            project: Some("myproject".to_string()),
            service: Some("web".to_string()),
            container_number: Some(2),
            ..Default::default()
        };
        assert_eq!(info1.display_name(), "myproject_web_2");

        let info2 = ComposeInfo {
            project: Some("myproject".to_string()),
            service: Some("db".to_string()),
            container_number: Some(1),
            ..Default::default()
        };
        assert_eq!(info2.display_name(), "myproject_db");

        let info3 = ComposeInfo {
            service: Some("redis".to_string()),
            ..Default::default()
        };
        assert_eq!(info3.display_name(), "redis");
    }

    #[test]
    fn test_sort_by_dependencies() {
        use bollard::models::ContainerSummary;

        let mut containers = vec![
            ContainerSummary {
                id: Some("web".to_string()),
                labels: Some(HashMap::from([
                    (COMPOSE_SERVICE_LABEL.to_string(), "web".to_string()),
                    (COMPOSE_DEPENDS_ON_LABEL.to_string(), "db".to_string()),
                ])),
                ..Default::default()
            },
            ContainerSummary {
                id: Some("cache".to_string()),
                labels: Some(HashMap::from([(
                    COMPOSE_SERVICE_LABEL.to_string(),
                    "cache".to_string(),
                )])),
                ..Default::default()
            },
            ContainerSummary {
                id: Some("db".to_string()),
                labels: Some(HashMap::from([(
                    COMPOSE_SERVICE_LABEL.to_string(),
                    "db".to_string(),
                )])),
                ..Default::default()
            },
        ];

        sort_by_dependencies(&mut containers);

        // Containers without dependencies should come first
        // db should come before web since web depends on db
        let ids: Vec<&str> = containers
            .iter()
            .filter_map(|c| c.id.as_ref().map(|s| s.as_str()))
            .collect();

        // cache and db have no dependencies, so they should come first
        // web depends on db, so it should come last
        assert!(
            ids.iter().position(|&id| id == "db").unwrap()
                < ids.iter().position(|&id| id == "web").unwrap()
        );
    }

    #[test]
    fn test_sort_by_dependencies_chain() {
        use bollard::models::ContainerSummary;

        // Test a->b->c dependency chain
        let mut containers = vec![
            ContainerSummary {
                id: Some("c".to_string()),
                labels: Some(HashMap::from([(
                    COMPOSE_SERVICE_LABEL.to_string(),
                    "c".to_string(),
                )])),
                ..Default::default()
            },
            ContainerSummary {
                id: Some("a".to_string()),
                labels: Some(HashMap::from([
                    (COMPOSE_SERVICE_LABEL.to_string(), "a".to_string()),
                    (COMPOSE_DEPENDS_ON_LABEL.to_string(), "b".to_string()),
                ])),
                ..Default::default()
            },
            ContainerSummary {
                id: Some("b".to_string()),
                labels: Some(HashMap::from([
                    (COMPOSE_SERVICE_LABEL.to_string(), "b".to_string()),
                    (COMPOSE_DEPENDS_ON_LABEL.to_string(), "c".to_string()),
                ])),
                ..Default::default()
            },
        ];

        sort_by_dependencies(&mut containers);

        let ids: Vec<&str> = containers
            .iter()
            .filter_map(|c| c.id.as_ref().map(|s| s.as_str()))
            .collect();

        // Order should be c, b, a
        assert_eq!(ids, vec!["c", "b", "a"]);
    }

    #[test]
    fn test_sort_by_dependencies_circular() {
        use bollard::models::ContainerSummary;

        // Test circular dependency: a->b->c->a
        let mut containers = vec![
            ContainerSummary {
                id: Some("a".to_string()),
                labels: Some(HashMap::from([
                    (COMPOSE_SERVICE_LABEL.to_string(), "a".to_string()),
                    (COMPOSE_DEPENDS_ON_LABEL.to_string(), "b".to_string()),
                ])),
                ..Default::default()
            },
            ContainerSummary {
                id: Some("b".to_string()),
                labels: Some(HashMap::from([
                    (COMPOSE_SERVICE_LABEL.to_string(), "b".to_string()),
                    (COMPOSE_DEPENDS_ON_LABEL.to_string(), "c".to_string()),
                ])),
                ..Default::default()
            },
            ContainerSummary {
                id: Some("c".to_string()),
                labels: Some(HashMap::from([
                    (COMPOSE_SERVICE_LABEL.to_string(), "c".to_string()),
                    (COMPOSE_DEPENDS_ON_LABEL.to_string(), "a".to_string()),
                ])),
                ..Default::default()
            },
        ];

        // Should fall back to simple sort without panicking
        sort_by_dependencies(&mut containers);

        // All containers have dependencies, so order might not change much
        // The important thing is that it doesn't panic
        assert_eq!(containers.len(), 3);
    }

    #[test]
    fn test_sort_by_dependencies_missing_dependency() {
        use bollard::models::ContainerSummary;

        // Test when a container depends on a non-existent service
        let mut containers = vec![
            ContainerSummary {
                id: Some("web".to_string()),
                labels: Some(HashMap::from([
                    (COMPOSE_SERVICE_LABEL.to_string(), "web".to_string()),
                    (
                        COMPOSE_DEPENDS_ON_LABEL.to_string(),
                        "db,nonexistent".to_string(),
                    ),
                ])),
                ..Default::default()
            },
            ContainerSummary {
                id: Some("db".to_string()),
                labels: Some(HashMap::from([(
                    COMPOSE_SERVICE_LABEL.to_string(),
                    "db".to_string(),
                )])),
                ..Default::default()
            },
        ];

        sort_by_dependencies(&mut containers);

        let ids: Vec<&str> = containers
            .iter()
            .filter_map(|c| c.id.as_ref().map(|s| s.as_str()))
            .collect();

        // db should still come before web
        assert!(
            ids.iter().position(|&id| id == "db").unwrap()
                < ids.iter().position(|&id| id == "web").unwrap()
        );
    }

    #[test]
    fn test_sort_by_dependencies_complex() {
        use bollard::models::ContainerSummary;

        // Test complex dependency graph
        // frontend -> api -> (db, cache)
        // worker -> (api, queue)
        // queue has no dependencies
        let mut containers = vec![
            ContainerSummary {
                id: Some("worker".to_string()),
                labels: Some(HashMap::from([
                    (COMPOSE_SERVICE_LABEL.to_string(), "worker".to_string()),
                    (
                        COMPOSE_DEPENDS_ON_LABEL.to_string(),
                        "api,queue".to_string(),
                    ),
                ])),
                ..Default::default()
            },
            ContainerSummary {
                id: Some("frontend".to_string()),
                labels: Some(HashMap::from([
                    (COMPOSE_SERVICE_LABEL.to_string(), "frontend".to_string()),
                    (COMPOSE_DEPENDS_ON_LABEL.to_string(), "api".to_string()),
                ])),
                ..Default::default()
            },
            ContainerSummary {
                id: Some("api".to_string()),
                labels: Some(HashMap::from([
                    (COMPOSE_SERVICE_LABEL.to_string(), "api".to_string()),
                    (COMPOSE_DEPENDS_ON_LABEL.to_string(), "db,cache".to_string()),
                ])),
                ..Default::default()
            },
            ContainerSummary {
                id: Some("db".to_string()),
                labels: Some(HashMap::from([(
                    COMPOSE_SERVICE_LABEL.to_string(),
                    "db".to_string(),
                )])),
                ..Default::default()
            },
            ContainerSummary {
                id: Some("cache".to_string()),
                labels: Some(HashMap::from([(
                    COMPOSE_SERVICE_LABEL.to_string(),
                    "cache".to_string(),
                )])),
                ..Default::default()
            },
            ContainerSummary {
                id: Some("queue".to_string()),
                labels: Some(HashMap::from([(
                    COMPOSE_SERVICE_LABEL.to_string(),
                    "queue".to_string(),
                )])),
                ..Default::default()
            },
        ];

        sort_by_dependencies(&mut containers);

        let ids: Vec<&str> = containers
            .iter()
            .filter_map(|c| c.id.as_ref().map(|s| s.as_str()))
            .collect();

        // Check key ordering constraints
        let pos = |id| ids.iter().position(|&x| x == id).unwrap();

        // db and cache should come before api
        assert!(pos("db") < pos("api"));
        assert!(pos("cache") < pos("api"));

        // api should come before frontend and worker
        assert!(pos("api") < pos("frontend"));
        assert!(pos("api") < pos("worker"));

        // queue should come before worker
        assert!(pos("queue") < pos("worker"));
    }
}
