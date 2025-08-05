#[cfg(test)]
mod tests {
    use super::super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_tracker() -> Tracker {
        Tracker::builder().build()
    }

    fn create_test_container(id: &str, name: &str) -> Container {
        Container::builder()
            .id(id.to_owned())
            .name(name.to_owned())
            .build()
    }

    #[test]
    fn test_add_and_get_container() {
        let tracker = create_test_tracker();
        let container = create_test_container("test123", "test-container");

        tracker.add_container(container.clone()).unwrap();

        let retrieved = tracker.get_container("test123");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "test-container");
    }

    #[test]
    fn test_get_container_by_name() {
        let tracker = create_test_tracker();
        let container = create_test_container("test456", "named-container");

        tracker.add_container(container).unwrap();

        let retrieved = tracker.get_container_by_name("named-container");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, "test456");
    }

    #[test]
    fn test_remove_container() {
        let tracker = create_test_tracker();
        let container = create_test_container("test789", "remove-me");

        tracker.add_container(container).unwrap();
        assert!(tracker.get_container("test789").is_some());

        let removed = tracker.remove_container("test789").unwrap();
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name, "remove-me");

        assert!(tracker.get_container("test789").is_none());
    }

    #[test]
    fn test_container_with_aliases() {
        let tracker = create_test_tracker();
        let mut container = create_test_container("alias-test", "aliased-container");
        container.aliases = vec!["alias1".to_string(), "alias2".to_string()];

        tracker.add_container(container).unwrap();

        let by_alias1 = tracker.get_container_by_alias("alias1");
        assert!(by_alias1.is_some());
        assert_eq!(by_alias1.unwrap().id, "alias-test");

        let by_alias2 = tracker.get_container_by_alias("alias2");
        assert!(by_alias2.is_some());
        assert_eq!(by_alias2.unwrap().id, "alias-test");
    }

    #[test]
    fn test_container_with_networks() {
        let tracker = create_test_tracker();
        let mut container = create_test_container("net-test", "networked-container");

        let mut network_details = HashMap::new();
        network_details.insert(
            "bridge".to_string(),
            Network::builder()
                .name("bridge".to_string())
                .ip_addresses(vec![IpAddr::V4(Ipv4Addr::new(172, 17, 0, 2))])
                .build(),
        );
        network_details.insert(
            "custom".to_string(),
            Network::builder()
                .name("custom".to_string())
                .ip_addresses(vec![IpAddr::V4(Ipv4Addr::new(172, 17, 0, 2))])
                .build(),
        );
        container.networks = network_details;

        tracker.add_container(container).unwrap();

        let containers_in_bridge = tracker.get_containers_in_network("bridge");
        assert_eq!(containers_in_bridge.len(), 1);
        assert_eq!(containers_in_bridge[0].id, "net-test");

        let containers_in_custom = tracker.get_containers_in_network("custom");
        assert_eq!(containers_in_custom.len(), 1);
    }

    #[test]
    fn test_update_container_networks() {
        let tracker = create_test_tracker();
        let mut container = create_test_container("update-test", "update-container");

        // Initial network
        let mut initial_networks = HashMap::new();
        initial_networks.insert(
            "network1".to_string(),
            Network::builder()
                .name("network1".to_string())
                .ip_addresses(vec![IpAddr::V4(Ipv4Addr::new(172, 17, 0, 2))])
                .build(),
        );
        container.networks = initial_networks;

        tracker.add_container(container).unwrap();
        assert_eq!(tracker.get_containers_in_network("network1").len(), 1);

        // Update networks
        let mut new_networks = HashMap::new();
        new_networks.insert(
            "network2".to_string(),
            Network::builder()
                .name("network2".to_string())
                .ip_addresses(vec![IpAddr::V4(Ipv4Addr::new(172, 17, 0, 2))])
                .build(),
        );

        tracker
            .update_container_networks("update-test", new_networks)
            .unwrap();

        // Old network should be empty
        assert_eq!(tracker.get_containers_in_network("network1").len(), 0);
        // New network should have the container
        assert_eq!(tracker.get_containers_in_network("network2").len(), 1);
    }

    #[test]
    fn test_find_container() {
        let tracker = create_test_tracker();
        let mut container = create_test_container("find-test", "findable");
        container.aliases = vec!["find-alias".to_string()];

        tracker.add_container(container).unwrap();

        // Find by ID
        let found = tracker.find_container("find-test");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "find-test");

        // Find by name
        let found = tracker.find_container("findable");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "find-test");

        // Find by alias
        let found = tracker.find_container("find-alias");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "find-test");

        // Not found
        let found = tracker.find_container("non-existent");
        assert!(found.is_none());
    }

    #[test]
    fn test_list_containers() {
        let tracker = create_test_tracker();

        for i in 0..3 {
            let container = create_test_container(&format!("id{}", i), &format!("container{}", i));
            tracker.add_container(container).unwrap();
        }

        let containers = tracker.list_containers();
        assert_eq!(containers.len(), 3);
    }

    #[test]
    fn test_clear() {
        let tracker = create_test_tracker();

        // Add some containers
        for i in 0..5 {
            let mut container =
                create_test_container(&format!("id{}", i), &format!("container{}", i));
            container.aliases = vec![format!("alias{}", i)];

            let mut networks = HashMap::new();
            networks.insert(
                "test-net".to_string(),
                Network::builder()
                    .name("test-net".to_string())
                    .ip_addresses(vec![IpAddr::V4(Ipv4Addr::new(172, 17, 0, 2))])
                    .build(),
            );
            container.networks = networks;

            tracker.add_container(container).unwrap();
        }

        assert_eq!(tracker.list_containers().len(), 5);
        assert_eq!(tracker.get_containers_in_network("test-net").len(), 5);

        tracker.clear();

        assert_eq!(tracker.list_containers().len(), 0);
        assert_eq!(tracker.get_containers_in_network("test-net").len(), 0);
        assert!(tracker.get_container_by_name("container0").is_none());
        assert!(tracker.get_container_by_alias("alias0").is_none());
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let tracker = Arc::new(create_test_tracker());
        let mut handles = vec![];

        // Spawn multiple threads that add containers
        for i in 0..10 {
            let tracker_clone = Arc::clone(&tracker);
            let handle = thread::spawn(move || {
                let container = create_test_container(
                    &format!("thread-{}", i),
                    &format!("container-thread-{}", i),
                );
                tracker_clone.add_container(container).unwrap();
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify all containers were added
        assert_eq!(tracker.list_containers().len(), 10);
    }

    #[test]
    fn test_remove_nonexistent_container() {
        let tracker = create_test_tracker();
        let result = tracker.remove_container("non-existent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_update_nonexistent_container() {
        let tracker = create_test_tracker();
        let networks = HashMap::new();
        let result = tracker.update_container_networks("non-existent", networks);
        assert!(result.is_err());
    }
}
