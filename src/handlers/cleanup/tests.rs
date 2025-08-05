use super::*;
use tempfile::NamedTempFile;

async fn setup_test_db() -> crate::Result<(NamedTempFile, Arc<Mutex<DB>>)> {
    let temp_file = NamedTempFile::new().unwrap();
    let db = DB::builder().db_path(temp_file.path()).build().await?;
    Ok((temp_file, Arc::new(Mutex::new(db))))
}

#[tokio::test]
async fn test_cleanup_tracker() {
    let (_temp, db) = setup_test_db().await.unwrap();

    // Initialize nftables for testing
    let mut nft_client = crate::nftables::NftablesClient::builder().build();
    if let Err(_) = nft_client.init_base_chains().await {
        eprintln!("Skipping test - nftables not available or insufficient permissions");
        return;
    }

    let tracker = Arc::new(CleanupTracker::builder().db(db).build());

    // Register some resources using the harborshield table that was just created
    tracker
        .register_rule(
            "harborshield".to_string(),
            "harborshield-input".to_string(),
            42,
        )
        .await
        .unwrap();
    tracker
        .register_chain("harborshield".to_string(), "custom_chain".to_string())
        .await
        .unwrap();

    // Unregister a resource
    tracker
        .unregister_rule(
            "harborshield".to_string(),
            "harborshield-input".to_string(),
            42,
        )
        .await
        .unwrap();

    // Cleanup
    tracker.cleanup_all().await.unwrap();

    // Shutdown (need to unwrap from Arc)
    let tracker = Arc::try_unwrap(tracker).ok().unwrap();
    tracker.shutdown().await.unwrap();

    // Clean up the table
    let mut nft_client = crate::nftables::NftablesClient::builder().build();
    let _ = nft_client.clear_table().await;
}

#[tokio::test]
async fn test_cleanup_guard() {
    let (_temp, db) = setup_test_db().await.unwrap();

    // Initialize nftables for testing
    let mut nft_client = crate::nftables::NftablesClient::builder().build();
    if let Err(_) = nft_client.init_base_chains().await {
        eprintln!("Skipping test - nftables not available or insufficient permissions");
        return;
    }

    let tracker = Arc::new(CleanupTracker::builder().db(db).build());

    // Test uncommitted guard (should trigger cleanup)
    {
        let _guard = CleanupGuard::builder().tracker(tracker.clone()).build();
        tracker
            .register_rule(
                "harborshield".to_string(),
                "harborshield-input".to_string(),
                99,
            )
            .await
            .unwrap();
        // Guard drops here without commit
    }

    // Give async cleanup time to run
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Test committed guard (no cleanup)
    {
        let guard = CleanupGuard::builder().tracker(tracker.clone()).build();
        tracker
            .register_rule(
                "harborshield".to_string(),
                "harborshield-output".to_string(),
                100,
            )
            .await
            .unwrap();
        guard.commit();
    }

    let tracker = Arc::try_unwrap(tracker).ok().unwrap();
    tracker.shutdown().await.unwrap();

    // Clean up the table
    let mut nft_client = crate::nftables::NftablesClient::builder().build();
    let _ = nft_client.clear_table().await;
}

#[tokio::test]
async fn test_database_cleanup() {
    let _ = tracing_subscriber::fmt::try_init();

    let (_temp, db) = setup_test_db().await.unwrap();

    // Insert test data
    {
        let db_guard = db.lock().await;
        use crate::database::{DbOp, DbOpResult};

        // Insert a container
        db_guard
            .execute(&DbOp::InsertContainer(
                &crate::database::models::ContainerIdentifiers {
                    id: "test123".to_string(),
                    name: "test-container".to_string(),
                },
            ))
            .await
            .unwrap();

        // Insert related data
        let addr = crate::database::models::Addr::from_ip(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 10)),
            "test123".to_string(),
        );
        db_guard.execute(&DbOp::InsertAddr(&addr)).await.unwrap();

        // Verify data was inserted
        let result = db_guard
            .execute(&DbOp::GetContainer("test123"))
            .await
            .unwrap();
        if let DbOpResult::ContainerIdentifiers(container) = result {
            assert!(container.is_some(), "Container should exist after insert");
        } else {
            panic!("Expected Container result");
        }
    }

    let tracker = Arc::new(CleanupTracker::builder().db(db.clone()).build());

    // Register the container for cleanup
    tracker
        .register_db_container("test123".to_string())
        .await
        .unwrap();

    // Perform cleanup
    tracker.cleanup_all().await.unwrap();

    // Give async cleanup time to complete
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Verify container was deleted
    {
        let db_guard = db.lock().await;
        use crate::database::{DbOp, DbOpResult};
        let result = db_guard
            .execute(&DbOp::GetContainer("test123"))
            .await
            .unwrap();
        if let DbOpResult::ContainerIdentifiers(container) = result {
            assert!(container.is_none(), "Container should have been cleaned up");
        } else {
            panic!("Expected Container result");
        }
    }

    let tracker = Arc::try_unwrap(tracker).ok().unwrap();
    tracker.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_nftables_cleanup_mock() {
    let (_temp, db) = setup_test_db().await.unwrap();

    // Initialize nftables for testing
    let mut nft_client = crate::nftables::NftablesClient::builder().build();
    if let Err(_) = nft_client.init_base_chains().await {
        eprintln!("Skipping test - nftables not available or insufficient permissions");
        return;
    }

    let tracker = Arc::new(CleanupTracker::builder().db(db).build());

    // Register nftables resources
    tracker
        .register_rule(
            "harborshield".to_string(),
            "harborshield-input".to_string(),
            123,
        )
        .await
        .unwrap();
    tracker
        .register_chain("harborshield".to_string(), "custom-chain".to_string())
        .await
        .unwrap();
    tracker
        .register_set("harborshield".to_string(), "blocked-ips".to_string())
        .await
        .unwrap();

    // Perform cleanup
    tracker.cleanup_all().await.unwrap();

    let tracker = Arc::try_unwrap(tracker).ok().unwrap();
    tracker.shutdown().await.unwrap();

    // Clean up the table
    let mut nft_client = crate::nftables::NftablesClient::builder().build();
    let _ = nft_client.clear_table().await;
}
