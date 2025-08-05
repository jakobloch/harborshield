use bon::builder;
use std::future::Future;

/// Initialize tracing for integration tests with maximum verbosity
pub fn init_test_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("harborshield=trace,integration_tests=trace")
        .with_test_writer()
        .try_init();
}

/// Initialize tracing with custom filter
pub fn init_test_tracing_with_filter(filter: &str) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_test_writer()
        .try_init();
}

#[builder]
pub async fn retry_with_delay<F, Fut, T, E>(
    mut operation: F,
    #[builder(default)] description: &str,
    #[builder(default = 5)] max_attempts: u32,
    #[builder(default = 5)] delay_seconds: u64,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Debug,
{
    for attempt in 1..=max_attempts {
        println!("{} - attempt {}/{}", description, attempt, max_attempts);

        match operation().await {
            Ok(result) => {
                println!("✓ {} succeeded on attempt {}", description, attempt);
                return Ok(result);
            }
            Err(e) => {
                if attempt < max_attempts {
                    println!(
                        "✗ {} failed on attempt {}: {:?}, retrying in {} seconds...",
                        description, attempt, e, delay_seconds
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(delay_seconds)).await;
                } else {
                    println!("✗ {} failed after {} attempts", description, max_attempts);
                    return Err(e);
                }
            }
        }
    }
    unreachable!()
}
