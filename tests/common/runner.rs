use crate::common::TestEnvironment;
use crate::common::assertions::ConnectivityAssertions;
use crate::common::assertions::{ContainerAssertions, NftablesAssertions};
use crate::common::fixtures::ComposeConfigs;
use crate::common::helpers;
use bon::Builder;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::sync::Mutex;

/// Test runner that manages the test environment lifecycle
/// separately from individual test execution
#[derive(Builder)]
pub struct Runner {
    /// The test environment that persists across tests
    environment: Arc<Mutex<TestEnvironment>>,

    /// Whether to use harborshield as a container
    #[builder(default = false)]
    should_use_whalewall_container: bool,

    /// Whether to restart harborshield between tests
    #[builder(default = false)]
    restart_whalewall_between_tests: bool,

    /// Test timeout in seconds
    #[builder(default = 600)]
    test_timeout_seconds: u64,
}
impl Runner {
    fn get_should_use_whalewall_container(&self) -> bool {
        self.should_use_whalewall_container
    }
    fn get_test_timeout_seconds(&self) -> u64 {
        self.test_timeout_seconds
    }
    fn get_environment(&self) -> Arc<tokio::sync::Mutex<TestEnvironment>> {
        self.environment.clone()
    }

    /// Initialize the test runner and start the environment
    async fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        eprintln!("🚀 Initializing test runner...");

        // Start harborshield if needed
        if self.get_should_use_whalewall_container() {
            self.start_whalewall_container().await?;
        }

        Ok(())
    }

    /// Start harborshield as a container
    async fn start_whalewall_container(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        eprintln!("🐳 Starting harborshield as a container...");

        // Build harborshield container
        let output = std::process::Command::new("docker")
            .args(&[
                "build",
                "-f",
                "Dockerfile.harborshield",
                "-t",
                "harborshield:test",
                ".",
            ])
            .output()?;

        if !output.status.success() {
            return Err(format!(
                "Failed to build harborshield container: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }

        // Run harborshield container
        let output = std::process::Command::new("docker")
            .args(&[
                "run",
                "-d",
                "--name",
                "harborshield-test-runner",
                "--network",
                "host",
                "--privileged",
                "--cap-add",
                "NET_ADMIN",
                "--cap-add",
                "SYS_MODULE",
                "-v",
                "/var/run/docker.sock:/var/run/docker.sock:ro",
                "-e",
                "RUST_LOG=harborshield=trace",
                "-e",
                "RUST_BACKTRACE=1",
                "harborshield:test",
            ])
            .output()?;

        if !output.status.success() {
            return Err(format!(
                "Failed to start harborshield container: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }

        // Wait for harborshield to be ready
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        eprintln!("✅ Harborshield container started");
        Ok(())
    }

    /// Stop harborshield container
    async fn stop_whalewall_container(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _ = std::process::Command::new("docker")
            .args(&["stop", "harborshield-test-runner"])
            .output();

        let _ = std::process::Command::new("docker")
            .args(&["rm", "harborshield-test-runner"])
            .output();

        Ok(())
    }

    /// Run a test with the managed environment
    pub async fn run_test<F, Fut>(
        &self,
        test_name: &str,
        test_fn: F,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        F: FnOnce(Arc<Mutex<TestEnvironment>>) -> Fut + Send,
        Fut: std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
            + Send,
    {
        eprintln!("\n🧪 Running test: {}", test_name);

        // Set up test-specific timeout
        let timeout = tokio::time::Duration::from_secs(self.get_test_timeout_seconds());

        // Run the test with timeout
        match tokio::time::timeout(timeout, test_fn(self.get_environment())).await {
            Ok(Ok(())) => {
                eprintln!("✅ Test {} passed", test_name);
                Ok(())
            }
            Ok(Err(e)) => {
                eprintln!("❌ Test {} failed: {}", test_name, e);
                Err(e)
            }
            Err(_) => {
                let err = format!(
                    "Test {} timed out after {} seconds",
                    test_name,
                    self.get_test_timeout_seconds()
                );
                eprintln!("❌ {}", err);
                Err(err.into())
            }
        }
    }

    /// Clean up after all tests
    async fn cleanup(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        eprintln!("\n🧹 Cleaning up test runner...");

        if self.get_should_use_whalewall_container() {
            self.stop_whalewall_container().await?;
        }

        // The TestEnvironment will clean up when dropped

        Ok(())
    }
}
