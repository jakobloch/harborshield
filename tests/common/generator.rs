/// Macro to generate standardized integration tests from compose YAML fixtures
///
/// This macro uses the ComposeParser to analyze the YAML and generate test assertions
#[macro_export]
macro_rules! generate_compose_test {
    ($test_name:ident, $compose_yaml:expr) => {
        #[tokio::test]
        #[ignore = concat!("Integration test - run with: cargo test ", stringify!($test_name), " -- --ignored")]
        async fn $test_name() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            use std::{fs, sync::Arc};
            use tempfile::NamedTempFile;
            use tokio::sync::Mutex;
            use temp_env::async_with_vars;
            use $crate::common::{
                parser::ComposeParser,
                Runner, TestEnvironment,
            };

            // Set environment variables for testing using temp_env
            let env_vars = vec![
                ("RUST_LOG", Some("harborshield=trace")),
                ("RUST_BACKTRACE", Some("1")),
            ];

            async_with_vars(env_vars, async {
                let _ = tracing_subscriber::fmt()
                    .with_env_filter("harborshield=trace,compose_integration_tests=trace")
                    .with_test_writer()
                    .try_init();

                // Parse the compose YAML to generate test assertions
                eprintln!("\n🚀 Starting test: {}", stringify!($test_name));
                eprintln!("{}", "=".repeat(60));
                let assertions = ComposeParser::parse_compose_yaml($compose_yaml)?;

                // Extract verdict chains that need to be created for this test
                let verdict_chains = ComposeParser::extract_verdict_chains($compose_yaml)?;
                if !verdict_chains.is_empty() {
                    eprintln!("📋 Test requires verdict chains: {:?}", verdict_chains);
                }
                eprintln!("{}", "=".repeat(60));

                // Create a temporary compose file
                let compose_file = NamedTempFile::new()?;
                fs::write(compose_file.path(), $compose_yaml)?;

                let runner = Runner::builder()
                    .environment(Arc::new(Mutex::new(
                        TestEnvironment::builder()
                            .compose_file(compose_file.path().to_path_buf())
                            .start_harborshield(true)
                            .restart_harborshield(false)
                            .test_name(stringify!($test_name).to_string())
                            .verdict_chains(verdict_chains)
                            .build()?,
                    )))
                    .build();

                // Run each assertion as a separate test
                for assertion in assertions {
                    runner
                        .run_test(&assertion.name, |env| async move {
                            (assertion.assertion)(env).await
                        })
                        .await?;
                }

                Ok(())
            }).await
        }
    };
}
