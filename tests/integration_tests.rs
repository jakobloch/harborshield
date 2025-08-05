#[macro_use]
mod common;

use common::fixtures::ComposeConfigs;

// Test complex multi-network architecture with cross-network dependencies
generate_compose_test!(
    multi_network_dependencies_test_suite,
    ComposeConfigs::multi_network_dependencies()
);
generate_compose_test!(client_test_suite, ComposeConfigs::client());
generate_compose_test!(web_app_test_suite, ComposeConfigs::basic_web_app());
generate_compose_test!(miniflux_test_suite, ComposeConfigs::miniflux());
generate_compose_test!(microservices_test_suite, ComposeConfigs::microservices());
generate_compose_test!(
    mapped_ports_localhost_test_suite,
    ComposeConfigs::mapped_ports_localhost_full()
);
generate_compose_test!(
    mapped_ports_external_test_suite,
    ComposeConfigs::mapped_ports_external_ips()
);
generate_compose_test!(logging_rules_test_suite, ComposeConfigs::logging_rules());
generate_compose_test!(
    complex_dependencies_test_suite,
    ComposeConfigs::complex_dependencies()
);
generate_compose_test!(port_ranges_test_suite, ComposeConfigs::port_ranges());

generate_compose_test!(ip_filtering_test_suite, ComposeConfigs::ip_filtering());
generate_compose_test!(
    verdict_chain_jumps_test_suite,
    ComposeConfigs::verdict_chain_jumps()
);
generate_compose_test!(udp_services_test_suite, ComposeConfigs::udp_services());
generate_compose_test!(
    output_rules_comprehensive_test_suite,
    ComposeConfigs::output_rules_comprehensive()
);
generate_compose_test!(verdict_queues_test_suite, ComposeConfigs::verdict_queues());
