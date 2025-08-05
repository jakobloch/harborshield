use crate::{Error, Result};
use bollard::models::Network;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use tracing::{debug, warn};

/// Information about a Docker network including gateway IPs
#[derive(Debug, Clone)]
pub struct NetworkGatewayInfo {
    pub network_id: String,
    pub network_name: String,
    pub gateway_ips: Vec<IpAddr>,
    pub subnet: Option<String>,
}

/// Extract gateway information from Docker network inspect response
pub fn extract_network_gateway(network: &Network) -> Result<NetworkGatewayInfo> {
    let network_id = network
        .id
        .as_ref()
        .ok_or_else(|| Error::invalid_state("Network missing ID", "has ID", "missing"))?
        .clone();

    let network_name = network
        .name
        .as_ref()
        .ok_or_else(|| Error::invalid_state("Network missing name", "has name", "missing"))?
        .clone();

    let mut gateway_ips = Vec::new();
    let mut subnet = None;

    // Extract gateway IPs from IPAM configuration
    if let Some(ipam) = &network.ipam {
        if let Some(configs) = &ipam.config {
            for config in configs {
                // Extract gateway IP
                if let Some(gateway_str) = &config.gateway {
                    match IpAddr::from_str(gateway_str) {
                        Ok(ip) => {
                            debug!("Found gateway IP {} for network {}", ip, network_name);
                            gateway_ips.push(ip);
                        }
                        Err(e) => {
                            warn!(
                                "Failed to parse gateway IP '{}' for network {}: {}",
                                gateway_str, network_name, e
                            );
                        }
                    }
                }

                // Extract subnet for reference
                if subnet.is_none() {
                    subnet = config.subnet.clone();
                }
            }
        }
    }

    // Docker default bridge network special handling
    if network_name == "bridge" && gateway_ips.is_empty() {
        // Default Docker bridge typically uses 172.17.0.1
        debug!("Using default gateway IP for Docker bridge network");
        gateway_ips.push(IpAddr::from_str("172.17.0.1").unwrap());
    }

    Ok(NetworkGatewayInfo {
        network_id,
        network_name,
        gateway_ips,
        subnet,
    })
}

/// Get gateway IPs for all networks a container is connected to
pub fn get_container_network_gateways(
    container_networks: &HashMap<String, bollard::models::EndpointSettings>,
    network_info_cache: &HashMap<String, NetworkGatewayInfo>,
) -> Vec<IpAddr> {
    let mut gateway_ips = Vec::new();

    for (network_name, _endpoint) in container_networks {
        if let Some(gateway_info) = network_info_cache.get(network_name) {
            gateway_ips.extend(&gateway_info.gateway_ips);
        }
    }

    gateway_ips
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::{Ipam, IpamConfig};

    #[test]
    fn test_extract_network_gateway() {
        let mut network = Network::default();
        network.id = Some("test-id".to_string());
        network.name = Some("test-network".to_string());

        let mut ipam = Ipam::default();
        let mut config = IpamConfig::default();
        config.gateway = Some("192.168.1.1".to_string());
        config.subnet = Some("192.168.1.0/24".to_string());
        ipam.config = Some(vec![config]);
        network.ipam = Some(ipam);

        let result = extract_network_gateway(&network).unwrap();
        assert_eq!(result.network_name, "test-network");
        assert_eq!(result.gateway_ips.len(), 1);
        assert_eq!(
            result.gateway_ips[0],
            IpAddr::from_str("192.168.1.1").unwrap()
        );
        assert_eq!(result.subnet, Some("192.168.1.0/24".to_string()));
    }

    #[test]
    fn test_default_bridge_gateway() {
        let mut network = Network::default();
        network.id = Some("bridge-id".to_string());
        network.name = Some("bridge".to_string());

        let result = extract_network_gateway(&network).unwrap();
        assert_eq!(result.network_name, "bridge");
        assert_eq!(result.gateway_ips.len(), 1);
        assert_eq!(
            result.gateway_ips[0],
            IpAddr::from_str("172.17.0.1").unwrap()
        );
    }
}
