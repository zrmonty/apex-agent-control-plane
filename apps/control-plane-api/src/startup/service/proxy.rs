use std::io;
use std::sync::Arc;

use apex_control_plane_api::{DockerCommandRunner, DockerProxyProvider, ProxyRuntimeProvider};
use tonic_health::ServingStatus;

const RUNTIME_NETWORK_ENV: &str = "APEX_CONTROL_MCP_PROXY_RUNTIME_NETWORK";

pub(super) fn build_runtime_provider()
-> Result<Option<Arc<dyn ProxyRuntimeProvider>>, Box<dyn std::error::Error>> {
    let network = parse_runtime_network(std::env::var(RUNTIME_NETWORK_ENV).ok().as_deref())?;
    let Some(network) = network else {
        println!(
            "apex-control-plane-api mcp proxy runtime: unavailable ({RUNTIME_NETWORK_ENV} is not configured)"
        );
        return Ok(None);
    };
    let provider = DockerProxyProvider::with_network(Arc::new(DockerCommandRunner), network)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    println!("apex-control-plane-api mcp proxy runtime: docker");
    Ok(Some(Arc::new(provider)))
}

fn parse_runtime_network(value: Option<&str>) -> Result<Option<String>, io::Error> {
    match value {
        None => Ok(None),
        Some("") => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{RUNTIME_NETWORK_ENV} must not be empty when set"),
        )),
        Some(value) => Ok(Some(value.to_owned())),
    }
}

pub(super) fn proxy_service_status(
    event_sink_configured: bool,
    runtime_provider_configured: bool,
) -> ServingStatus {
    if event_sink_configured && runtime_provider_configured {
        ServingStatus::Serving
    } else {
        ServingStatus::NotServing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_health_requires_both_production_boundaries() {
        assert_eq!(proxy_service_status(true, true), ServingStatus::Serving);
        assert_eq!(proxy_service_status(true, false), ServingStatus::NotServing);
        assert_eq!(proxy_service_status(false, true), ServingStatus::NotServing);
    }

    #[test]
    fn runtime_network_is_optional_but_never_accepts_an_empty_value() {
        assert_eq!(parse_runtime_network(None).unwrap(), None);
        assert_eq!(
            parse_runtime_network(Some("apex-mcp-proxy-egress"))
                .unwrap()
                .as_deref(),
            Some("apex-mcp-proxy-egress")
        );
        assert!(parse_runtime_network(Some("")).is_err());
    }
}
