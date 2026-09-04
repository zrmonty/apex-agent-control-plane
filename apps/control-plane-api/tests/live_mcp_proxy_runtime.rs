//! Opt-in runtime proof for a provisioned managed MCP proxy container.
//!
//! The test is deliberately skipped unless a disposable Compose profile is
//! running. When enabled, missing containers or missing isolation controls are
//! failures rather than a misleading green contract test.

use std::process::Command;

fn enabled() -> bool {
    std::env::var("APEX_CONTROL_LIVE_MCP_PROXY_RUNTIME").ok().as_deref() == Some("1")
}

fn container() -> String {
    std::env::var("APEX_CONTROL_LIVE_MCP_PROXY_CONTAINER")
        .unwrap_or_else(|_| "apex-gateway-ref-mcp-proxy-portfolio-1".to_owned())
}

#[test]
fn provisioned_proxy_container_has_the_hardened_runtime_profile() {
    if !enabled() {
        eprintln!("skip live MCP proxy runtime proof: set APEX_CONTROL_LIVE_MCP_PROXY_RUNTIME=1");
        return;
    }

    let output = Command::new("docker")
        .args(["inspect", "--format", "{{json .}}", &container()])
        .output()
        .expect("docker must be available for the enabled runtime proof");
    assert!(output.status.success(), "the enabled MCP proxy container must exist");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("docker inspect must return JSON");
    let item = document.as_object().expect("docker inspect object");
    let config = item["Config"].as_object().expect("container config");
    let host = item["HostConfig"].as_object().expect("host config");
    assert_eq!(config["User"], "10001:10001");
    assert_eq!(host["ReadonlyRootfs"], true);
    assert_eq!(host["Privileged"], false);
    assert!(host["NetworkMode"].as_str().is_some_and(|value| value == "mcp-proxy-egress" || value.ends_with("_mcp-proxy-egress")));
    assert!(host["SecurityOpt"].as_array().is_some_and(|values| values.iter().any(|value| value == "no-new-privileges:true")));
    assert!(host["CapDrop"].as_array().is_some_and(|values| values.iter().any(|value| value == "ALL")));
    assert!(host["Mounts"].as_array().is_some_and(|mounts| mounts.iter().all(|mount| mount["Destination"] != "/var/run/docker.sock")));
}
