use apex_proxy_runtime_agent::{RuntimeOwnershipInput, proto};
use serde_json::{Value, json};

pub const PROXY: &str = "0191b7f1-7f2c-7c13-9a61-2f29f2be1001";
pub const REVISION: &str = "0191b7f1-7f2c-7c13-9a61-2f29f2be1002";
pub const INSTALLATION: &str = "0191b7f1-7f2c-7c13-9a61-2f29f2be1003";
pub const INSTANCE: &str = "0191b7f1-7f2c-7c13-9a61-2f29f2be1004";
pub const OTHER: &str = "0191b7f1-7f2c-7c13-9a61-2f29f2be1005";
pub const BIG: u64 = 9_007_199_254_740_993;
pub const CANARY: &str = "PRIVATE_BOUNDARY_CANARY_7A";

pub fn target() -> proto::RuntimeTarget {
    proto::RuntimeTarget {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        proxy_id: PROXY.into(),
        revision_id: REVISION.into(),
        generation: BIG,
        fencing_token: u64::MAX,
    }
}

/// Complete synthetic canonical wire fixture: NOT a published/verified config.
pub fn configuration() -> proto::RuntimeConfiguration {
    let mut config: proto::RuntimeConfiguration = serde_json::from_str(include_str!(
        "../../../../contracts/fixtures/mcp-proxy/runtime-revision.json"
    ))
    .expect("canonical generated fixture");
    config.generation = BIG;
    config
}

pub fn ownership() -> RuntimeOwnershipInput {
    RuntimeOwnershipInput {
        installation_id: INSTALLATION.into(),
        container_id: "a".repeat(64),
        image_id: format!("sha256:{}", "b".repeat(64)),
        name: format!("apex-runtime-{INSTANCE}"),
        target: target(),
        config_hash: "c".repeat(64),
        runtime_manifest_hash: "d".repeat(64),
        launch_context_hash: "e".repeat(64),
        process_instance_id: INSTANCE.into(),
    }
}

/// Literal label namespace, independently supplied by the boundary contract.
pub fn labels(value: &RuntimeOwnershipInput) -> Value {
    json!({
        "io.apex.runtime.installation-id": value.installation_id,
        "io.apex.runtime.workspace-id": value.target.workspace_id,
        "io.apex.runtime.namespace-id": value.target.namespace_id,
        "io.apex.runtime.proxy-id": value.target.proxy_id,
        "io.apex.runtime.revision-id": value.target.revision_id,
        "io.apex.runtime.generation": value.target.generation.to_string(),
        "io.apex.runtime.fencing-token": value.target.fencing_token.to_string(),
        "io.apex.runtime.config-hash": value.config_hash,
        "io.apex.runtime.runtime-manifest-hash": value.runtime_manifest_hash,
        "io.apex.runtime.launch-context-hash": value.launch_context_hash,
        "io.apex.runtime.process-instance-id": value.process_instance_id,
    })
}

pub fn inspect(value: &RuntimeOwnershipInput, status: &str) -> Value {
    json!([{
        "Id": value.container_id, "Name": format!("/{}", value.name), "Image": value.image_id,
        "Config": {"Labels": labels(value), "Env": [format!("TOKEN={CANARY}")]},
        "State": {"Status": status, "Error": CANARY},
        "Mounts": [{"Source": format!("/private/{CANARY}"), "Destination": "/run/secrets"}],
        "HostConfig": {"Binds": [CANARY]}, "NetworkSettings": {"Ignored": CANARY},
    }])
}

pub fn document() -> String {
    inspect(&ownership(), "running").to_string()
}

pub fn duplicate_before(input: &str, key: &str, value: &str) -> String {
    let needle = format!("\"{key}\":");
    assert!(input.contains(&needle));
    input.replacen(&needle, &format!("{needle}{value},{needle}"), 1)
}
