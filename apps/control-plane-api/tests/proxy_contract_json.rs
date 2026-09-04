use apex_control_plane_api::proto::{McpProxyRevision, ProxyStageTiming, RuntimeConfiguration};
use serde_json::{Value, json};

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contracts/fixtures/mcp-proxy"
);

#[test]
fn timing_json_preserves_microseconds_and_large_integers() {
    let value: ProxyStageTiming = serde_json::from_value(json!({
        "name": "policy", "startedAtUnixUs": "9007199254740993",
        "durationUs": "7", "durationNs": "7000"
    }))
    .expect("generated timing JSON");
    assert_eq!(value.started_at_unix_us, 9_007_199_254_740_993);
    assert_eq!(serde_json::to_value(value).unwrap()["durationUs"], "7");
}

#[test]
fn generated_json_rejects_unknown_fields() {
    assert!(serde_json::from_value::<ProxyStageTiming>(json!({"surprise": true})).is_err());
}

#[test]
fn shared_fixtures_round_trip_without_endpoint_or_precision_loss() {
    fn fixture(name: &str) -> Value {
        serde_json::from_str(&std::fs::read_to_string(format!("{FIXTURES}/{name}.json")).unwrap())
            .unwrap()
    }
    let control: McpProxyRevision = serde_json::from_value(fixture("control-revision")).unwrap();
    let spec = apex_control_plane_api::ProxySpec::try_from(control.spec.clone().unwrap()).unwrap();
    apex_control_plane_api::validate_proxy_spec(&spec).unwrap();
    let runtime: RuntimeConfiguration =
        serde_json::from_value(fixture("runtime-revision")).unwrap();
    assert_ne!(
        runtime.resource_url,
        runtime.spec.as_ref().unwrap().upstreams[0].endpoint_or_command_ref
    );
    assert_eq!(
        runtime.spec.as_ref().unwrap().ingress,
        control.spec.unwrap().ingress
    );
    assert_eq!(
        serde_json::to_value(runtime).unwrap(),
        fixture("runtime-revision")
    );
}
