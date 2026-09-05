use super::{
    super::policy::PolicyState,
    support::{INSTALLATION, PROXY, REVISION, bytes, enrollment, peer_policy},
};
use serde_json::{Value, json};
use std::time::Instant;

fn document() -> Value {
    let runtime: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/fixtures/mcp-proxy/runtime-revision.json"
    )))
    .unwrap();
    json!({"schemaVersion":1,"version":"bindings-1","validFromUnixUs":"100","expiresAtUnixUs":"1000",
        "profiles":[{"installationId":INSTALLATION,"workspaceId":"work","namespaceId":"ns",
            "proxyId":PROXY,"revisionId":REVISION,"hostPolicyVersion":"host-policy-1",
            "resourceUrl":runtime["resourceUrl"],"images":[{"digest":runtime["spec"]["runtimeProfile"]["imageDigest"],
                "imageRef":runtime["imageRef"]}],"secretRefs":runtime["secretRefs"],
            "toolSchemas":runtime["toolSchemas"],"approvedOutputProfiles":["portfolio-read-v1"],
            "networkGrants":runtime["networkGrants"],"auth":runtime["auth"],"telemetry":runtime["telemetry"],
            "pidLimit":runtime["pidLimit"]}]})
}

#[test]
fn deployment_rotation_invalidates_inflight_and_identical_refresh_does_not() {
    let mut state = PolicyState::new();
    let at = Instant::now();
    let (peer, enrollment) = (bytes(&peer_policy()), bytes(&enrollment()));
    let mut catalog = document();
    state
        .publish_with_deployment(&peer, &enrollment, Some(&bytes(&catalog)), at, at)
        .unwrap();
    let first = state.current(at).unwrap();
    state
        .publish_with_deployment(&peer, &enrollment, Some(&bytes(&catalog)), at, at)
        .unwrap();
    assert!(state.recheck(&first, at).is_ok());
    catalog["version"] = "bindings-2".into();
    state
        .publish_with_deployment(&peer, &enrollment, Some(&bytes(&catalog)), at, at)
        .unwrap();
    assert!(state.recheck(&first, at).is_err());
    assert_eq!(
        state
            .current(at)
            .unwrap()
            .deployment
            .as_ref()
            .unwrap()
            .version(),
        "bindings-2"
    );
}

#[test]
fn changed_bytes_with_same_binding_version_disable_current_and_survive_disable() {
    for disable in [false, true] {
        let mut state = PolicyState::new();
        let at = Instant::now();
        let (peer, enrollment) = (bytes(&peer_policy()), bytes(&enrollment()));
        let mut catalog = document();
        state
            .publish_with_deployment(&peer, &enrollment, Some(&bytes(&catalog)), at, at)
            .unwrap();
        let first = state.current(at).unwrap();
        if disable {
            state.disable();
        }
        catalog["profiles"][0]["pidLimit"] = 256.into();
        assert!(
            state
                .publish_with_deployment(&peer, &enrollment, Some(&bytes(&catalog)), at, at)
                .is_err()
        );
        assert!(state.current(at).is_err());
        assert!(state.recheck(&first, at).is_err());
    }
}

#[test]
fn malformed_configured_deployment_disables_the_entire_authority_pair() {
    let mut state = PolicyState::new();
    let at = Instant::now();
    let (peer, enrollment) = (bytes(&peer_policy()), bytes(&enrollment()));
    state
        .publish_with_deployment(&peer, &enrollment, Some(&bytes(&document())), at, at)
        .unwrap();
    assert!(
        state
            .publish_with_deployment(&peer, &enrollment, Some(b"{"), at, at)
            .is_err()
    );
    assert!(state.current(at).is_err());
}

#[test]
fn invalid_resource_limits_reject_initial_catalog_and_disable_refresh() {
    for field in ["telemetry", "pidLimit"] {
        let mut catalog = document();
        catalog["profiles"][0][field] = if field == "telemetry" {
            json!({})
        } else {
            json!(0)
        };
        let at = Instant::now();
        let (peer, enrollment) = (bytes(&peer_policy()), bytes(&enrollment()));
        let mut initial = PolicyState::new();
        assert!(
            initial
                .publish_with_deployment(&peer, &enrollment, Some(&bytes(&catalog)), at, at)
                .is_err()
        );
        assert!(initial.current(at).is_err());
        let mut current = PolicyState::new();
        current
            .publish_with_deployment(&peer, &enrollment, Some(&bytes(&document())), at, at)
            .unwrap();
        let selected = current.current(at).unwrap();
        catalog["version"] = "bindings-2".into();
        assert!(
            current
                .publish_with_deployment(&peer, &enrollment, Some(&bytes(&catalog)), at, at)
                .is_err()
        );
        assert!(current.current(at).is_err());
        assert!(current.recheck(&selected, at).is_err());
    }
}
