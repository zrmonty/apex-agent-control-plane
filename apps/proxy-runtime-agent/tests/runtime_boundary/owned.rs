use super::support::*;
use apex_proxy_runtime_agent::{
    EngineState, ExpectedRuntimeOwnership, RuntimeError, check_owned_inspect,
};
use serde_json::json;

#[test]
fn complete_expected_identity_matches_without_retaining_irrelevant_secret_fields() {
    let raw = ownership();
    let expected = ExpectedRuntimeOwnership::from_unverified(raw.clone());
    let result = check_owned_inspect(&document(), &expected).expect("identity equality only");
    assert_eq!(result.identity(), &raw);
    assert_eq!(result.state(), EngineState::Running);
    assert!(!format!("{result:?}").contains(CANARY));
    assert!(!format!("{:?}", result.identity()).contains(CANARY));
    // The output has no readiness/admission/provisioning or authority flag.
}

#[test]
fn narrow_projection_object_and_single_optional_name_slash_are_supported() {
    let raw = ownership();
    let expected = ExpectedRuntimeOwnership::from_unverified(raw.clone());
    for name in [raw.name.clone(), format!("/{}", raw.name)] {
        let input = json!({"Id": raw.container_id, "Name": name, "Image": raw.image_id,
            "Config": {"Labels": labels(&raw)}, "State": {"Status": "created"}});
        let result = check_owned_inspect(&input.to_string(), &expected).expect("projection");
        assert_eq!(result.identity().name, raw.name);
        assert_eq!(result.state(), EngineState::Created);
    }
}

#[test]
fn all_supported_engine_states_are_closed_lifecycle_values_not_readiness() {
    let expected = ExpectedRuntimeOwnership::from_unverified(ownership());
    for (status, state) in [
        ("created", EngineState::Created),
        ("running", EngineState::Running),
        ("restarting", EngineState::Restarting),
        ("paused", EngineState::Paused),
        ("exited", EngineState::Exited),
        ("dead", EngineState::Dead),
        ("removing", EngineState::Removing),
    ] {
        let result =
            check_owned_inspect(&inspect(&ownership(), status).to_string(), &expected).unwrap();
        assert_eq!(result.state(), state);
    }
    for invalid in [
        "",
        "ready",
        "healthy",
        "RUNNING",
        " running",
        "running\n",
        CANARY,
    ] {
        let error = check_owned_inspect(&inspect(&ownership(), invalid).to_string(), &expected)
            .unwrap_err();
        assert_eq!(error, RuntimeError::UnsupportedState);
    }
}

#[test]
fn immutable_expected_snapshot_does_not_follow_later_mutations_of_raw_source() {
    let mut raw = ownership();
    let expected = ExpectedRuntimeOwnership::from_unverified(raw.clone());
    raw.target.fencing_token = 1;
    raw.container_id = "f".repeat(64);
    assert!(check_owned_inspect(&document(), &expected).is_ok());
    assert!(check_owned_inspect(&inspect(&raw, "running").to_string(), &expected).is_err());
}

#[test]
fn unknown_labels_are_bounded_and_ignored_without_reflection() {
    let expected = ExpectedRuntimeOwnership::from_unverified(ownership());
    let mut input = inspect(&ownership(), "created");
    let extra = input[0]["Config"]["Labels"].as_object_mut().unwrap();
    extra.insert("x".repeat(128), json!(CANARY));
    extra.insert("example.long-value".into(), json!("x".repeat(512)));
    for index in 0..51 {
        extra.insert(format!("example.extra-{index}"), json!("value"));
    }
    assert_eq!(extra.len(), 64);
    let result = check_owned_inspect(&input.to_string(), &expected).unwrap();
    assert_eq!(result.identity(), &ownership());
    assert!(!format!("{result:?}").contains(CANARY));
    input[0]["Config"]["Labels"]["example.too-many"] = json!("65th");
    assert!(check_owned_inspect(&input.to_string(), &expected).is_err());
}

#[test]
fn exact_inspect_byte_limit_is_accepted_but_one_extra_byte_is_not() {
    let expected = ExpectedRuntimeOwnership::from_unverified(ownership());
    let input = document();
    let exact = format!("{input}{}", " ".repeat(65_536 - input.len()));
    assert!(check_owned_inspect(&exact, &expected).is_ok());
    assert!(check_owned_inspect(&format!("{exact} "), &expected).is_err());
}

#[test]
fn malformed_expectations_are_checked_before_parsing_and_do_not_leak() {
    for field in [
        "installation",
        "container",
        "image",
        "name",
        "process",
        "workspace",
        "namespace",
        "proxy",
        "revision",
        "generation",
        "fence",
        "config",
        "manifest",
        "launch",
    ] {
        let mut raw = ownership();
        match field {
            "installation" => raw.installation_id = CANARY.into(),
            "container" => raw.container_id = "sha256:abc".into(),
            "image" => raw.image_id = "image:latest".into(),
            "name" => raw.name = format!("/tmp/{CANARY}"),
            "process" => raw.process_instance_id = CANARY.into(),
            "workspace" => raw.target.workspace_id = "".into(),
            "namespace" => raw.target.namespace_id = "a/b".into(),
            "proxy" => raw.target.proxy_id = PROXY.to_uppercase(),
            "revision" => raw.target.revision_id = OTHER.replace("-7c13-", "-4c13-"),
            "generation" => raw.target.generation = 0,
            "fence" => raw.target.fencing_token = 0,
            "config" => raw.config_hash = CANARY.into(),
            "manifest" => raw.runtime_manifest_hash = "A".repeat(64),
            "launch" => raw.launch_context_hash = "e".repeat(63),
            _ => unreachable!(),
        }
        let matched_bad = inspect(&raw, "created").to_string();
        assert!(!format!("{raw:?}").contains(CANARY));
        let expected = ExpectedRuntimeOwnership::from_unverified(raw);
        assert!(!format!("{expected:?}").contains(CANARY));
        for input in [matched_bad.as_str(), "malformed"] {
            let error = check_owned_inspect(input, &expected).unwrap_err();
            assert_eq!(error, RuntimeError::InvalidExpectedOwnership, "{field}");
            assert!(!format!("{error:?} {error}").contains(CANARY));
        }
    }
}

#[test]
fn shaped_but_inconsistent_expected_name_is_not_an_arbitrary_engine_handle() {
    let mut raw = ownership();
    raw.name = format!("apex-runtime-{OTHER}");
    let input = inspect(&raw, "created").to_string();
    let expected = ExpectedRuntimeOwnership::from_unverified(raw);
    assert_eq!(
        check_owned_inspect(&input, &expected).unwrap_err(),
        RuntimeError::InvalidExpectedOwnership
    );
}

#[test]
fn synthetic_equal_hashes_and_large_integers_only_establish_comparison_consistency() {
    let mut raw = ownership();
    raw.runtime_manifest_hash = raw.config_hash.clone();
    raw.target.generation = u64::MAX;
    raw.target.fencing_token = BIG;
    let expected = ExpectedRuntimeOwnership::from_unverified(raw.clone());
    let result = check_owned_inspect(&inspect(&raw, "created").to_string(), &expected).unwrap();
    assert_eq!(result.identity().target.generation, u64::MAX);
    assert_eq!(result.identity().target.fencing_token, BIG);
    // Matching synthetic/stale/high expected values says NOTHING about a current
    // authenticated lease, installation provenance, ownership grant or admission.
}
