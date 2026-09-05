use super::support::*;
use apex_proxy_runtime_agent::{ExpectedRuntimeOwnership, RuntimeError, check_owned_inspect};
use serde_json::{Value, json};
use std::error::Error as _;

fn refused(input: &str) {
    let expected = ExpectedRuntimeOwnership::from_unverified(ownership());
    let error = check_owned_inspect(input, &expected).expect_err("must refuse inspect");
    assert!(!format!("{error:?} {error}").contains(CANARY));
    assert!(error.source().is_none());
}

#[test]
fn each_observed_identity_and_label_mismatch_is_refused() {
    let raw = ownership();
    let expected = ExpectedRuntimeOwnership::from_unverified(raw.clone());
    for (key, replacement) in [
        ("Id", "f".repeat(64)),
        ("Image", format!("sha256:{}", "f".repeat(64))),
        ("Name", format!("/apex-runtime-{OTHER}")),
    ] {
        let mut input = inspect(&raw, "created");
        input[0][key] = json!(replacement);
        assert!(
            check_owned_inspect(&input.to_string(), &expected).is_err(),
            "{key}"
        );
    }
    let wrong = [
        ("installation-id", OTHER.to_owned()),
        ("workspace-id", "other".into()),
        ("namespace-id", "other".into()),
        ("proxy-id", OTHER.into()),
        ("revision-id", OTHER.into()),
        ("generation", (BIG + 1).to_string()),
        ("fencing-token", (u64::MAX - 1).to_string()),
        ("config-hash", "f".repeat(64)),
        ("runtime-manifest-hash", "f".repeat(64)),
        ("launch-context-hash", "f".repeat(64)),
        ("process-instance-id", OTHER.into()),
    ];
    for (suffix, replacement) in wrong {
        let mut input = inspect(&raw, "created");
        input[0]["Config"]["Labels"][format!("io.apex.runtime.{suffix}")] = json!(replacement);
        assert_eq!(
            check_owned_inspect(&input.to_string(), &expected).unwrap_err(),
            RuntimeError::OwnershipMismatch
        );
    }
}

#[test]
fn changed_expected_record_is_not_reflected_or_adopted_from_labels() {
    for field in [
        "installation",
        "container",
        "image",
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
            "installation" => raw.installation_id = OTHER.into(),
            "container" => raw.container_id = "f".repeat(64),
            "image" => raw.image_id = format!("sha256:{}", "f".repeat(64)),
            "process" => {
                raw.process_instance_id = OTHER.into();
                raw.name = format!("apex-runtime-{OTHER}");
            }
            "workspace" => raw.target.workspace_id = "foreign".into(),
            "namespace" => raw.target.namespace_id = "foreign".into(),
            "proxy" => raw.target.proxy_id = OTHER.into(),
            "revision" => raw.target.revision_id = OTHER.into(),
            "generation" => raw.target.generation = BIG - 1,
            "fence" => raw.target.fencing_token = 1,
            "config" => raw.config_hash = "f".repeat(64),
            "manifest" => raw.runtime_manifest_hash = "f".repeat(64),
            "launch" => raw.launch_context_hash = "f".repeat(64),
            _ => unreachable!(),
        }
        let expected = ExpectedRuntimeOwnership::from_unverified(raw);
        assert_eq!(
            check_owned_inspect(&document(), &expected).unwrap_err(),
            RuntimeError::OwnershipMismatch,
            "{field}"
        );
    }
}

#[test]
fn neither_stale_nor_poisoned_high_expected_fence_proves_ownership() {
    let mut observed = ownership();
    observed.target.fencing_token = 4;
    for fence in [1, u64::MAX] {
        let mut raw = observed.clone();
        raw.target.fencing_token = fence;
        let expected = ExpectedRuntimeOwnership::from_unverified(raw);
        assert!(
            check_owned_inspect(&inspect(&observed, "running").to_string(), &expected).is_err()
        );
    }
    // No durable state or lease is updated by a pure comparison.
}

#[test]
fn required_inspect_fields_and_every_ownership_label_must_be_present() {
    for path in [
        vec!["Id"],
        vec!["Name"],
        vec!["Image"],
        vec!["Config"],
        vec!["State"],
        vec!["Config", "Labels"],
        vec!["State", "Status"],
    ] {
        let mut input = inspect(&ownership(), "created");
        let mut object = &mut input[0];
        for key in &path[..path.len() - 1] {
            object = &mut object[*key];
        }
        object
            .as_object_mut()
            .unwrap()
            .remove(*path.last().unwrap());
        refused(&input.to_string());
    }
    for key in labels(&ownership()).as_object().unwrap().keys() {
        let mut input = inspect(&ownership(), "created");
        input[0]["Config"]["Labels"]
            .as_object_mut()
            .unwrap()
            .remove(key);
        refused(&input.to_string());
    }
}

#[test]
fn inspect_types_cardinality_trailing_and_canonical_ids_are_strict() {
    for path in [
        vec!["Id"],
        vec!["Name"],
        vec!["Image"],
        vec!["Config"],
        vec!["State"],
        vec!["Config", "Labels"],
        vec!["State", "Status"],
    ] {
        for bad in [Value::Null, json!(7), json!(true), json!([])] {
            let mut input = inspect(&ownership(), "created");
            let mut field = &mut input[0];
            for key in &path {
                field = &mut field[*key];
            }
            *field = bad;
            refused(&input.to_string());
        }
    }
    for input in [
        String::new(),
        "[]".into(),
        "null".into(),
        "[null]".into(),
        format!("{}true", document()),
        format!("{}{}", document(), document()),
        json!([
            inspect(&ownership(), "created")[0],
            inspect(&ownership(), "created")[0]
        ])
        .to_string(),
    ] {
        refused(&input);
    }
    for (key, values) in [
        (
            "Id",
            vec!["sha256:abc".into(), "a".repeat(63), "A".repeat(64)],
        ),
        (
            "Image",
            vec![
                "b".repeat(64),
                format!("sha256:{}", "B".repeat(64)),
                "image:latest".into(),
            ],
        ),
        (
            "Name",
            vec![
                format!("//{}", ownership().name),
                format!("{} ", ownership().name),
                "/tmp/foreign".into(),
            ],
        ),
    ] {
        for value in values {
            let mut input = inspect(&ownership(), "created");
            input[0][key] = json!(value);
            refused(&input.to_string());
        }
    }
}

#[test]
fn duplicate_required_fields_and_labels_never_use_last_wins() {
    let input = document();
    for (key, bad) in [
        ("Id", "\"foreign\""),
        ("Name", "\"foreign\""),
        ("Image", "\"foreign\""),
        ("Config", "{}"),
        ("State", "{}"),
        ("Labels", "{}"),
        ("Status", "\"exited\""),
    ] {
        refused(&duplicate_before(&input, key, bad));
    }
    for (key, value) in labels(&ownership()).as_object().unwrap() {
        refused(&duplicate_before(&input, key, &value.to_string()));
        refused(&duplicate_before(&input, key, "\"foreign\""));
    }
    let key = "\"io.apex.runtime.fencing-token\":";
    let escaped = input.replacen(
        key,
        &format!("\"\\u0069o.apex.runtime.fencing-token\":\"0\",{key}"),
        1,
    );
    refused(&escaped);
    refused(&input.replacen("\"Id\":", "\"\\u0049d\":\"foreign\",\"Id\":", 1));
    let extra = input.replacen("\"Labels\":{", "\"Labels\":{\"example.extra\":\"one\",", 1);
    refused(&duplicate_before(&extra, "example.extra", "\"two\""));
}

#[test]
fn label_values_are_typed_bounded_and_decimal_canonical_without_float_conversion() {
    for suffix in ["generation", "fencing-token"] {
        for value in [
            json!(BIG),
            json!(true),
            json!(null),
            json!([]),
            json!({"secret": CANARY}),
            json!("0"),
            json!("01"),
            json!("+1"),
            json!("1 "),
            json!("1e3"),
            json!("1.0"),
            json!("18446744073709551616"),
            json!("9007199254740992"),
        ] {
            let mut input = inspect(&ownership(), "created");
            input[0]["Config"]["Labels"][format!("io.apex.runtime.{suffix}")] = value;
            refused(&input.to_string());
        }
    }
    for (key, value) in [
        ("x".repeat(129), json!("small")),
        ("é".repeat(65), json!("small")),
        (String::new(), json!("small")),
        ("extra".into(), json!("x".repeat(513))),
        ("extra".into(), json!("é".repeat(257))),
        ("extra".into(), json!(null)),
        ("extra".into(), json!({"nested": CANARY})),
    ] {
        let mut input = inspect(&ownership(), "created");
        input[0]["Config"]["Labels"][key] = value;
        refused(&input.to_string());
    }
}

#[test]
fn ignored_inspect_structure_cannot_bypass_nesting_bound() {
    let expected = ExpectedRuntimeOwnership::from_unverified(ownership());
    for (arrays, allowed) in [(30, true), (31, false), (200, false)] {
        let input = document();
        let nested = format!("{}0{}", "[".repeat(arrays), "]".repeat(arrays));
        let augmented = input.replacen("[{", &format!("[{{\"IgnoredDeep\":{nested},"), 1);
        assert_eq!(check_owned_inspect(&augmented, &expected).is_ok(), allowed);
    }
}

#[test]
fn error_taxonomy_has_only_static_bounded_messages_and_no_source() {
    for (error, code) in [
        (RuntimeError::InvalidTarget, "RUNTIME_INVALID_TARGET"),
        (
            RuntimeError::InvalidConfigurationBinding,
            "RUNTIME_INVALID_CONFIGURATION_BINDING",
        ),
        (RuntimeError::InvalidInspect, "RUNTIME_INVALID_INSPECT"),
        (
            RuntimeError::InvalidExpectedOwnership,
            "RUNTIME_INVALID_EXPECTED_OWNERSHIP",
        ),
        (
            RuntimeError::OwnershipMismatch,
            "RUNTIME_OWNERSHIP_MISMATCH",
        ),
        (RuntimeError::UnsupportedState, "RUNTIME_UNSUPPORTED_STATE"),
    ] {
        assert_eq!(error.to_string(), code);
        assert!(error.to_string().len() <= 64 && error.source().is_none());
        assert!(!format!("{error:?}").contains(CANARY));
    }
}
