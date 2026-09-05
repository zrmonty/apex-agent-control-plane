use super::support::*;
use apex_control_plane_api::proto;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[test]
fn decoded_operation_blob_cannot_replace_the_independently_selected_row_identity_or_state() {
    let f = Fixture::new(true);
    f.positive();
    for field in 0..16 {
        let mut operation = f.operation.clone();
        match field {
            0 => operation.operation_id = Uuid::now_v7().to_string(),
            1 => operation.request_id = Uuid::now_v7().to_string(),
            2 => operation.request_id = "018f3d4a-8b9c-7d0e-cf12-3a4b5c6d7e87".into(),
            3 => operation.scope = None,
            4 => operation.scope.as_mut().unwrap().workspace_id = "other".into(),
            5 => operation.scope.as_mut().unwrap().namespace_id = "other".into(),
            6 => operation.scope.as_mut().unwrap().proxy_id = Uuid::now_v7().to_string(),
            7 => operation.revision_id = Uuid::now_v7().to_string(),
            8 => operation.generation += 1,
            9 => operation.desired_state = proto::ProxyDesiredState::Paused as i32,
            10 => operation.observed_state = proto::ProxyObservedState::Reconciling as i32,
            11 => operation.observed_state = 999,
            12 => operation.observed_at_unix_us = 1,
            13 => operation.operation_id = String::new(),
            14 => operation.generation = 0,
            _ => operation.error_code = "secret://SNAPSHOT_CANARY/error".into(),
        }
        f.save_operation(&operation);
        f.reject(
            &f.target,
            &f.operation.operation_id,
            "controller-a",
            REFUSED,
        );
        f.save_operation(&f.operation);
    }
    f.execute(
        "UPDATE mcp_proxy_operations SET current_result=$2 WHERE operation_id=$1",
        &[
            &f.operation.operation_id.parse::<Uuid>().unwrap(),
            &vec![255_u8],
        ],
    );
    f.reject(
        &f.target,
        &f.operation.operation_id,
        "controller-a",
        REFUSED,
    );
    f.save_operation(&f.operation);
    f.positive();
}

#[test]
fn publication_flag_and_historical_control_hash_are_checked_from_the_actual_revision_row() {
    let f = Fixture::new(true);
    f.positive();
    let raw: String = f
        .client()
        .query_one(
            "SELECT spec_json FROM mcp_proxy_revisions WHERE proxy_id=$1 AND revision_id=$2",
            &[f.input.proxy_id.as_uuid(), f.revision_id().as_uuid()],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        format!("{:x}", Sha256::digest(raw.as_bytes())),
        f.revision.config_hash,
        "the real public writer supplies the historical canonical control spec"
    );
    f.execute(
        "UPDATE mcp_proxy_revisions SET is_published=FALSE WHERE proxy_id=$1 AND revision_id=$2",
        &[f.input.proxy_id.as_uuid(), f.revision_id().as_uuid()],
    );
    f.reject(
        &f.target,
        &f.operation.operation_id,
        "controller-a",
        REFUSED,
    );
    f.execute(
        "UPDATE mcp_proxy_revisions SET is_published=TRUE WHERE proxy_id=$1 AND revision_id=$2",
        &[f.input.proxy_id.as_uuid(), f.revision_id().as_uuid()],
    );
    for hash in ["b".repeat(64), "F".repeat(64)] {
        f.execute(
            "UPDATE mcp_proxy_revisions SET config_hash=$3 WHERE proxy_id=$1 AND revision_id=$2",
            &[f.input.proxy_id.as_uuid(), f.revision_id().as_uuid(), &hash],
        );
        f.reject(
            &f.target,
            &f.operation.operation_id,
            "controller-a",
            REFUSED,
        );
    }
    f.execute(
        "UPDATE mcp_proxy_revisions SET config_hash=$3 WHERE proxy_id=$1 AND revision_id=$2",
        &[
            f.input.proxy_id.as_uuid(),
            f.revision_id().as_uuid(),
            &f.revision.config_hash,
        ],
    );
    f.positive();
}

#[test]
fn rehashed_unsupported_specs_and_malformed_rows_refuse_without_publication_hash_bypass() {
    let f = Fixture::new(true);
    f.positive();
    let raw: String = f
        .client()
        .query_one(
            "SELECT spec_json FROM mcp_proxy_revisions WHERE proxy_id=$1 AND revision_id=$2",
            &[f.input.proxy_id.as_uuid(), f.revision_id().as_uuid()],
        )
        .unwrap()
        .get(0);
    let original: Value = serde_json::from_str(&raw).unwrap();
    let mut inputs = vec!["SNAPSHOT_CANARY malformed".to_owned(), "{}".into()];
    for field in 0..11 {
        let mut spec = original.clone();
        match field {
            0 => spec["ingress"]["inbound_authentication_required"] = json!(false),
            1 => spec["ingress"]["protocol_revision"] = json!("unsupported"),
            2 => spec["upstreams"][0]["transport"] = json!(2),
            3 => spec["runtime_profile"]["rootless"] = json!(false),
            4 => spec["runtime_profile"]["filesystem_policy"] = json!("writable"),
            5 => spec["runtime_profile"]["network_policy"] = json!("default-open"),
            6 => spec["governance_binding"]["approval_mode"] = json!("operator"),
            7 => spec["exposed_tools"][0]["alias"] = json!("renamed.read"),
            8 => spec["upstreams"][0]["credential_ref"] = json!(""),
            9 => spec["ingress"]["transport"] = json!(2),
            _ => {
                spec["cli_profiles"] = json!([{
                    "profile_id": "cli", "executable_ref": "exec://catalog/read",
                    "executable_digest": format!("sha256:{}", "a".repeat(64)),
                    "argv_template": ["read"], "argv_schema": { "fields": [] },
                    "environment_allowlist": [], "secret_refs": [], "working_directory": "/workspace",
                    "filesystem_policy": "read-only", "network_policy": "deny", "shell": false,
                    "timeout_ms": 1000, "max_output_bytes": 1024, "allowed_exit_codes": [0]
                }])
            }
        }
        let encoded = spec.to_string();
        if field != 8 {
            apex_control_plane_api::parse_proxy_spec_wire_json(&encoded)
                .expect("unsupported publication case must retain a valid control-spec shape");
        }
        inputs.push(encoded);
    }
    for spec in inputs {
        // These modified canonical JSON bytes get a matching SHA, so an integrity
        // mismatch cannot substitute for supported-spec validation.
        let hash = format!("{:x}", Sha256::digest(spec.as_bytes()));
        f.execute("UPDATE mcp_proxy_revisions SET spec_json=$3,config_hash=$4 WHERE proxy_id=$1 AND revision_id=$2",
            &[f.input.proxy_id.as_uuid(), f.revision_id().as_uuid(), &spec, &hash]);
        f.reject(
            &f.target,
            &f.operation.operation_id,
            "controller-a",
            REFUSED,
        );
    }
    f.execute("UPDATE mcp_proxy_revisions SET spec_json=$3,config_hash=$4 WHERE proxy_id=$1 AND revision_id=$2",
        &[f.input.proxy_id.as_uuid(), f.revision_id().as_uuid(), &raw, &f.revision.config_hash]);
    f.positive();
}
