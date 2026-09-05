use serde_json::json;

use super::super::enrollment::{Enrollment, preflight};
use super::support::{bytes, enrollment};

#[test]
fn preflight_enforces_original_bytes_and_depth_before_shape_decoding() {
    let mut exact = bytes(&enrollment());
    exact.resize(65_536, b' ');
    assert!(preflight(&exact).is_ok());
    assert!(Enrollment::parse_json(&exact).is_ok());
    exact.push(b' ');
    assert!(preflight(&exact).is_err());
    assert!(Enrollment::parse_json(&exact).is_err());
    assert!(preflight(&[]).is_err());
    assert!(preflight(&[0xff]).is_err());
    // Direct lexical guard checks avoid letting the object-shape guard mask depth.
    let at_limit = format!("{}0{}", "[".repeat(32), "]".repeat(32));
    let over = format!("[{at_limit}]");
    assert!(preflight(at_limit.as_bytes()).is_ok());
    assert!(preflight(over.as_bytes()).is_err());
    assert!(preflight(br#"{"quoted":"[[[\"\\"}"#).is_ok());
}

#[test]
fn identifier_caps_accept_exact_bytes_and_reject_one_more() {
    for (pointer, max) in [
        ("/version", 128),
        ("/peerPolicyVersion", 128),
        ("/controllers/0/identityId", 128),
        ("/controllers/0/workerId", 128),
        ("/installations/0/agentIdentityId", 128),
        ("/installations/0/hostPolicyVersion", 128),
        ("/installations/0/scopes/0/workspaceId", 256),
        ("/installations/0/scopes/0/namespaceId", 256),
    ] {
        let mut value = enrollment();
        *value.pointer_mut(pointer).unwrap() = json!("a".repeat(max));
        assert!(Enrollment::parse_json(&bytes(&value)).is_ok());
        *value.pointer_mut(pointer).unwrap() = json!("a".repeat(max + 1));
        assert!(Enrollment::parse_json(&bytes(&value)).is_err());
    }
}

#[test]
fn controller_and_installation_collection_caps_have_independent_positive_controls() {
    let mut value = enrollment();
    value["controllers"] = json!(
        (0..128)
            .map(|i| json!({
                "identityId": format!("controller-{i}"), "workerId": format!("worker-{i}")
            }))
            .collect::<Vec<_>>()
    );
    assert!(Enrollment::parse_json(&bytes(&value)).is_ok());
    value["controllers"]
        .as_array_mut()
        .unwrap()
        .push(json!({"identityId":"extra", "workerId":"extra"}));
    assert!(Enrollment::parse_json(&bytes(&value)).is_err());

    let mut value = enrollment();
    let template = value["installations"][0].clone();
    value["installations"] = json!(
        (0..128)
            .map(|i| {
                let mut row = template.clone();
                row["installationId"] = json!(format!("018f3d4a-8b9c-7d0e-8f12-{i:012x}"));
                row
            })
            .collect::<Vec<_>>()
    );
    assert!(bytes(&value).len() <= 65_536);
    assert!(Enrollment::parse_json(&bytes(&value)).is_ok());
    let mut extra = template;
    extra["installationId"] = json!("018f3d4a-8b9c-7d0e-8f12-ffffffffffff");
    value["installations"].as_array_mut().unwrap().push(extra);
    assert!(Enrollment::parse_json(&bytes(&value)).is_err());
}

#[test]
fn scope_caps_are_64_per_installation_and_1024_total_not_a_cartesian_product() {
    let mut value = enrollment();
    value["installations"][0]["scopes"] = json!(
        (0..64)
            .map(|i| json!({
                "workspaceId": "w", "namespaceId": format!("n{i}")
            }))
            .collect::<Vec<_>>()
    );
    assert!(Enrollment::parse_json(&bytes(&value)).is_ok());
    let mut over_row = value.clone();
    over_row["installations"][0]["scopes"]
        .as_array_mut()
        .unwrap()
        .push(json!({"workspaceId":"w","namespaceId":"extra"}));
    assert!(Enrollment::parse_json(&bytes(&over_row)).is_err());
    let template = value["installations"][0].clone();
    value["installations"] = json!(
        (0..16)
            .map(|i| {
                let mut row = template.clone();
                row["installationId"] = json!(format!("018f3d4a-8b9c-7d0e-8f12-{i:012x}"));
                row
            })
            .collect::<Vec<_>>()
    );
    assert!(bytes(&value).len() < 65_536);
    assert!(Enrollment::parse_json(&bytes(&value)).is_ok());
    let mut extra = template;
    extra["installationId"] = json!("018f3d4a-8b9c-7d0e-8f12-ffffffffffff");
    extra["scopes"] = json!([{"workspaceId":"w","namespaceId":"one"}]);
    value["installations"].as_array_mut().unwrap().push(extra);
    assert!(bytes(&value).len() < 65_536);
    assert!(Enrollment::parse_json(&bytes(&value)).is_err());
}

#[test]
fn empty_or_duplicate_enrollment_collections_refuse_without_alias_resolution() {
    for pointer in ["/controllers", "/installations", "/installations/0/scopes"] {
        let mut value = enrollment();
        *value.pointer_mut(pointer).unwrap() = json!([]);
        assert!(Enrollment::parse_json(&bytes(&value)).is_err());
        let mut value = enrollment();
        let duplicate = value.pointer(pointer).unwrap()[0].clone();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert!(Enrollment::parse_json(&bytes(&value)).is_err());
    }
    for second in [
        json!({"identityId":"controller-a","workerId":"worker-b"}),
        json!({"identityId":"controller-b","workerId":"worker-a"}),
    ] {
        let mut value = enrollment();
        value["controllers"].as_array_mut().unwrap().push(second);
        assert!(Enrollment::parse_json(&bytes(&value)).is_err());
    }
}
