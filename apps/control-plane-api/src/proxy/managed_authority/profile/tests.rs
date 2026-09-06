//! Strict document tests only; these values are not authenticated TLS peers.
use super::*;
use serde_json::{Value, json};

fn document() -> Value {
    json!({
        "schema_version":1,"version":"managed-v1",
        "valid_from_unix_us":"1","expires_at_unix_us":"9223372036854775807",
        "profiles":[{
            "installation_id":"0191b7f1-7f2c-7c13-9a61-2f29f2be1001",
            "workspace_id":"northstar","namespace_id":"research",
            "proxy_id":"0191b7f1-7f2c-7c13-9a61-2f29f2be1002",
            "revision_id":"0191b7f1-7f2c-7c13-9a61-2f29f2be1003",
            "authority_profile_ref":"profile:read","authority_profile_version":"v1",
            "evidence_agent_id":"proxy-reader",
            "credentials":[{"certificate_sha256":"a".repeat(64),"token_sha256":"b".repeat(64)}]
        }]
    })
}

#[test]
fn valid_bounded_managed_profile_and_empty_revocation_document_parse() {
    assert!(Profile::parse(&serde_json::to_vec(&document()).unwrap()).is_ok());
    let mut value = document();
    value["profiles"] = json!([]);
    assert!(Profile::parse(&serde_json::to_vec(&value).unwrap()).is_ok());
}

#[test]
fn managed_profiles_reject_unknown_duplicate_noncanonical_and_ambiguous_entries() {
    for (pointer, value) in [
        ("/schema_version", json!(2)),
        ("/version", json!("..")),
        ("/valid_from_unix_us", json!(1)),
        ("/valid_from_unix_us", json!("01")),
        ("/valid_from_unix_us", json!("0")),
        ("/expires_at_unix_us", json!("9223372036854775808")),
        ("/expires_at_unix_us", json!("1")),
        ("/profiles/0/installation_id", json!("not-an-installation")),
        ("/profiles/0/workspace_id", json!("northstar/other")),
        ("/profiles/0/evidence_agent_id", json!("")),
        ("/profiles/0/credentials", json!([])),
        (
            "/profiles/0/credentials/0/token_sha256",
            json!("B".repeat(64)),
        ),
    ] {
        let mut input = document();
        *input.pointer_mut(pointer).unwrap() = value;
        assert!(
            Profile::parse(&serde_json::to_vec(&input).unwrap()).is_err(),
            "{pointer}"
        );
    }
    let mut input = document();
    input["unexpected"] = json!(true);
    assert!(Profile::parse(&serde_json::to_vec(&input).unwrap()).is_err());
    input = document();
    input["profiles"][0]["credentials"][0]["raw_token"] = json!("must-not-be-here");
    assert!(Profile::parse(&serde_json::to_vec(&input).unwrap()).is_err());
    input = document();
    input["profiles"] = json!([input["profiles"][0], input["profiles"][0]]);
    assert!(Profile::parse(&serde_json::to_vec(&input).unwrap()).is_err());
    let encoded = serde_json::to_string(&document()).unwrap();
    let duplicate = encoded.replacen(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":1",
        1,
    );
    assert!(Profile::parse(duplicate.as_bytes()).is_err());
    assert!(Profile::parse(&vec![b' '; 262145]).is_err());
}

#[test]
fn rotation_stays_within_one_logical_proxy_and_preserves_domain_identifier_width() {
    let mut input = document();
    input["profiles"][0]["workspace_id"] = json!("a".repeat(256));
    input["profiles"][0]["namespace_id"] = json!("a._:-Z9");
    input["profiles"][0]["evidence_agent_id"] = json!("a".repeat(256));
    assert!(Profile::parse(&serde_json::to_vec(&input).unwrap()).is_ok());
    let first = document()["profiles"][0].clone();
    let mut second = first.clone();
    second["revision_id"] = json!("0191b7f1-7f2c-7c13-9a61-2f29f2be1004");
    input = document();
    input["profiles"] = json!([first, second]);
    assert!(Profile::parse(&serde_json::to_vec(&input).unwrap()).is_ok());
    input["profiles"][1]["proxy_id"] = json!("0191b7f1-7f2c-7c13-9a61-2f29f2be1005");
    assert!(
        Profile::parse(&serde_json::to_vec(&input).unwrap()).is_err(),
        "shared evidence identity"
    );
    input["profiles"][1]["evidence_agent_id"] = json!("another-proxy");
    assert!(
        Profile::parse(&serde_json::to_vec(&input).unwrap()).is_err(),
        "shared TLS/token pair"
    );
    input["profiles"][1]["credentials"][0]["token_sha256"] = json!("c".repeat(64));
    assert!(Profile::parse(&serde_json::to_vec(&input).unwrap()).is_ok());
}
