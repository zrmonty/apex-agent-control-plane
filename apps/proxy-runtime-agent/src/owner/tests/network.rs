use super::*;
pub(crate) fn execution_documents() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let network = crate::network_catalog::tests::fixture();
    let image = json!({"schema_version":1,"images":[{"id":"guard-v1",
        "image_ref":network["profiles"][0]["guard_image_ref"],"signing":{
            "certificate_oidc_issuer":"https://issuer.example","certificate_identity":"release@example.com"}}]});
    let scope = network["installation_id"].as_str().unwrap();
    let authority = json!({"schema_version":1,"version":"v1","valid_from_unix_us":1,"expires_at_unix_us":i64::MAX,
        "profiles":[{"installation_id":scope,"workspace_id":"work","namespace_id":"ns","proxy_id":scope,
            "host_policy_version":"host-v1","reference":"live","version":"v1",
            "governance":{"endpoint":"https://governance.example","tls_server_name":"governance.example"},
            "evidence":{"endpoint":"https://evidence.example","tls_server_name":"evidence.example"}}]});
    let tools = json!({"schema_version":1,"version":"v1","valid_from_unix_us":1,"expires_at_unix_us":i64::MAX,
        "profiles":[{"installation_id":scope,"workspace_id":"work","namespace_id":"ns","proxy_id":scope,"revision_id":scope,
            "host_policy_version":"host-v1","deployment_bindings_version":"bindings-1","config_hash":"a".repeat(64),"entries":[]}]});
    (
        serde_json::to_vec(&image).unwrap(),
        serde_json::to_vec(&authority).unwrap(),
        serde_json::to_vec(&tools).unwrap(),
    )
}
fn metadata() -> Metadata {
    let (p, c) = documents();
    let (i, a, t) = execution_documents();
    Metadata::parse(&p, &c)
        .unwrap()
        .with_execution(&i, &a, &t)
        .unwrap()
}
fn network(v: &serde_json::Value) -> Result<Metadata, &'static str> {
    metadata().with_network(
        &serde_json::to_vec(v).unwrap(),
        "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01",
        "host-v1",
    )
}
#[test]
fn network_metadata_digest_changes_with_every_original_byte_and_keeps_legacy() {
    let legacy = metadata();
    let v = crate::network_catalog::tests::fixture();
    let joined = network(&v).unwrap();
    assert!(joined.network.is_some());
    assert!(joined.current().is_ok());
    assert_ne!(legacy.digest, joined.digest);
    assert_eq!(joined.digest, network(&v).unwrap().digest);
    let pretty = metadata()
        .with_network(
            &serde_json::to_vec_pretty(&v).unwrap(),
            v["installation_id"].as_str().unwrap(),
            "host-v1",
        )
        .unwrap();
    assert_ne!(joined.digest, pretty.digest);
    assert_eq!(legacy.digest, metadata().digest);
    assert!(legacy.network.is_none());
}
#[test]
fn network_metadata_requires_execution_exact_identity_images_and_currentness() {
    let v = crate::network_catalog::tests::fixture();
    let bytes = serde_json::to_vec(&v).unwrap();
    let (p, c) = documents();
    assert!(
        Metadata::parse(&p, &c)
            .unwrap()
            .with_network(&bytes, v["installation_id"].as_str().unwrap(), "host-v1")
            .is_err()
    );
    for (path, bad) in [
        ("/installation_id", json!(uuid::Uuid::now_v7().to_string())),
        ("/host_policy_version", json!("wrong")),
        ("/expires_at_unix_us", json!(2)),
        ("/valid_from_unix_us", json!(i64::MAX - 1)),
        ("/profiles/0/guard_image_catalog_id", json!("not-guard")),
        (
            "/profiles/0/guard_image_ref",
            json!(format!("registry.example/guard@sha256:{}", "c".repeat(64))),
        ),
    ] {
        let mut bad_value = v.clone();
        *bad_value.pointer_mut(path).unwrap() = bad;
        assert!(network(&bad_value).is_err(), "{path}");
    }
}
