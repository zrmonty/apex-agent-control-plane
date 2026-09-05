use super::DeploymentCatalog;
use crate::{
    proto,
    proxy::{McpProxyRevision, ProxyId, ProxyLifecycleState, ProxyRevisionId, ProxySpec},
};
use serde_json::{Value, json};

const INSTALLATION: &str = "01940000-0000-7000-8000-000000000001";
const OTHER_ID: &str = "01940000-0000-7000-8000-000000000002";
const HOST_POLICY: &str = "host-v1";
const GOLDEN_HASH: &str = "db5ddc4670e5f901240e1c2910d9f78dd8a65237c86f197d13938be967afe5da";

// The same independent control/runtime goldens used by export_runtime_fixture.
fn fixture() -> (Value, McpProxyRevision, proto::RuntimeConfiguration) {
    let control: proto::McpProxyRevision = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/fixtures/mcp-proxy/control-revision.json"
    )))
    .unwrap();
    let runtime: proto::RuntimeConfiguration = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/fixtures/mcp-proxy/runtime-revision.json"
    )))
    .unwrap();
    let revision = McpProxyRevision::new(
        ProxyId::new(&control.proxy_id).unwrap(),
        ProxyRevisionId::new(&control.revision_id).unwrap(),
        ProxySpec::try_from(control.spec.unwrap()).unwrap(),
        control.config_hash,
        ProxyLifecycleState::Ready,
    )
    .unwrap();
    let document = json!({
        "schemaVersion": 1,
        "version": "deployment-v1",
        "validFromUnixUs": "100",
        "expiresAtUnixUs": "200",
        "profiles": [{
            "installationId": INSTALLATION,
            "workspaceId": runtime.workspace_id,
            "namespaceId": runtime.namespace_id,
            "proxyId": runtime.proxy_id,
            "revisionId": runtime.revision_id,
            "hostPolicyVersion": HOST_POLICY,
            "resourceUrl": runtime.resource_url,
            "images": [{
                "digest": revision.spec.runtime_profile.image_digest,
                "imageRef": runtime.image_ref,
            }],
            "secretRefs": runtime.secret_refs,
            "toolSchemas": runtime.tool_schemas,
            "approvedOutputProfiles": ["portfolio-read-v1"],
            "networkGrants": runtime.network_grants,
            "auth": runtime.auth,
            "telemetry": runtime.telemetry,
            "pidLimit": runtime.pid_limit,
        }],
    });
    (document, revision, runtime)
}

fn parse(document: &Value) -> DeploymentCatalog {
    DeploymentCatalog::parse_json(&serde_json::to_vec(document).unwrap())
        .expect("valid deployment metadata must be accepted")
}

fn target(runtime: &proto::RuntimeConfiguration) -> proto::RuntimeTarget {
    proto::RuntimeTarget {
        workspace_id: runtime.workspace_id.clone(),
        namespace_id: runtime.namespace_id.clone(),
        proxy_id: runtime.proxy_id.clone(),
        revision_id: runtime.revision_id.clone(),
        generation: runtime.generation,
        fencing_token: 7,
    }
}

fn refused(document: &Value) {
    assert!(DeploymentCatalog::parse_json(&serde_json::to_vec(document).unwrap()).is_err());
}

#[test]
fn catalog_accepts_bounded_document_and_checks_half_open_validity() {
    let (document, _, _) = fixture();
    let catalog = parse(&document);
    assert_eq!(catalog.version(), "deployment-v1");
    assert!(catalog.check_current(99).is_err());
    assert!(catalog.check_current(100).is_ok());
    assert!(catalog.check_current(199).is_ok());
    assert!(catalog.check_current(200).is_err());
    assert!(catalog.check_current(u64::MAX).is_err());
    assert_eq!(format!("{catalog:?}"), "DeploymentCatalog { [redacted] }");
}

#[test]
fn exact_selection_compiles_complete_independent_runtime_golden() {
    let (document, revision, mut expected) = fixture();
    let unchanged = revision.clone();
    let actual = parse(&document)
        .compile(&target(&expected), INSTALLATION, HOST_POLICY, &revision)
        .expect("exact metadata and revision must compile");
    expected.runtime_manifest_hash = GOLDEN_HASH.into();
    assert_eq!(actual, expected);
    assert_eq!(revision, unchanged);
}

#[test]
fn generation_is_injected_from_verified_target_and_changes_manifest_only() {
    let (document, revision, runtime) = fixture();
    let mut selected = target(&runtime);
    selected.generation = 9_007_199_254_740_993;
    let actual = parse(&document)
        .compile(&selected, INSTALLATION, HOST_POLICY, &revision)
        .unwrap();
    assert_eq!(actual.generation, 9_007_199_254_740_993);
    assert_eq!(actual.config_hash, runtime.config_hash);
    assert_eq!(actual.spec, runtime.spec);
    assert_ne!(actual.runtime_manifest_hash, GOLDEN_HASH);
    assert_eq!(
        actual.runtime_manifest_hash,
        crate::proxy::runtime_manifest_hash(&actual).unwrap()
    );
}

#[test]
fn selection_denies_each_different_target_installation_or_host_policy() {
    let (document, revision, runtime) = fixture();
    let catalog = parse(&document);
    for field in [
        "workspace",
        "namespace",
        "proxy",
        "revision",
        "generation",
        "fence",
    ] {
        let mut selected = target(&runtime);
        match field {
            "workspace" => selected.workspace_id = "other-workspace".into(),
            "namespace" => selected.namespace_id = "other-namespace".into(),
            "proxy" => selected.proxy_id = OTHER_ID.into(),
            "revision" => selected.revision_id = OTHER_ID.into(),
            "generation" => selected.generation = 0,
            "fence" => selected.fencing_token = 0,
            _ => unreachable!(),
        }
        assert!(
            catalog
                .compile(&selected, INSTALLATION, HOST_POLICY, &revision)
                .is_err(),
            "{field}"
        );
    }
    for (installation, policy) in [(OTHER_ID, HOST_POLICY), (INSTALLATION, "host-v2")] {
        assert!(
            catalog
                .compile(&target(&runtime), installation, policy, &revision)
                .is_err()
        );
    }
    for generation in [i64::MAX as u64 + 1, u64::MAX] {
        let mut selected = target(&runtime);
        selected.generation = generation;
        assert!(
            catalog
                .compile(&selected, INSTALLATION, HOST_POLICY, &revision)
                .is_err()
        );
    }
}

#[test]
fn matching_profile_cannot_substitute_another_revision_or_proxy() {
    let (document, revision, runtime) = fixture();
    let catalog = parse(&document);
    let mut different = revision.clone();
    different.revision_id = ProxyRevisionId::new(OTHER_ID).unwrap();
    assert!(
        catalog
            .compile(&target(&runtime), INSTALLATION, HOST_POLICY, &different)
            .is_err()
    );
    different = revision;
    different.proxy_id = ProxyId::new(OTHER_ID).unwrap();
    assert!(
        catalog
            .compile(&target(&runtime), INSTALLATION, HOST_POLICY, &different)
            .is_err()
    );
}

#[test]
fn selector_uniqueness_excludes_host_policy_and_selection_is_not_first_profile() {
    let (mut document, revision, runtime) = fixture();
    let mut other = document["profiles"][0].clone();
    other["installationId"] = json!(OTHER_ID);
    other["pidLimit"] = json!(256);
    document["profiles"]
        .as_array_mut()
        .unwrap()
        .insert(0, other);
    let actual = parse(&document)
        .compile(&target(&runtime), INSTALLATION, HOST_POLICY, &revision)
        .unwrap();
    assert_eq!(actual.pid_limit, 128);
    document["profiles"][0]["installationId"] = json!(INSTALLATION);
    document["profiles"][0]["hostPolicyVersion"] = json!("host-v2");
    refused(&document);
}

#[test]
fn metadata_rejects_schema_epoch_version_and_selector_grammar_errors() {
    let (base, _, _) = fixture();
    for (pointer, value) in [
        ("/schemaVersion", json!(0)),
        ("/schemaVersion", json!(2)),
        ("/validFromUnixUs", json!("0")),
        ("/expiresAtUnixUs", json!("100")),
        ("/expiresAtUnixUs", json!("99")),
        ("/expiresAtUnixUs", json!("9223372036854775808")),
        ("/validFromUnixUs", json!("9223372036854775808")),
        ("/version", json!("")),
        ("/version", json!("v".repeat(129))),
        ("/version", json!("../private")),
        ("/profiles/0/installationId", json!("not-uuid")),
        (
            "/profiles/0/proxyId",
            json!("01940000-0000-4000-8000-000000000001"),
        ),
        (
            "/profiles/0/revisionId",
            json!("01940000-0000-7000-A000-000000000001"),
        ),
        ("/profiles/0/workspaceId", json!("../workspace")),
        ("/profiles/0/namespaceId", json!("")),
        ("/profiles/0/hostPolicyVersion", json!("h".repeat(129))),
        ("/profiles/0/secretRefs/0", json!("raw-secret-canary")),
    ] {
        let mut changed = base.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        refused(&changed);
    }
}

#[test]
fn metadata_rejects_duplicate_lists_before_maps_or_sets_erase_them() {
    let (base, _, _) = fixture();
    for pointer in [
        "/profiles",
        "/profiles/0/images",
        "/profiles/0/secretRefs",
        "/profiles/0/toolSchemas",
        "/profiles/0/approvedOutputProfiles",
        "/profiles/0/networkGrants",
        "/profiles/0/auth/requiredScopes",
    ] {
        let mut changed = base.clone();
        let list = changed
            .pointer_mut(pointer)
            .unwrap()
            .as_array_mut()
            .unwrap();
        list.push(list[0].clone());
        refused(&changed);
    }
    let mut changed = base;
    changed["profiles"][0]["networkGrants"][0]["approvedCidrs"] =
        json!(["8.8.8.8/32", "8.8.8.8/32"]);
    refused(&changed);
}

#[test]
fn metadata_rejects_duplicate_image_digest_even_with_different_image_reference() {
    let (mut document, _, _) = fixture();
    let mut duplicate = document["profiles"][0]["images"][0].clone();
    duplicate["imageRef"] = json!("registry.example/private-canary");
    document["profiles"][0]["images"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    refused(&document);
}

#[test]
fn metadata_enforces_byte_and_profile_ceilings_including_valid_boundary() {
    let (mut document, _, _) = fixture();
    let profile = document["profiles"][0].clone();
    document["profiles"] = json!([]);
    refused(&document);
    for index in 0..32 {
        let mut next = profile.clone();
        next["workspaceId"] = json!(format!("workspace-{index}"));
        document["profiles"].as_array_mut().unwrap().push(next);
    }
    parse(&document);
    document["profiles"].as_array_mut().unwrap().push(profile);
    refused(&document);
    let (base, _, _) = fixture();
    let mut input = serde_json::to_vec(&base).unwrap();
    input.resize(262_144, b' ');
    assert!(DeploymentCatalog::parse_json(&input).is_ok());
    input.push(b' ');
    assert!(DeploymentCatalog::parse_json(&input).is_err());
}

#[test]
fn original_json_guards_reject_duplicates_unknown_fields_and_noncanonical_u64() {
    let (base, _, _) = fixture();
    let input = serde_json::to_string(&base).unwrap();
    for changed in [
        input.replacen("{", "{\"version\":null,", 1),
        input.replacen("{", "{\"vers\\u0069on\":null,", 1),
        input.replacen("{", "{\"schema_version\":1,", 1),
        input.replacen("{", "{\"unknown\":true,", 1),
        input.replace("\"100\"", "100"),
        input.replace("\"100\"", "\"0100\""),
        input.replace("\"100\"", "\"+100\""),
        input.replace("\"100\"", "\"1e2\""),
        input.replace("\"100\"", "null"),
    ] {
        assert!(DeploymentCatalog::parse_json(changed.as_bytes()).is_err());
    }
    for field in ["generation", "configuration", "manifest", "rawSecret"] {
        let mut changed = base.clone();
        changed["profiles"][0][field] = json!("private-canary");
        refused(&changed);
    }
}

#[test]
fn compiler_refuses_incomplete_metadata_with_static_redacted_diagnostic() {
    let (mut document, revision, runtime) = fixture();
    document["profiles"][0]["resourceUrl"] = json!("https://private-canary.example/mcp");
    let error = parse(&document)
        .compile(&target(&runtime), INSTALLATION, HOST_POLICY, &revision)
        .expect_err("compiler must validate resource against immutable ingress");
    assert!(!format!("{error:?} {error}").contains("private-canary"));
    document["profiles"][0]["secretRefs"] = json!(["private-secret-canary"]);
    let error = DeploymentCatalog::parse_json(&serde_json::to_vec(&document).unwrap()).unwrap_err();
    assert!(!format!("{error:?} {error}").contains("private-secret-canary"));
}
