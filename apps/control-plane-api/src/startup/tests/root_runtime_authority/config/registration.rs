//! Root route fixture only: empty managed enrollment cannot register a launch.
use super::*;
use serde_json::{Value, json};

pub(super) fn write(directory: &OwnedDir, operation: &Fixture) {
    let c: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/fixtures/mcp-proxy/runtime-revision.json"
    )))
    .unwrap();
    let t = &operation.target;
    let document = json!({"schemaVersion":1,"version":"root-deployment-1","validFromUnixUs":"1","expiresAtUnixUs":"9223372036854775807",
        "profiles":[{"installationId":INSTALLATION,"workspaceId":t.workspace_id,"namespaceId":t.namespace_id,"proxyId":t.proxy_id,"revisionId":t.revision_id,
        "hostPolicyVersion":"live-host-policy-1","resourceUrl":c["resourceUrl"],"images":[{"digest":c["spec"]["runtimeProfile"]["imageDigest"],"imageRef":c["imageRef"]}],
        "secretRefs":c["secretRefs"],"toolSchemas":c["toolSchemas"],"approvedOutputProfiles":["portfolio-read-v1"],"networkGrants":c["networkGrants"],"auth":c["auth"],"telemetry":c["telemetry"],"pidLimit":c["pidLimit"]}]});
    directory.write("deployment.json", &serde_json::to_vec(&document).unwrap());
}
