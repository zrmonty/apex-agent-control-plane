use serde_json::{Value, json};

use crate::proto::{CheckRuntimeAuthorityRequest, RuntimeAuthorityAction, RuntimeTarget};

pub(super) const INSTALLATION: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01";
pub(super) const PROXY: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e02";
pub(super) const REVISION: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e03";
pub(super) const OPERATION: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e04";
pub(super) const COMMAND: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e05";

// Deliberately synthetic, component-only metadata. No real pins or credentials.
pub(super) fn enrollment() -> Value {
    json!({
        "schemaVersion": 1, "version": "enrollment-1", "peerPolicyVersion": "policy-1",
        "validFromUnixUs": "100", "expiresAtUnixUs": "1000",
        "controllers": [{"identityId": "controller-a", "workerId": "worker-a"}],
        "installations": [{
            "installationId": INSTALLATION, "agentIdentityId": "agent-a", "revoked": false,
            "hostPolicyVersion": "host-policy-1",
            "scopes": [{"workspaceId": "work", "namespaceId": "ns"}]
        }]
    })
}

pub(super) fn peer_policy() -> Value {
    let grant = json!({"installationId": INSTALLATION, "workspaceId": "work", "namespaceId": "ns"});
    json!({
        "schemaVersion": 1, "version": "policy-1",
        "validFromUnixUs": "100", "expiresAtUnixUs": "1000",
        "peers": [
            {"certificateSha256": "11".repeat(32), "identityId": "agent-a", "role": "agent",
             "revoked": false, "grants": [grant.clone()]},
            {"certificateSha256": "22".repeat(32), "identityId": "controller-a", "role": "controller",
             "revoked": false, "grants": [grant]}
        ]
    })
}

pub(super) fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("component fixture serialization")
}

pub(super) fn request() -> tonic::Request<CheckRuntimeAuthorityRequest> {
    tonic::Request::new(CheckRuntimeAuthorityRequest {
        schema_version: 1,
        target: Some(RuntimeTarget {
            workspace_id: "work".into(),
            namespace_id: "ns".into(),
            proxy_id: PROXY.into(),
            revision_id: REVISION.into(),
            generation: 7,
            fencing_token: 11,
        }),
        operation_id: OPERATION.into(),
        command_id: COMMAND.into(),
        action: RuntimeAuthorityAction::CheckCurrentOperation as i32,
        installation_id: INSTALLATION.into(),
        observed_controller_certificate_sha256: vec![0x22; 32],
    })
}
