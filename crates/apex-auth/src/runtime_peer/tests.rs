use super::*;
use serde_json::{Value, json};

mod authorization;
mod current;
mod limits;
mod parsing;

const INSTALL_A: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01";
const INSTALL_B: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e02";
const IDENTITY: &str = "runtime-controller-a";

fn grant(installation: &str, workspace: &str, namespace: &str) -> Value {
    json!({"installationId": installation, "workspaceId": workspace, "namespaceId": namespace})
}

fn document() -> Value {
    json!({
        "schemaVersion": 1,
        "version": "policy-1",
        "validFromUnixUs": "1",
        "expiresAtUnixUs": "18446744073709551615",
        "peers": [{
            "certificateSha256": "11".repeat(32),
            "identityId": IDENTITY,
            "role": "controller",
            "revoked": false,
            "grants": [grant(INSTALL_A, "work", "ns")]
        }]
    })
}

fn parse(value: &Value) -> Result<RuntimePeerPolicy, RuntimePeerError> {
    RuntimePeerPolicy::parse_json(&serde_json::to_vec(value).unwrap())
}

fn invalid(value: &Value) {
    assert_eq!(parse(value).unwrap_err(), RuntimePeerError::InvalidPolicy);
}

fn selection<'a>(installation: &'a str, workspace: &'a str, namespace: &'a str) -> Selection<'a> {
    Selection {
        role: RuntimePeerRole::Controller,
        installation_id: installation,
        workspace_id: workspace,
        namespace_id: namespace,
    }
}

fn peer() -> PeerIdentity {
    PeerIdentity {
        certificate_sha256: [0x11; 32],
    }
}
