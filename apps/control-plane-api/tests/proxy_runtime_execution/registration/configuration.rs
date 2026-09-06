//! Test-owned explicit preparation enrollment; the signed image stays untouched.
use crate::{fixture::*, pki};
use apex_control_plane_api::proto;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const WORKLOAD_TOKEN: &str = "task4a-joint-workload-token-123";

pub fn write(f: &Fixture) {
    let base = f.root.join("config");
    let mut authority: Value =
        serde_json::from_slice(&std::fs::read(base.join("authority-profiles.json")).unwrap())
            .unwrap();
    authority["schema_version"] = json!(2);
    authority["version"] = json!("managed-preparation-v2");
    for p in authority["profiles"].as_array_mut().unwrap() {
        p["mode"] = json!("managed_preparation");
        p["version"] = json!("v2");
    }
    json(&base, "authority-profiles.json", &authority);
    let mut catalog: Value =
        serde_json::from_slice(&std::fs::read(base.join("launch-catalog.json")).unwrap()).unwrap();
    for p in catalog["profiles"].as_array_mut().unwrap() {
        p["authority_profile_version"] = json!("v2");
    }
    json(&base, "launch-catalog.json", &catalog);
    // Independent fixture-owner image observation becomes protected expected
    // metadata before the agent starts; not an RPC-selected image-ID fallback.
    let result = std::process::Command::new("/apex-engine-tools/docker")
        .args([
            "--host",
            "unix:///run/apex-docker.sock",
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            IMAGE,
        ])
        .output()
        .unwrap();
    assert!(result.status.success());
    let image_id = String::from_utf8(result.stdout).unwrap().trim().to_owned();
    assert!(
        image_id
            .strip_prefix("sha256:")
            .is_some_and(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
    );
    let p = &f.proxies[0];
    let managed = json!({"schema_version":1,"version":"managed-v2","valid_from_unix_us":"1","expires_at_unix_us":"9223372036854775807",
        "profiles":[{"installation_id":INSTALL,"workspace_id":p.scope.workspace_id,"namespace_id":p.scope.namespace_id,"proxy_id":p.id.to_string(),"revision_id":p.revision.revision_id.to_string(),
        "authority_profile_ref":"live","authority_profile_version":"v2","evidence_agent_id":"joint-managed-proxy",
        "credentials":[{"certificate_sha256":pki::hex(&f.pki.pin(pki::OTHER)),"token_sha256":format!("{:x}",Sha256::digest(WORKLOAD_TOKEN.as_bytes()))}],
        "launch":{"config_hash":p.revision.config_hash,"host_policy_version":"joint-host-1","deployment_bindings_version":"joint-bindings-1","image_ref":IMAGE,"image_id":image_id,
        "materials":(1..=13).rev().map(|role|json!({"role":proto::RuntimeMaterialRole::try_from(role).unwrap().as_str_name(),"reference":format!("secret://deployment/m{role}"),"version":"v1"})).collect::<Vec<_>>()}}]});
    json(&f.root.join("control"), "managed.json", &managed);
    for (role, name) in [
        (2, "ca.pem"),
        (3, "ingest-http-client.pem"),
        (4, "ingest-http-client.key"),
    ] {
        crate::fixture::write(
            &f.root.join("material"),
            &format!("m{role}"),
            &f.pki.read("trusted-host", name),
        );
    }
    crate::fixture::write(&f.root.join("material"), "m5", WORKLOAD_TOKEN.as_bytes());
}
