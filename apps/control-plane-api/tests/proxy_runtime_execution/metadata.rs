use super::fixture::*;
use apex_control_plane_api::proto;
use serde_json::json;

pub fn write(f: &Fixture) {
    let scopes = f
        .proxies
        .iter()
        .map(|p| json!({"workspaceId":p.scope.workspace_id,"namespaceId":p.scope.namespace_id}))
        .collect::<Vec<_>>();
    let grants=f.proxies.iter().map(|p|json!({"installationId":INSTALL,"workspaceId":p.scope.workspace_id,"namespaceId":p.scope.namespace_id})).collect::<Vec<_>>();
    let peer = json!({"schemaVersion":1,"version":"joint-policy-1","validFromUnixUs":"1","expiresAtUnixUs":"9223372036854775807",
        "peers":[{"certificateSha256":super::pki::hex(&f.pki.pin(super::pki::AGENT)),"identityId":"joint-agent","role":"agent","revoked":false,"grants":grants},
        {"certificateSha256":super::pki::hex(&f.pki.pin(super::pki::CONTROLLER)),"identityId":"joint-controller","role":"controller","revoked":false,"grants":grants}]});
    let enrollment = json!({"schemaVersion":1,"version":"joint-enrollment-1","peerPolicyVersion":"joint-policy-1",
        "validFromUnixUs":"1","expiresAtUnixUs":"9223372036854775807","controllers":[{"identityId":"joint-controller","workerId":"controller-a"}],
        "installations":[{"installationId":INSTALL,"agentIdentityId":"joint-agent","revoked":false,"hostPolicyVersion":"joint-host-1","scopes":scopes}]});
    let control = f.root.join("control");
    let agent = f.root.join("config");
    for (name, source) in [
        ("ca.pem", "ca.pem"),
        ("server.pem", "control-plane-server.pem"),
        ("server.key", "control-plane-server.key"),
        ("controller.pem", "control-operator-client.pem"),
        ("controller.key", "control-operator-client.key"),
        ("gateway-token", "mcp-gateway-token"),
    ] {
        super::fixture::write(&control, name, &f.pki.read("trusted-host", source));
    }
    for (name, source) in [
        ("server-ca.pem", "ca.pem"),
        ("server-cert.pem", "control-plane-server.pem"),
        ("server-key.pem", "control-plane-server.key"),
        ("authority-ca.pem", "ca.pem"),
        ("authority-client-cert.pem", "agent-workload-client.pem"),
        ("authority-client-key.pem", "agent-workload-client.key"),
    ] {
        super::fixture::write(&agent, name, &f.pki.read("trusted-host", source));
    }
    json(&control, "peer.json", &peer);
    json(&control, "enrollment.json", &enrollment);
    json(&agent, "peer-policy.json", &peer);
    json(
        &control,
        "execution.json",
        &json!({"schema_version":1,"installation_id":INSTALL,"worker_id":"controller-a",
        "endpoint":format!("https://{}",f.agent),"server_name":"control-plane-api","ca_file":"ca.pem","client_cert_file":"controller.pem","client_key_file":"controller.key",
        "scopes":f.proxies.iter().map(|p|json!({"workspace_id":p.scope.workspace_id,"namespace_id":p.scope.namespace_id})).collect::<Vec<_>>()}),
    );
    json(
        &agent,
        "agent.json",
        &json!({"schema_version":1,"listen":f.agent.to_string(),"installation_id":INSTALL,"agent_identity_id":"joint-agent",
        "enrollment_version":"joint-enrollment-1","host_policy_version":"joint-host-1","authority_endpoint":format!("https://{}",f.cp),"authority_tls_server_name":"control-plane-api",
        "execution":{"journal_root":f.root.join("journal"),"staging_root":f.root.join("staging"),"material_root":f.root.join("material"),
        "docker_executable":"/apex-engine-tools/docker","docker_socket":"/run/apex-docker.sock","docker_config_root":f.root.join("docker"),
        "cosign_executable":"/apex-signature-tools/cosign","cosign_cache_root":f.root.join("cosign")}}),
    );
    let mut golden: proto::RuntimeConfiguration = serde_json::from_str(include_str!(
        "../../../../contracts/fixtures/mcp-proxy/runtime-revision.json"
    ))
    .unwrap();
    golden.tool_schemas[0].upstream_id = "portfolio".into();
    let profiles=f.proxies.iter().map(|p|json!({"installationId":INSTALL,"workspaceId":p.scope.workspace_id,"namespaceId":p.scope.namespace_id,
        "proxyId":p.id.to_string(),"revisionId":p.revision.revision_id.to_string(),"hostPolicyVersion":"joint-host-1","resourceUrl":"https://gateway.example.test/mcp",
        "images":[{"digest":p.revision.spec.runtime_profile.image_digest,"imageRef":IMAGE}],"secretRefs":["secret://SNAPSHOT_CANARY/upstream"],
        "toolSchemas":golden.tool_schemas,"approvedOutputProfiles":["portfolio-read-v1"],
        "networkGrants":[{"grantId":"portfolio-public","host":"portfolio.example.test","port":443,"approvedCidrs":["8.8.8.8/32"]}],
        "auth":{"issuer":"https://identity.example.test/","audience":"https://gateway.example.test/mcp","jwksUri":"https://identity.example.test/jwks","requiredScopes":["mcp:invoke"],"workloadIdentityRef":"identity://runtime/agent"},
        "telemetry":golden.telemetry,"pidLimit":64})).collect::<Vec<_>>();
    json(
        &control,
        "deployment.json",
        &json!({"schemaVersion":1,"version":"joint-bindings-1","validFromUnixUs":"1","expiresAtUnixUs":"9223372036854775807","profiles":profiles}),
    );
    let launch=f.proxies.iter().map(|p|json!({"installation_id":INSTALL,"workspace_id":p.scope.workspace_id,"namespace_id":p.scope.namespace_id,
        "proxy_id":p.id.to_string(),"revision_id":p.revision.revision_id.to_string(),"host_policy_version":"joint-host-1","deployment_bindings_version":"joint-bindings-1",
        "config_hash":p.revision.config_hash,"authority_profile_ref":"live","authority_profile_version":"v1","image_catalog_id":"gateway",
        "materials":(1..=13).rev().map(|n|json!({"role":proto::RuntimeMaterialRole::try_from(n).unwrap().as_str_name(),"reference":format!("secret://deployment/m{n}"),"version":"v1","source_name":format!("m{n}")})).collect::<Vec<_>>()})).collect::<Vec<_>>();
    json(
        &agent,
        "launch-catalog.json",
        &json!({"schema_version":1,"version":"joint-launch-1","valid_from_unix_us":1,"expires_at_unix_us":i64::MAX,"profiles":launch}),
    );
    json(
        &agent,
        "image-catalog.json",
        &json!({"schema_version":1,"images":[{"id":"gateway","image_ref":IMAGE,
        "signing":{"certificate_oidc_issuer":"https://accounts.google.com","certificate_identity":"keyless@projectsigstore.iam.gserviceaccount.com"}}]}),
    );
    let authority=f.proxies.iter().map(|p|json!({"installation_id":INSTALL,"workspace_id":p.scope.workspace_id,"namespace_id":p.scope.namespace_id,"proxy_id":p.id.to_string(),
        "host_policy_version":"joint-host-1","reference":"live","version":"v1","governance":{"endpoint":"https://governance.example","tls_server_name":"governance.example"},
        "evidence":{"endpoint":"https://evidence.example","tls_server_name":"evidence.example"}})).collect::<Vec<_>>();
    json(
        &agent,
        "authority-profiles.json",
        &json!({"schema_version":1,"version":"v1","valid_from_unix_us":1,"expires_at_unix_us":i64::MAX,"profiles":authority}),
    );
    let tools=f.proxies.iter().map(|p|json!({"installation_id":INSTALL,"workspace_id":p.scope.workspace_id,"namespace_id":p.scope.namespace_id,"proxy_id":p.id.to_string(),
        "revision_id":p.revision.revision_id.to_string(),"host_policy_version":"joint-host-1","deployment_bindings_version":"joint-bindings-1","config_hash":p.revision.config_hash,
        "entries":[{"reference":"secret://SNAPSHOT_CANARY/upstream","version":"v1","source_name":"tool0"}]})).collect::<Vec<_>>();
    json(
        &agent,
        "tool-bindings.json",
        &json!({"schema_version":1,"version":"v1","valid_from_unix_us":1,"expires_at_unix_us":i64::MAX,"profiles":tools}),
    );
    for n in 1..=13 {
        super::fixture::write(
            &f.root.join("material"),
            &format!("m{n}"),
            if n == 1 {
                b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            } else {
                b"task3b-secret-canary"
            },
        );
    }
    super::fixture::write(&f.root.join("material"), "tool0", b"task3b-tool-canary");
}
