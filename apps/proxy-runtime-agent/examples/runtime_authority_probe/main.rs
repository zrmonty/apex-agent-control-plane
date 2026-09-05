//! Test-only cross-process authority probe. No engine, provisioning or admission.
//! Requires an explicit test opt-in and existing disposable PKI.
use apex_proxy_runtime_agent::{
    authority::{AuthorityClientConfig, RuntimeAuthorityClient},
    proto::{CheckRuntimeAuthorityRequest, RuntimeAuthoritySnapshot},
};
use serde::Deserialize;
use std::{io::Read, path::PathBuf, time::Duration};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};

#[allow(dead_code)]
#[path = "../../tests/runtime_peer_pair/pki.rs"]
mod pki;
mod server;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    authority_endpoint: String,
    peer_policy: serde_json::Value,
    request: CheckRuntimeAuthorityRequest,
    config_hash: String,
    caller: String,
}

fn main() {
    if run().is_err() {
        // Never print the parser, filesystem, transport or TLS error chain.
        eprintln!("RUNTIME_AUTHORITY_PROBE_FAILED");
        std::process::exit(1);
    }
}

fn run() -> Result<(), ()> {
    if std::env::var("APEX_RUNTIME_AUTHORITY_PROBE").as_deref() != Ok("1") {
        return Err(());
    }
    let mut args = std::env::args_os().skip(1);
    let path = PathBuf::from(args.next().ok_or(())?);
    if args.next().is_some() {
        return Err(());
    }
    let file = std::fs::File::open(path).map_err(|_| ())?;
    let mut bytes = Vec::new();
    file.take(65_537).read_to_end(&mut bytes).map_err(|_| ())?;
    if bytes.len() > 65_536 {
        return Err(());
    }
    let input: Input = serde_json::from_slice(&bytes).map_err(|_| ())?;
    let endpoint = url::Url::parse(&input.authority_endpoint).map_err(|_| ())?;
    if endpoint.scheme() != "https" || endpoint.host_str() != Some("127.0.0.1") {
        return Err(());
    }
    let runtime = tokio::runtime::Runtime::new().map_err(|_| ())?;
    let result = runtime
        .block_on(async { tokio::time::timeout(Duration::from_secs(12), probe(input)).await })
        .map_err(|_| ())??;
    let output = serde_json::to_vec(&result).map_err(|_| ())?;
    if output.len() > 8192 {
        return Err(());
    }
    use std::io::Write;
    std::io::stdout().write_all(&output).map_err(|_| ())
}

async fn probe(input: Input) -> Result<serde_json::Value, ()> {
    let pki = pki::Pki::require();
    let client = RuntimeAuthorityClient::connect(AuthorityClientConfig {
        endpoint: input.authority_endpoint,
        tls_server_name: "control-plane-api".into(),
        ca_pem: pki.read("trusted-host", "ca.pem"),
        client_certificate_pem: pki.read("trusted-host", "agent-workload-client.pem"),
        client_key_pem: pki.read("trusted-host", "agent-workload-client.key"),
        installation_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01".into(),
        agent_identity_id: "live-agent".into(),
        enrollment_version: "live-enrollment-1".into(),
        host_policy_version: "live-host-policy-1".into(),
    })
    .await
    .map_err(|_| ())?;
    let policy = apex_auth::RuntimePeerPolicy::parse_json(
        &serde_json::to_vec(&input.peer_policy).map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    let server = server::start(client, policy, input.config_hash, &pki)?;
    let result = invoke(&pki, &server.endpoint, &input.caller, input.request).await;
    server.finish().await?;
    match result {
        Ok(snapshot) => Ok(serde_json::json!({"snapshot": snapshot})),
        Err(status) => {
            let code = status.message();
            if code.len() > 128
                || !code.starts_with("RUNTIME_AUTHORITY_CLIENT_")
                || !code
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
            {
                return Err(());
            }
            Ok(serde_json::json!({"error": code}))
        }
    }
}

async fn invoke(
    pki: &pki::Pki,
    endpoint: &str,
    caller: &str,
    body: CheckRuntimeAuthorityRequest,
) -> Result<RuntimeAuthoritySnapshot, tonic::Status> {
    let leaf = match caller {
        "controller" => pki::CONTROLLER,
        "agent" => pki::AGENT,
        _ => return Err(tonic::Status::invalid_argument("INVALID_TEST_CALLER")),
    };
    let tls = ClientTlsConfig::new()
        .domain_name("control-plane-api")
        .ca_certificate(Certificate::from_pem(pki.read("trusted-host", "ca.pem")))
        .identity(pki.identity("trusted-host", leaf));
    let channel = Endpoint::from_shared(endpoint.to_owned())
        .map_err(|_| tonic::Status::unavailable("TEST_ENDPOINT"))?
        .tls_config(tls)
        .map_err(|_| tonic::Status::unavailable("TEST_TLS"))?
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .connect()
        .await
        .map_err(|_| tonic::Status::unavailable("TEST_CONNECT"))?;
    let mut client = apex_proxy_runtime_agent::proto::runtime_authority_service_client::RuntimeAuthorityServiceClient::new(channel)
        .max_decoding_message_size(4096).max_encoding_message_size(4096);
    let mut request = tonic::Request::new(body);
    request.set_timeout(Duration::from_secs(5));
    request
        .metadata_mut()
        .insert("authorization", "PROBE_SECRET_CANARY".parse().unwrap());
    client
        .check_runtime_authority(request)
        .await
        .map(tonic::Response::into_inner)
}
