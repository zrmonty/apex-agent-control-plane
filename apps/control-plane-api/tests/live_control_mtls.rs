//! Live mTLS tests against a running `control-plane-api` container.
//!
//! Enabled only when `APEX_CONTROL_LIVE_MTLS=1` and the live-mTLS PKI exists,
//! so offline unit CI stays green. Mirrors
//! `apps/event-ingest/tests/live_mtls.rs`.
//!
//! These exist because nothing else in this repository can catch a broken TLS
//! gate. Every other test drives the service in-process as a library, where
//! `ServerTlsConfig` is never constructed at all: a build that silently made
//! client certificates optional would pass the entire unit suite.
//!
//! The four cases are deliberately a matrix, not a happy path plus a smoke
//! test. `rejects_a_client_with_no_certificate` and
//! `rejects_a_client_certificate_from_another_ca` only mean something next to
//! `rejects_a_valid_certificate_without_an_operator_token`: that one proves a
//! correctly-certified client *does* reach the application layer and gets a
//! gRPC `Unauthenticated` status back. So when the other two fail at the
//! transport instead, the certificate is demonstrably what stopped them --
//! rather than the server being broken in some way that rejects everything.

use std::error::Error as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use apex_control_plane_api::proto;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

fn live_enabled() -> bool {
    std::env::var("APEX_CONTROL_LIVE_MTLS").ok().as_deref() == Some("1")
}

fn endpoint_url() -> String {
    std::env::var("APEX_CONTROL_LIVE_ENDPOINT")
        .unwrap_or_else(|_| "https://localhost:18446".to_owned())
}

fn secrets_dir() -> PathBuf {
    if let Ok(path) = std::env::var("APEX_CONTROL_LIVE_SECRETS") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/live-mtls/secrets-host")
}

/// Adversarial fixtures from `deploy/compose/e2e/generate_adversarial_pki.py`
/// -- specifically a client leaf signed by a CA the gateway does not trust.
fn adversarial_dir() -> PathBuf {
    if let Ok(path) = std::env::var("APEX_CONTROL_LIVE_ADVERSARIAL_PKI") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/live-mtls/adversarial")
}

fn require_secret(root: &Path, name: &str) -> Vec<u8> {
    let path = root.join(name);
    assert!(
        path.is_file(),
        "missing live-mTLS fixture {name} under {}; run generate_pki.py",
        root.display()
    );
    std::fs::read(&path).expect("fixture must be readable")
}

/// The operator credential table is `token|scopes`. Split from the right, the
/// same way `parse_operator_token_table` does, so a token containing the
/// separator still round-trips whole.
fn operator_token(root: &Path) -> String {
    let raw = String::from_utf8(require_secret(root, "control-operator-tokens"))
        .expect("operator token table must be UTF-8");
    let entry = raw
        .split(';')
        .map(str::trim)
        .find(|entry| !entry.is_empty())
        .expect("operator token table must have at least one entry");
    entry
        .rsplit_once('|')
        .expect("operator token table entry must be token|scopes")
        .0
        .to_owned()
}

fn tls_config(client_identity: Option<Identity>) -> ClientTlsConfig {
    let root = secrets_dir();
    let config = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(require_secret(&root, "ca.pem")))
        // The server leaf carries SAN dns:localhost and IP 127.0.0.1/::1.
        .domain_name("localhost");
    match client_identity {
        Some(identity) => config.identity(identity),
        None => config,
    }
}

fn operator_identity() -> Identity {
    let root = secrets_dir();
    Identity::from_pem(
        require_secret(&root, "control-operator-client.pem"),
        require_secret(&root, "control-operator-client.key"),
    )
}

/// The *ingest* workload's client certificate and bearer token, i.e. the
/// credential set that authenticates against the data path.
fn ingest_workload_credential() -> Option<(Identity, String)> {
    let root = secrets_dir();
    if !root.join("ingest-http-client.pem").is_file() {
        return None;
    }
    let identity = Identity::from_pem(
        require_secret(&root, "ingest-http-client.pem"),
        require_secret(&root, "ingest-http-client.key"),
    );
    let token = match std::fs::read(root.join("ingest-bearer-token")) {
        Ok(bytes) => String::from_utf8(bytes).ok()?.trim().to_owned(),
        Err(_) => "gateway-ref-token".to_owned(),
    };
    Some((identity, token))
}

fn rogue_identity() -> Option<Identity> {
    let root = adversarial_dir();
    if !root.join("wrong-ca-client.pem").is_file() {
        return None;
    }
    Some(Identity::from_pem(
        require_secret(&root, "wrong-ca-client.pem"),
        require_secret(&root, "wrong-ca-client.key"),
    ))
}

fn stop_command() -> proto::ControlCommandRequest {
    proto::ControlCommandRequest {
        // None: the gateway mints a canonical UUIDv7 itself, so this test
        // does not have to reproduce the clock-acceptance window rules in
        // envelope.rs.
        command_id: None,
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        agent_id: "live-mtls-agent".to_owned(),
        run_id: "live-mtls-run".to_owned(),
        parent_run_id: None,
        trace_id: "live-mtls-trace".to_owned(),
        action: proto::ControlAction::Stop as i32,
        reason_code: Some("operator.request".to_owned()),
        parameters: Some(prost_types::Struct::default()),
    }
}

/// Outcome of one end-to-end attempt, so a test can tell "the TLS handshake
/// refused this client" apart from "the application refused this client".
enum Attempt {
    /// Never reached the application: the connection or handshake failed.
    Transport(String),
    /// Reached the application and got a gRPC status back.
    Status(tonic::Status),
    Accepted(proto::ControlCommandResponse),
}

async fn attempt(
    client_identity: Option<Identity>,
    bearer: Option<&str>,
) -> Result<Attempt, Box<dyn std::error::Error>> {
    let channel = Endpoint::from_shared(endpoint_url())?
        .tls_config(tls_config(client_identity))?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(10))
        .connect()
        .await;
    let channel = match channel {
        Ok(channel) => channel,
        Err(error) => return Ok(Attempt::Transport(error.to_string())),
    };
    let mut client = proto::control_gateway_client::ControlGatewayClient::new(channel);
    let mut request = tonic::Request::new(stop_command());
    if let Some(bearer) = bearer {
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {bearer}").parse()?);
    }
    match client.submit_command(request).await {
        Ok(response) => Ok(Attempt::Accepted(response.into_inner())),
        // A handshake that only fails once bytes are actually written shows up
        // here rather than at connect(). tonic reports those as Unknown or
        // Unavailable with a transport source attached, so classify by source
        // rather than by code alone.
        Err(status)
            if status.source().is_some()
                && matches!(
                    status.code(),
                    tonic::Code::Unknown | tonic::Code::Unavailable | tonic::Code::Internal
                ) =>
        {
            Ok(Attempt::Transport(status.to_string()))
        }
        Err(status) => Ok(Attempt::Status(status)),
    }
}

#[tokio::test]
async fn accepts_a_valid_operator_certificate_and_token() {
    if !live_enabled() {
        eprintln!("skip live control mTLS: set APEX_CONTROL_LIVE_MTLS=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();
    let token = operator_token(&secrets_dir());
    match attempt(Some(operator_identity()), Some(&token))
        .await
        .expect("attempt must complete")
    {
        Attempt::Accepted(response) => {
            assert!(
                !response.command_id.is_empty(),
                "an accepted command must carry a command_id"
            );
        }
        Attempt::Status(status) => panic!("valid operator was rejected: {status}"),
        Attempt::Transport(error) => panic!("valid operator failed the handshake: {error}"),
    }
}

#[tokio::test]
async fn rejects_a_valid_certificate_without_an_operator_token() {
    if !live_enabled() {
        eprintln!("skip live control mTLS: set APEX_CONTROL_LIVE_MTLS=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();
    // The control point of the matrix: a trusted certificate gets all the way
    // to the application boundary, which is what makes the two transport
    // rejections below meaningful rather than vacuous.
    match attempt(Some(operator_identity()), None)
        .await
        .expect("attempt must complete")
    {
        Attempt::Status(status) => assert_eq!(status.code(), tonic::Code::Unauthenticated),
        Attempt::Accepted(_) => panic!("a command was accepted with no operator credential"),
        Attempt::Transport(error) => {
            panic!("a trusted certificate must reach the application layer, got: {error}")
        }
    }
}

#[tokio::test]
async fn rejects_a_client_with_no_certificate() {
    if !live_enabled() {
        eprintln!("skip live control mTLS: set APEX_CONTROL_LIVE_MTLS=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();
    // Even carrying a valid operator token: client_auth_optional(false) means
    // the credential never gets a chance to be presented.
    let token = operator_token(&secrets_dir());
    match attempt(None, Some(&token))
        .await
        .expect("attempt must complete")
    {
        // Logged, not just asserted: a CI run that says only "ok" cannot show
        // a reviewer that the refusal came from the handshake.
        Attempt::Transport(error) => {
            eprintln!("no-certificate client refused at transport: {error}")
        }
        Attempt::Status(status) => {
            panic!("a certificate-less client reached the application layer: {status}")
        }
        Attempt::Accepted(_) => panic!("a command was accepted without a client certificate"),
    }
}

/// ADR-0006 requires the control channel to be independently authenticated
/// from the ingest data path: "an ingest workload token is not accepted here
/// and vice versa". The unit tests assert that about the resolver; this
/// asserts it about the two credentials a real deployment actually issues,
/// against the running service.
///
/// In this lab profile both leaves chain to the same CA, so the certificate
/// alone gets through the handshake -- which is what makes this test about
/// the credential boundary rather than the transport one. A production
/// deployment additionally separates the CAs (CONTROL_CLIENT_CA_FILE vs
/// GATEWAY_CLIENT_CA_FILE in deploy/compose/compose.yaml), so there the same
/// attempt would not survive the handshake either.
#[tokio::test]
async fn rejects_an_ingest_workload_credential() {
    if !live_enabled() {
        eprintln!("skip live control mTLS: set APEX_CONTROL_LIVE_MTLS=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();
    let Some((identity, ingest_token)) = ingest_workload_credential() else {
        panic!(
            "missing ingest workload fixtures under {}; run generate_pki.py",
            secrets_dir().display()
        );
    };
    match attempt(Some(identity), Some(&ingest_token))
        .await
        .expect("attempt must complete")
    {
        Attempt::Status(status) => assert_eq!(status.code(), tonic::Code::Unauthenticated),
        Attempt::Transport(error) => {
            eprintln!("ingest workload credential refused at transport: {error}")
        }
        Attempt::Accepted(_) => {
            panic!("an ingest workload credential submitted a control command")
        }
    }
}

#[tokio::test]
async fn rejects_a_client_certificate_from_another_ca() {
    if !live_enabled() {
        eprintln!("skip live control mTLS: set APEX_CONTROL_LIVE_MTLS=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();
    let Some(identity) = rogue_identity() else {
        panic!(
            "missing adversarial PKI under {}; run deploy/compose/e2e/generate_adversarial_pki.py",
            adversarial_dir().display()
        );
    };
    let token = operator_token(&secrets_dir());
    match attempt(Some(identity), Some(&token))
        .await
        .expect("attempt must complete")
    {
        Attempt::Transport(error) => {
            eprintln!("untrusted-CA client refused at transport: {error}")
        }
        Attempt::Status(status) => {
            panic!("a certificate from an untrusted CA reached the application layer: {status}")
        }
        Attempt::Accepted(_) => {
            panic!("a command was accepted with a certificate from an untrusted CA")
        }
    }
}
