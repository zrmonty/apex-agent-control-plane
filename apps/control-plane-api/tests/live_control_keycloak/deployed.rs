//! Half two: a deployed `control-plane-api` container configured with
//! `APEX_CONTROL_KEYCLOAK_ISSUER`, accepting a real Keycloak token over mTLS.
//! See the crate root's module doc for the full "why".

use std::time::Duration;

use apex_control_plane_api::proto;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

use super::support::*;

fn oidc_endpoint() -> String {
    std::env::var("APEX_CONTROL_LIVE_OIDC_ENDPOINT")
        .unwrap_or_else(|_| "https://localhost:18449".to_owned())
}

fn tls_config() -> ClientTlsConfig {
    let root = secrets_dir();
    ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(require_secret(&root, "ca.pem")))
        .domain_name("localhost")
        .identity(Identity::from_pem(
            require_secret(&root, "control-operator-client.pem"),
            require_secret(&root, "control-operator-client.key"),
        ))
}

async fn submit(token: &str) -> Result<proto::ControlCommandResponse, tonic::Status> {
    let channel = Endpoint::from_shared(oidc_endpoint())
        .expect("endpoint must parse")
        .tls_config(tls_config())
        .expect("client TLS must configure")
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .connect()
        .await
        .expect("the OIDC control gateway must be reachable over mTLS");
    let mut client = proto::control_gateway_client::ControlGatewayClient::new(channel);
    let mut request = tonic::Request::new(proto::ControlCommandRequest {
        command_id: Some(uuid::Uuid::now_v7().to_string()),
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        agent_id: "live-keycloak-agent".to_owned(),
        run_id: "live-keycloak-run".to_owned(),
        parent_run_id: None,
        trace_id: "live-keycloak-trace".to_owned(),
        action: proto::ControlAction::Stop as i32,
        reason_code: Some("operator.request".to_owned()),
        parameters: Some(prost_types::Struct::default()),
    });
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("valid metadata"),
    );
    client.submit_command(request).await.map(|r| r.into_inner())
}

/// The deployed selection path. This container is configured with
/// `APEX_CONTROL_KEYCLOAK_ISSUER` and *no* static token table -- setting both
/// is a hard startup error -- so if `build_operator_resolver` did not actually
/// choose the Keycloak resolver, the container would authenticate nobody.
#[tokio::test]
async fn the_deployed_container_accepts_a_real_keycloak_operator_credential() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();
    let token = scoped_token();
    let response = submit(&token)
        .await
        .expect("a real Keycloak operator credential must be accepted by the container");
    assert!(!response.duplicate);
    assert!(!response.command_id.is_empty());
}

/// ... and the scope in the credential is enforced by the container, not just
/// derived by it. The lab realm grants `acme/prod` only.
#[tokio::test]
async fn the_deployed_container_enforces_the_scope_the_credential_carries() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();
    let token = scoped_token();
    let channel = Endpoint::from_shared(oidc_endpoint())
        .expect("endpoint must parse")
        .tls_config(tls_config())
        .expect("client TLS must configure")
        .connect_timeout(Duration::from_secs(10))
        .connect()
        .await
        .expect("reachable");
    let mut client = proto::control_gateway_client::ControlGatewayClient::new(channel);
    let mut request = tonic::Request::new(proto::ControlCommandRequest {
        command_id: Some(uuid::Uuid::now_v7().to_string()),
        workspace_id: "someone-elses-workspace".to_owned(),
        namespace_id: "prod".to_owned(),
        agent_id: "live-keycloak-agent".to_owned(),
        run_id: "live-keycloak-run".to_owned(),
        parent_run_id: None,
        trace_id: "live-keycloak-trace".to_owned(),
        action: proto::ControlAction::Stop as i32,
        reason_code: Some("operator.request".to_owned()),
        parameters: Some(prost_types::Struct::default()),
    });
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("valid metadata"),
    );
    let status = client
        .submit_command(request)
        .await
        .expect_err("a scope the credential does not hold must be refused");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

/// The static lab credential must be worthless against a Keycloak-configured
/// container. Otherwise "the production path is wired up" would be compatible
/// with the static table still being live alongside it.
#[tokio::test]
async fn the_deployed_container_refuses_the_static_lab_operator_token() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();
    let table = String::from_utf8(require_secret(&secrets_dir(), "control-operator-tokens"))
        .expect("operator token table must be UTF-8");
    let static_token = table
        .split(';')
        .map(str::trim)
        .find(|entry| !entry.is_empty())
        .expect("at least one entry")
        .rsplit_once('|')
        .expect("token|scopes")
        .0
        .to_owned();
    let status = submit(&static_token)
        .await
        .expect_err("a static table token must not authenticate against Keycloak");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}
