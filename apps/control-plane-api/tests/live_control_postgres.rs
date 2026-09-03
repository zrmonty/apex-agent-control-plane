//! Live multi-replica tests against two `control-plane-api` containers
//! sharing one Postgres outbox.
//!
//! Enabled only when `APEX_CONTROL_LIVE_POSTGRES=1`, so offline unit CI stays
//! green. Start the stack with
//! `deploy/compose/compose.gateway-ref.yaml -f compose.control-pg.yaml`.
//!
//! These exist because `--features postgres` used to change nothing about the
//! running binary: `startup::service::storage::open_outbox` unconditionally built a
//! `FileOutbox`, and the feature only forwarded the dependency to
//! `apex-durability`. Nothing in this repository could tell the difference,
//! because every other test either drives the crate in-process (choosing the
//! backend itself) or drives the file-backed container.
//!
//! One replica would only prove a connection string was read. Two is the
//! claim that matters for what comes next -- cross-replica rate limiting --
//! and it is the claim `event-ingest`'s own `PostgresOutbox` fixes were about:
//! advisory-locked schema DDL so replicas starting together do not race the
//! `CREATE TABLE IF NOT EXISTS`, `ON CONFLICT DO NOTHING` so the loser of a
//! concurrent insert gets the row's real answer instead of INTERNAL_FAILURE,
//! and `FOR UPDATE SKIP LOCKED` claim leases so two fanout workers take
//! disjoint batches. This asserts those hold when *this* crate is the one
//! using them.

use std::path::{Path, PathBuf};
use std::time::Duration;

use apex_control_plane_api::proto;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

fn live_enabled() -> bool {
    std::env::var("APEX_CONTROL_LIVE_POSTGRES").ok().as_deref() == Some("1")
}

/// The two replicas. Distinct published ports, one shared database.
fn endpoints() -> (String, String) {
    (
        std::env::var("APEX_CONTROL_LIVE_PG_ENDPOINT_A")
            .unwrap_or_else(|_| "https://localhost:18447".to_owned()),
        std::env::var("APEX_CONTROL_LIVE_PG_ENDPOINT_B")
            .unwrap_or_else(|_| "https://localhost:18448".to_owned()),
    )
}

fn secrets_dir() -> PathBuf {
    if let Ok(path) = std::env::var("APEX_CONTROL_LIVE_SECRETS") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/live-mtls/secrets-host")
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

/// The operator credential table is `token|scopes`; split from the right, the
/// same way `parse_operator_token_table` does.
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

fn agent_token(root: &Path) -> String {
    let raw = String::from_utf8(require_secret(root, "control-agent-tokens"))
        .expect("agent token table must be UTF-8");
    raw.split(';')
        .map(str::trim)
        .find(|entry| !entry.is_empty())
        .and_then(|entry| entry.split('|').next())
        .expect("agent token table must have at least one entry")
        .to_owned()
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

fn agent_tls_config() -> ClientTlsConfig {
    let root = secrets_dir();
    ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(require_secret(&root, "ca.pem")))
        .domain_name("localhost")
        .identity(Identity::from_pem(
            require_secret(&root, "agent-workload-client.pem"),
            require_secret(&root, "agent-workload-client.key"),
        ))
}

async fn connect(url: &str) -> tonic::transport::Channel {
    Endpoint::from_shared(url.to_owned())
        .expect("endpoint must parse")
        .tls_config(tls_config())
        .expect("client TLS must configure")
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .connect()
        .await
        .unwrap_or_else(|error| panic!("{url} must be reachable over mTLS: {error}"))
}

async fn connect_agent(url: &str) -> tonic::transport::Channel {
    Endpoint::from_shared(url.to_owned())
        .expect("endpoint must parse")
        .tls_config(agent_tls_config())
        .expect("agent TLS must configure")
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .connect()
        .await
        .unwrap_or_else(|error| panic!("{url} must be reachable over mTLS: {error}"))
}

fn stop_command(command_id: Option<String>) -> proto::ControlCommandRequest {
    proto::ControlCommandRequest {
        command_id,
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        agent_id: "live-pg-agent".to_owned(),
        run_id: "live-pg-run".to_owned(),
        parent_run_id: None,
        trace_id: "live-pg-trace".to_owned(),
        action: proto::ControlAction::Stop as i32,
        reason_code: Some("operator.request".to_owned()),
        parameters: Some(prost_types::Struct::default()),
    }
}

async fn submit(
    channel: tonic::transport::Channel,
    token: &str,
    command_id: Option<String>,
) -> Result<proto::ControlCommandResponse, tonic::Status> {
    let mut client = proto::control_gateway_client::ControlGatewayClient::new(channel);
    let mut request = tonic::Request::new(stop_command(command_id));
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("valid metadata"),
    );
    client.submit_command(request).await.map(|r| r.into_inner())
}

async fn poll(
    channel: tonic::transport::Channel,
    token: &str,
) -> Result<proto::PollCommandsResponse, tonic::Status> {
    let mut client = proto::control_gateway_client::ControlGatewayClient::new(channel);
    let mut request = tonic::Request::new(proto::PollCommandsRequest { max_commands: 64 });
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("valid metadata"),
    );
    client.poll_commands(request).await.map(|r| r.into_inner())
}

/// A caller-supplied `command_id` must be a canonical lowercase UUIDv7 whose
/// embedded millisecond clock is inside the gateway's acceptance window
/// (`envelope.rs`), which `now_v7` satisfies by construction.
fn fresh_command_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// Sixteen concurrent submissions of one `command_id`, split evenly across two
/// replicas that share a Postgres outbox. Exactly one may be a first
/// acceptance; the rest must be recognised as duplicates rather than failing.
///
/// The failure this catches is specific: without `ON CONFLICT DO NOTHING`,
/// `SELECT ... FOR UPDATE` locks nothing when the row is absent, so every
/// replica reads "absent", every one reaches the insert, and each loser gets a
/// unique-violation surfaced as INTERNAL_FAILURE -- an operator's `stop`
/// failing with a server error because someone else sent the same one.
#[tokio::test]
async fn two_replicas_accept_one_command_id_exactly_once() {
    if !live_enabled() {
        eprintln!("skip live control Postgres: set APEX_CONTROL_LIVE_POSTGRES=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();
    let (url_a, url_b) = endpoints();
    let token = operator_token(&secrets_dir());
    let channel_a = connect(&url_a).await;
    let channel_b = connect(&url_b).await;
    let command_id = fresh_command_id();

    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..16 {
        let channel = if index % 2 == 0 {
            channel_a.clone()
        } else {
            channel_b.clone()
        };
        let token = token.clone();
        let command_id = command_id.clone();
        tasks.spawn(async move { submit(channel, &token, Some(command_id)).await });
    }

    let mut accepted = 0;
    let mut duplicates = 0;
    while let Some(joined) = tasks.join_next().await {
        let response = joined
            .expect("submission task must not panic")
            .unwrap_or_else(|status| {
                panic!(
                    "a concurrent duplicate submission failed instead of being recognised: {status}"
                )
            });
        assert_eq!(
            response.command_id, command_id,
            "the gateway must echo the caller's command_id"
        );
        if response.duplicate {
            duplicates += 1;
        } else {
            accepted += 1;
        }
    }
    assert_eq!(
        accepted, 1,
        "exactly one of 16 concurrent submissions of one command_id may be a first acceptance"
    );
    assert_eq!(duplicates, 15);
}

/// The command delivery half must be shared just like the audit outbox half:
/// accept on replica A, poll on replica B, and observe the command without
/// relying on sticky routing or a process-local journal.
#[tokio::test]
async fn a_command_accepted_on_one_replica_is_pollable_from_the_other() {
    if !live_enabled() {
        eprintln!("skip live control Postgres: set APEX_CONTROL_LIVE_POSTGRES=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();
    let (url_a, url_b) = endpoints();
    let root = secrets_dir();
    let operator = operator_token(&root);
    let agent = agent_token(&root);
    let command_id = fresh_command_id();
    let mut command = stop_command(Some(command_id.clone()));
    command.agent_id = "reference-agent".to_owned();

    let mut operator_client =
        proto::control_gateway_client::ControlGatewayClient::new(connect(&url_a).await);
    let mut request = tonic::Request::new(command);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {operator}")
            .parse()
            .expect("valid metadata"),
    );
    operator_client
        .submit_command(request)
        .await
        .expect("replica A must accept the command");

    let response = poll(connect_agent(&url_b).await, &agent)
        .await
        .expect("replica B must serve the shared inbox");
    assert!(
        response
            .commands
            .iter()
            .any(|command| command.command_id == command_id),
        "replica B did not return the command accepted by replica A"
    );
    assert_eq!(response.agent_id, "reference-agent");
}

/// A command accepted by replica A must be visible as a duplicate to replica
/// B. On the file outbox each replica has its own file and both would report a
/// first acceptance, so this is the assertion that distinguishes a genuinely
/// shared authoritative outbox from two independent ones -- i.e. it fails if
/// `--features postgres` silently fell back to `FileOutbox` again.
#[tokio::test]
async fn a_command_accepted_by_one_replica_is_a_duplicate_at_the_other() {
    if !live_enabled() {
        eprintln!("skip live control Postgres: set APEX_CONTROL_LIVE_POSTGRES=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();
    let (url_a, url_b) = endpoints();
    let token = operator_token(&secrets_dir());
    let command_id = fresh_command_id();

    let first = submit(connect(&url_a).await, &token, Some(command_id.clone()))
        .await
        .expect("the first submission must be accepted");
    assert!(
        !first.duplicate,
        "a freshly minted command_id must not be reported as a duplicate"
    );

    let second = submit(connect(&url_b).await, &token, Some(command_id.clone()))
        .await
        .expect("the second replica must recognise the command rather than fail");
    assert!(
        second.duplicate,
        "replica B must see replica A's command; a per-replica file outbox would report a first acceptance here"
    );
    assert_eq!(second.command_id, command_id);
}

/// The same `command_id` with *different* fields must still be an idempotency
/// conflict across replicas, not a silent overwrite of an operator's recorded
/// intent. Submitted to the other replica than the original on purpose.
#[tokio::test]
async fn a_reused_command_id_with_different_fields_conflicts_across_replicas() {
    if !live_enabled() {
        eprintln!("skip live control Postgres: set APEX_CONTROL_LIVE_POSTGRES=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();
    let (url_a, url_b) = endpoints();
    let token = operator_token(&secrets_dir());
    let command_id = fresh_command_id();

    submit(connect(&url_a).await, &token, Some(command_id.clone()))
        .await
        .expect("the first submission must be accepted");

    let mut request = stop_command(Some(command_id));
    // A different action under the same idempotency key: `pause`, not `stop`.
    request.action = proto::ControlAction::Pause as i32;
    let mut client =
        proto::control_gateway_client::ControlGatewayClient::new(connect(&url_b).await);
    let mut tonic_request = tonic::Request::new(request);
    tonic_request.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("valid metadata"),
    );
    let status = client
        .submit_command(tonic_request)
        .await
        .expect_err("a reused command_id with different fields must be refused");
    // `InvalidArgument`, per `errors.rs`'s existing mapping of
    // `CommandErrorCode::IdempotencyConflict`. Asserted against the mapping
    // rather than a guessed gRPC code so this test fails if the taxonomy
    // changes, instead of quietly passing on any error at all.
    assert_eq!(
        status.code(),
        tonic::Code::InvalidArgument,
        "expected an idempotency conflict, got: {status}"
    );
}
