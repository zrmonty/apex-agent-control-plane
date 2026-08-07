//! Live cross-replica admission tests: two `control-plane-api` containers, one
//! Postgres outbox, one Valkey.
//!
//! Enabled only when `APEX_CONTROL_LIVE_VALKEY=1`, so offline unit CI stays
//! green. Start the stack with `deploy/compose/compose.gateway-ref.yaml -f
//! compose.control-pg.yaml -f compose.control-valkey.yaml`.
//!
//! The defect these close: the per-operator admission ceiling in `service.rs`
//! was a process-local `HashMap`, so N replicas admitted N times the
//! configured limit. That was academic while a file outbox made multiple
//! replicas unsafe to run; it stopped being academic the moment the Postgres
//! outbox landed and CI started running two of them.
//!
//! In-process coverage already exists (`service.rs`'s
//! `two_replicas_without_a_shared_store_admit_twice_the_ceiling` and its
//! shared-store counterpart), but it shares a store *object* between two
//! services in one process. That is not the claim. The claim is that two
//! separate processes, in separate containers, each holding their own Valkey
//! connection over mTLS with their own ACL user, agree on one ceiling -- and
//! that when that Valkey goes away mid-run each of them falls back to its own
//! local ceiling instead of failing open or hanging.
//!
//! The overlay pins `APEX_CONTROL_ADMISSION_LIMIT=8` over a 60-second window
//! precisely so the assertions can be exact. On the shipped one-second window
//! a burst that straddles a boundary can legitimately admit two windows'
//! worth, and "somewhere between 8 and 16" does not distinguish one shared
//! ceiling from two local ones.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use apex_control_plane_api::proto;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

fn live_enabled() -> bool {
    std::env::var("APEX_CONTROL_LIVE_VALKEY").ok().as_deref() == Some("1")
}

/// The configured ceiling, which the compose overlay sets and this test must
/// agree with. Read from the environment so the two cannot drift silently.
fn admission_limit() -> usize {
    std::env::var("APEX_CONTROL_ADMISSION_LIMIT")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(8)
}

fn endpoints() -> (String, String) {
    (
        std::env::var("APEX_CONTROL_LIVE_PG_ENDPOINT_A")
            .unwrap_or_else(|_| "https://localhost:18447".to_owned()),
        std::env::var("APEX_CONTROL_LIVE_PG_ENDPOINT_B")
            .unwrap_or_else(|_| "https://localhost:18448".to_owned()),
    )
}

/// The Valkey container this test stops and starts. Named, not discovered, so
/// the test can never take down something it did not bring up.
fn valkey_container() -> String {
    std::env::var("APEX_CONTROL_LIVE_VALKEY_CONTAINER")
        .unwrap_or_else(|_| "apex-gateway-ref-ci-control-valkey-1".to_owned())
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

fn operator_token(root: &Path) -> String {
    let raw = String::from_utf8(require_secret(root, "control-operator-tokens"))
        .expect("operator token table must be UTF-8");
    raw.split(';')
        .map(str::trim)
        .find(|entry| !entry.is_empty())
        .expect("operator token table must have at least one entry")
        .rsplit_once('|')
        .expect("operator token table entry must be token|scopes")
        .0
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

async fn connect(url: &str) -> tonic::transport::Channel {
    Endpoint::from_shared(url.to_owned())
        .expect("endpoint must parse")
        .tls_config(tls_config())
        .expect("client TLS must configure")
        .connect_timeout(Duration::from_secs(10))
        // Generous: a request that arrives while the accelerator is being
        // probed should still complete. If it does not, that is the stall this
        // test exists to catch, and a timeout would report it as such.
        .timeout(Duration::from_secs(60))
        .connect()
        .await
        .unwrap_or_else(|error| panic!("{url} must be reachable over mTLS: {error}"))
}

async fn submit(
    channel: tonic::transport::Channel,
    token: &str,
    agent: &str,
) -> Result<proto::ControlCommandResponse, tonic::Status> {
    let mut client = proto::control_gateway_client::ControlGatewayClient::new(channel);
    let mut request = tonic::Request::new(proto::ControlCommandRequest {
        command_id: Some(uuid::Uuid::now_v7().to_string()),
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        agent_id: agent.to_owned(),
        run_id: "live-valkey-run".to_owned(),
        parent_run_id: None,
        trace_id: "live-valkey-trace".to_owned(),
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

struct BurstResult {
    accepted: usize,
    rate_limited: usize,
    other_errors: Vec<tonic::Code>,
    elapsed: Duration,
}

/// Fires `attempts` submissions alternating between the two replicas and
/// tallies what came back.
///
/// Sequential rather than concurrent, deliberately. Concurrency would let
/// several requests read the shared counter before any of them incremented it,
/// and this test is about the *ceiling*, not about the accelerator's atomicity
/// -- which is `INCR`'s problem and already exercised by `event-ingest`. A
/// sequential burst makes the expected number exact.
async fn burst(
    channel_a: &tonic::transport::Channel,
    channel_b: &tonic::transport::Channel,
    token: &str,
    attempts: usize,
) -> BurstResult {
    let started = Instant::now();
    let mut result = BurstResult {
        accepted: 0,
        rate_limited: 0,
        other_errors: Vec::new(),
        elapsed: Duration::ZERO,
    };
    for index in 0..attempts {
        let channel = if index % 2 == 0 {
            channel_a.clone()
        } else {
            channel_b.clone()
        };
        match submit(channel, token, "live-valkey-agent").await {
            Ok(_) => result.accepted += 1,
            Err(status) if status.code() == tonic::Code::ResourceExhausted => {
                result.rate_limited += 1
            }
            Err(status) => result.other_errors.push(status.code()),
        }
    }
    result.elapsed = started.elapsed();
    result
}

fn docker(args: &[&str]) {
    let status = Command::new("docker")
        .args(args)
        .status()
        .unwrap_or_else(|error| panic!("docker {args:?} could not run: {error}"));
    assert!(status.success(), "docker {args:?} failed: {status}");
}

fn docker_output(args: &[&str]) -> String {
    let output = Command::new("docker")
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("docker {args:?} could not run: {error}"));
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Hex-encodes a key component the way `event-ingest`'s `ephemeral::types`
/// does, so the keys probed below are the literal ones the gateway writes.
fn hex(value: &str) -> String {
    value.bytes().map(|byte| format!("{byte:02x}")).collect()
}

/// The control gateway's Valkey ACL user must be able to touch its own
/// admission namespace and nothing else.
///
/// This is the half of the isolation story that the ceiling assertions cannot
/// show. `apex_event_ingest`'s ephemeral key prefix is the fixed literal
/// `apex:ingest`, which this crate deliberately does not fork, so the
/// *namespace component* plus a narrowed ACL key pattern is what keeps the two
/// services' counters apart -- and a pattern that was accidentally widened to
/// `~*` would pass every other assertion in this file while letting either
/// service clear or inflate the other's rate-limit state.
///
/// `render_configs.py` derives the pattern from the same namespace constant
/// the Rust side uses; this proves the derivation actually bites at the
/// server.
#[tokio::test]
async fn the_control_valkey_acl_user_cannot_reach_the_ingest_keyspace() {
    if !live_enabled() {
        eprintln!("skip live control Valkey: set APEX_CONTROL_LIVE_VALKEY=1");
        return;
    }
    let password_path = secrets_dir().join("valkey-control-password");
    assert!(
        password_path.is_file(),
        "missing valkey-control-password under {}; run generate_pki.py",
        secrets_dir().display()
    );
    let password = String::from_utf8(std::fs::read(&password_path).expect("readable"))
        .expect("password must be UTF-8")
        .trim()
        .to_owned();
    let container = valkey_container();

    let probe = |key: &str| {
        let script = format!(
            "valkey-cli --tls --cacert /run/secrets/valkey_client_ca \
             --cert /run/secrets/valkey_server_cert --key /run/secrets/valkey_server_key \
             -h 127.0.0.1 -p 6379 --user apex-control --pass '{password}' \
             --no-auth-warning GET '{key}'"
        );
        docker_output(&["exec", &container, "sh", "-c", &script])
    };

    // The gateway's own namespace: permitted (the value may or may not be set;
    // what matters is that it is not refused).
    let own = probe(&format!(
        "apex:ingest:rl:{}:probe",
        hex("apex.control.admission")
    ));
    assert!(
        !own.contains("NOPERM"),
        "the control gateway's ACL user must be able to reach its own admission namespace: {own}"
    );

    // The ingest workload's keyspace, in the exact shape `event-ingest` writes
    // (namespace = the envelope's workspace_id): refused.
    for ingest_key in [
        format!("apex:ingest:rl:{}:{}", hex("acme"), hex("admission")),
        format!("apex:ingest:rl:{}:{}", hex("unscoped"), hex("admission")),
        format!("apex:ingest:fp:{}:00ff", hex("acme")),
        format!("apex:ingest:deny:{}:00ff", hex("acme")),
    ] {
        let denied = probe(&ingest_key);
        assert!(
            denied.contains("NOPERM"),
            "the control gateway's ACL user must not reach {ingest_key}: {denied}"
        );
    }
}

/// One test, not three, because the three claims are sequential states of one
/// stack: the shared ceiling holds, then the accelerator dies and the local
/// ceilings take over, then it comes back and the shared ceiling holds again.
/// Splitting them would either race (`cargo test` runs tests in parallel) or
/// require each to rebuild the outage, which is the slow part.
#[tokio::test]
async fn the_admission_ceiling_is_shared_across_replicas_and_survives_a_valkey_outage() {
    if !live_enabled() {
        eprintln!("skip live control Valkey: set APEX_CONTROL_LIVE_VALKEY=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();
    let limit = admission_limit();
    let (url_a, url_b) = endpoints();
    let token = operator_token(&secrets_dir());
    let channel_a = connect(&url_a).await;
    let channel_b = connect(&url_b).await;
    let attempts = limit * 8;

    // ---------------------------------------------------------------
    // 1. Valkey up: the ceiling is shared.
    // ---------------------------------------------------------------
    let shared = burst(&channel_a, &channel_b, &token, attempts).await;
    assert!(
        shared.other_errors.is_empty(),
        "unexpected errors during the shared-ceiling burst: {:?}",
        shared.other_errors
    );
    // The load-bearing assertion. Two replicas, one operator, one ceiling.
    // Without the shared store this is `2 * limit`, and that difference is the
    // whole defect: an admission control that quietly scales with the replica
    // count is not the control that was configured.
    assert_eq!(
        shared.accepted, limit,
        "combined admission across both replicas must equal the configured ceiling, not {} x it",
        attempts / limit.max(1)
    );
    assert_eq!(shared.rate_limited, attempts - limit);
    eprintln!(
        "shared ceiling: {}/{} accepted across two replicas in {:?}",
        shared.accepted, attempts, shared.elapsed
    );

    // ---------------------------------------------------------------
    // 2. Valkey stopped mid-run: each replica falls back to its own local
    //    ceiling. Neither fails open (which would admit everything) nor hangs
    //    (which is the 135-second stall `ephemeral/fallback.rs`'s circuit
    //    breaker exists to prevent, and reuse alone does not guarantee).
    // ---------------------------------------------------------------
    docker(&["stop", "--timeout", "5", &valkey_container()]);

    // A fresh operator-scoped counter is not available -- the operator subject
    // is fixed by the credential -- so the local buckets are whatever the
    // first burst left them. Wait out the 60-second window so both replicas
    // start from a clean local bucket and the count below is exact.
    tokio::time::sleep(Duration::from_secs(65)).await;

    let degraded = burst(&channel_a, &channel_b, &token, attempts).await;
    assert!(
        degraded.other_errors.is_empty(),
        "a dead accelerator must degrade, not error: {:?}",
        degraded.other_errors
    );
    assert_eq!(
        degraded.accepted,
        limit * 2,
        "with the accelerator down each replica must enforce its own local ceiling -- not fail open ({attempts}) and not fail shut (0)"
    );
    // Bounded, and by a wide margin: the breaker means one slow probe per
    // cool-down rather than one per request, and `admit` runs the store call
    // on a blocking thread so that probe cannot stall the tonic worker. The
    // measured pre-breaker failure was 135 seconds for a *single* request.
    assert!(
        degraded.elapsed < Duration::from_secs(120),
        "{attempts} requests against a dead accelerator took {:?}; the circuit breaker is not holding",
        degraded.elapsed
    );
    eprintln!(
        "valkey down: {}/{} accepted across two replicas in {:?}",
        degraded.accepted, attempts, degraded.elapsed
    );

    // ---------------------------------------------------------------
    // 3. Valkey back: the breaker closes and the shared ceiling applies again,
    //    with no restart of either replica. `LazyValkeyStore` reconnecting is
    //    what makes that true; without it a stopped accelerator would be
    //    permanent for the process's lifetime.
    // ---------------------------------------------------------------
    docker(&["start", &valkey_container()]);
    // Long enough for the container to accept connections and for the
    // breaker's cool-down (1s doubling to a 30s ceiling) to expire, plus the
    // 60-second local window so the local buckets are not the thing doing the
    // limiting.
    tokio::time::sleep(Duration::from_secs(75)).await;

    let recovered = burst(&channel_a, &channel_b, &token, attempts).await;
    assert!(
        recovered.other_errors.is_empty(),
        "unexpected errors after recovery: {:?}",
        recovered.other_errors
    );
    assert_eq!(
        recovered.accepted, limit,
        "the shared ceiling must reapply once the accelerator returns, without restarting either replica"
    );
    eprintln!(
        "valkey restored: {}/{} accepted across two replicas in {:?}",
        recovered.accepted, attempts, recovered.elapsed
    );
}
