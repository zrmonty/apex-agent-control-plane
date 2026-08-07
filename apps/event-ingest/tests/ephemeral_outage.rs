//! Rate-limiter behaviour when the Valkey accelerator dies mid-run.
//!
//! `FallbackEphemeralStore` prefers Valkey and, on `Unavailable`, falls back to
//! an in-process limiter enforcing the same ceiling. That is the documented
//! "fail closed to the local ceiling" behaviour, and it had only ever been
//! checked by reading the code. Two things need proving against a real server:
//!
//!   * losing Valkey must not fail **open** -- admission must stay bounded;
//!   * losing Valkey must not fail **closed on everything** either. The store
//!     is behind one process-wide mutex, so a Valkey that swallows packets
//!     rather than refusing them could stall every admission behind a socket
//!     timeout. A refusal is cheap; a blackhole is the dangerous case, and
//!     `docker pause` produces exactly that.
//!
//! What this cannot prove, and is not claimed: that the *global* limit is
//! preserved. It is not. With Valkey down each replica enforces the ceiling
//! independently, so an N-replica deployment admits up to N times the intended
//! rate until Valkey returns. That is a deliberate availability-over-strictness
//! trade, not a defect, but it is a real widening of the budget.
//!
//! ```text
//! APEX_VALKEY_OUTAGE=1 \
//! APEX_ADVERSARIAL_GATEWAY=https://localhost:18446 \
//! APEX_ADVERSARIAL_SECRETS=deploy/compose/live-mtls/secrets-host \
//! APEX_VALKEY_CONTAINER=apex-pentest-valkey \
//!   cargo test --test ephemeral_outage --features test-support -- --test-threads=1
//! ```

#![cfg(feature = "test-support")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use apex_event_ingest::{canonical_event_hash, proto};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

const AGENT_ID: &str = "reference-agent";
/// `MAX_ADMISSION_REQUESTS_PER_SECOND` in `auth/service.rs`.
const CEILING: usize = 256;

fn enabled() -> bool {
    std::env::var("APEX_VALKEY_OUTAGE").ok().as_deref() == Some("1")
        && std::env::var("APEX_ADVERSARIAL_GATEWAY").is_ok()
}

fn skip(name: &str) -> bool {
    if !enabled() {
        eprintln!("skip {name}: set APEX_VALKEY_OUTAGE=1 and APEX_ADVERSARIAL_GATEWAY");
        return true;
    }
    false
}

fn valkey_container() -> String {
    std::env::var("APEX_VALKEY_CONTAINER").unwrap_or_else(|_| "apex-pentest-valkey".to_owned())
}

fn secrets_dir() -> PathBuf {
    std::env::var("APEX_ADVERSARIAL_SECRETS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../deploy/compose/live-mtls/secrets-host")
        })
}

fn read(root: &Path, name: &str) -> Vec<u8> {
    std::fs::read(root.join(name)).unwrap_or_else(|e| panic!("missing {name}: {e}"))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .unwrap()
}

fn docker(args: &[&str]) -> bool {
    Command::new("docker")
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

async fn channel() -> Channel {
    let root = secrets_dir();
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(read(&root, "ca.pem")))
        .identity(Identity::from_pem(
            read(&root, "ingest-http-client.pem"),
            read(&root, "ingest-http-client.key"),
        ))
        .domain_name("localhost");
    Channel::from_shared(std::env::var("APEX_ADVERSARIAL_GATEWAY").unwrap())
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .expect("gateway channel")
}

fn bearer() -> String {
    String::from_utf8(read(&secrets_dir(), "ingest-bearer-token"))
        .unwrap()
        .trim()
        .to_owned()
}

async fn send(
    channel: &Channel,
    envelope: proto::EventEnvelope,
) -> Result<proto::IngestResponse, tonic::Status> {
    let mut request = tonic::Request::new(envelope);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {}", bearer()).parse().unwrap());
    proto::event_ingest_client::EventIngestClient::new(channel.clone())
        .ingest(request)
        .await
        .map(|r| r.into_inner())
}

fn base(event_id: &str) -> proto::EventEnvelope {
    let mut data = prost_types::Struct::default();
    data.fields.insert(
        "note".to_owned(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue("valkey-probe".to_owned())),
        },
    );
    proto::EventEnvelope {
        event_id: event_id.to_owned(),
        timestamp: "2026-08-06T12:00:00.000000Z".to_owned(),
        r#type: 1,
        agent_id: AGENT_ID.to_owned(),
        run_id: "run-1".to_owned(),
        parent_run_id: None,
        trace_id: "trace-1".to_owned(),
        scope: Some(proto::Scope {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            agent_group_ids: vec![],
        }),
        actor: Some(proto::Actor {
            r#type: 2,
            id: AGENT_ID.to_owned(),
        }),
        version: Some(proto::Version {
            agent_code: "v1".to_owned(),
            prompt: "p1".to_owned(),
            model: "m1".to_owned(),
        }),
        data: Some(data),
        integrity: Some(proto::Integrity {
            prev_hash: None,
            event_hash: "0".repeat(64),
        }),
        schema_version: 1,
    }
}

fn sign(mut envelope: proto::EventEnvelope) -> proto::EventEnvelope {
    let hash = canonical_event_hash(&envelope).expect("hash");
    envelope.integrity.as_mut().unwrap().event_hash = hash;
    envelope
}

fn event_id(suffix: u32) -> String {
    static NONCE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let nonce = *NONCE.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|e| e.as_secs() % 0x0000_0000_ffff)
            .unwrap_or(0)
    });
    format!(
        "018f5c91-2d88-7c00-8000-{:012x}",
        (nonce << 24) | 0x00dd_0000 | u64::from(suffix)
    )
}

struct Burst {
    admitted: usize,
    limited: usize,
    other: Vec<String>,
    slowest: Duration,
}

/// Fires `count` requests concurrently and classifies the answers.
///
/// `admitted` counts requests that reached the gateway's execution lane, which
/// is what the admission budget is supposed to bound. RESOURCE_EXHAUSTED covers
/// both the rate limiter and the adapter's `try_lock` back-pressure; neither
/// admits an event, so both count as "not admitted".
fn burst(count: u32, tag: u32) -> Burst {
    runtime().block_on(async {
        let channel = channel().await;
        let mut handles = Vec::new();
        for index in 0..count {
            let channel = channel.clone();
            let id = event_id(tag * 1000 + index);
            handles.push(tokio::spawn(async move {
                let started = Instant::now();
                let result = send(&channel, sign(base(&id))).await;
                (result, started.elapsed())
            }));
        }
        let mut burst = Burst {
            admitted: 0,
            limited: 0,
            other: Vec::new(),
            slowest: Duration::ZERO,
        };
        for handle in handles {
            let (result, elapsed) = handle.await.expect("request task");
            burst.slowest = burst.slowest.max(elapsed);
            match result {
                Ok(_) => burst.admitted += 1,
                Err(status) if status.code() == tonic::Code::ResourceExhausted => {
                    burst.limited += 1
                }
                Err(status) => burst.other.push(format!("{:?}", status.code())),
            }
        }
        burst
    })
}

fn valid_event_still_works(tag: u32) -> bool {
    runtime().block_on(async {
        let channel = channel().await;
        // Retry through back-pressure the way a correct client would.
        for _ in 0..80 {
            match send(&channel, sign(base(&event_id(tag)))).await {
                Ok(_) => return true,
                Err(status) if status.code() == tonic::Code::ResourceExhausted => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(status) => {
                    eprintln!("valid event failed: {status:?}");
                    return false;
                }
            }
        }
        false
    })
}

/// Stopping Valkey must keep admission bounded and keep the gateway serving.
#[test]
fn valkey_outage_keeps_admission_bounded_and_the_gateway_serving() {
    if skip("valkey_outage_keeps_admission_bounded_and_the_gateway_serving") {
        return;
    }
    let container = valkey_container();

    let healthy = burst(400, 1);
    eprintln!(
        "valkey up:   admitted={} limited={} other={:?} slowest={:?}",
        healthy.admitted, healthy.limited, healthy.other, healthy.slowest
    );
    assert!(
        healthy.other.is_empty(),
        "unexpected status codes with Valkey healthy: {:?}",
        healthy.other
    );
    assert!(
        healthy.admitted <= CEILING,
        "admission budget was exceeded with Valkey healthy: {} > {CEILING}",
        healthy.admitted
    );

    assert!(docker(&["stop", "-t", "2", &container]), "could not stop {container}");

    let outage = burst(400, 2);
    eprintln!(
        "valkey down: admitted={} limited={} other={:?} slowest={:?}",
        outage.admitted, outage.limited, outage.other, outage.slowest
    );

    // Fail closed, not open: losing the accelerator must not widen this
    // process's budget.
    assert!(
        outage.admitted <= CEILING,
        "losing Valkey FAILED OPEN: {} requests were admitted, above the {CEILING} ceiling",
        outage.admitted
    );
    // ...and not closed on everything either.
    assert!(
        outage.other.is_empty(),
        "losing Valkey produced non-RESOURCE_EXHAUSTED failures: {:?}",
        outage.other
    );
    assert!(
        outage.admitted > 0,
        "losing Valkey rejected every request; the in-process fallback did not take over"
    );
    assert!(
        valid_event_still_works(9001),
        "a valid event could not be ingested while Valkey was down"
    );

    assert!(docker(&["start", &container]), "could not start {container}");
    // Valkey needs a moment to accept TLS again.
    std::thread::sleep(Duration::from_secs(5));
    assert!(
        valid_event_still_works(9002),
        "the gateway did not recover after Valkey came back"
    );
    let recovered = burst(400, 3);
    eprintln!(
        "valkey back: admitted={} limited={} other={:?} slowest={:?}",
        recovered.admitted, recovered.limited, recovered.other, recovered.slowest
    );
    assert!(
        recovered.other.is_empty(),
        "unexpected status codes after Valkey recovered: {:?}",
        recovered.other
    );
    assert!(
        recovered.admitted <= CEILING,
        "admission budget was exceeded after recovery: {} > {CEILING}",
        recovered.admitted
    );
}

/// A Valkey that swallows packets instead of refusing them is the dangerous
/// case: the ephemeral store sits behind one process-wide mutex, so a socket
/// that neither answers nor resets can hold every admission behind it.
///
/// `docker pause` freezes the server with its listener still bound, which is
/// exactly a blackhole. The gateway sets 3s connect/read/write timeouts on the
/// Valkey connection specifically to bound this; the test pins that the bound
/// actually holds end to end rather than just being configured.
#[test]
fn paused_valkey_does_not_stall_admission_indefinitely() {
    if skip("paused_valkey_does_not_stall_admission_indefinitely") {
        return;
    }
    let container = valkey_container();
    // Make sure it is running before pausing it.
    let _ = docker(&["start", &container]);
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        valid_event_still_works(9100),
        "the gateway was not healthy before the blackhole test"
    );

    assert!(docker(&["pause", &container]), "could not pause {container}");
    let paused = std::panic::catch_unwind(|| {
        let started = Instant::now();
        let result = burst(24, 4);
        (result, started.elapsed())
    });
    assert!(docker(&["unpause", &container]), "could not unpause {container}");

    let (outcome, elapsed) = paused.expect("burst panicked against a blackholed Valkey");
    eprintln!(
        "valkey blackholed: admitted={} limited={} other={:?} slowest={:?} total={:?}",
        outcome.admitted, outcome.limited, outcome.other, outcome.slowest, elapsed
    );
    assert!(
        outcome.other.is_empty(),
        "a blackholed Valkey produced non-RESOURCE_EXHAUSTED failures: {:?}",
        outcome.other
    );
    // The per-command bound is 3s and the store is serialised, so a small
    // burst must not take minutes. This is deliberately generous: the point is
    // to catch an unbounded stall, not to assert a latency SLO.
    assert!(
        outcome.slowest < Duration::from_secs(90),
        "a single request waited {:?} on a blackholed Valkey; the socket timeouts \
         are not bounding the shared ephemeral-store mutex",
        outcome.slowest
    );

    std::thread::sleep(Duration::from_secs(3));
    assert!(
        valid_event_still_works(9101),
        "the gateway did not recover after Valkey was unpaused"
    );
}
