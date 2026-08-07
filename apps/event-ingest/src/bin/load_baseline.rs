//! Throughput / latency harness for a **live** `apex-event-ingest` container.
//!
//! Phase 0.6 work item 1. Every number in the Phase 0.6 plan's "Measured
//! baseline" section came from reading code. This binary replaces that with
//! measurements taken over real gRPC on a real mTLS channel against the
//! actually-built `apex-event-ingest` image, running under
//! `deploy/compose/compose.gateway-ref.yaml` with its real durability chain
//! (file outbox + idempotency journal, JetStream, ClickHouse projection,
//! archive provider with read-back verification).
//!
//! It is a client, not a fixture: it never links the gateway in-process, never
//! reaches into a store, and never disables a control. It reuses this crate's
//! own `proto` types and `canonical_event_hash` only so the envelopes it sends
//! are genuinely well formed -- a Python re-implementation of RFC 8785
//! canonicalization that drifted by one byte would measure nothing but the
//! validation rejection path.
//!
//! ## Per-stage attribution without instrumenting the gateway
//!
//! The gateway emits no timing signal, and adding one is remediation, not
//! measurement. Stages are therefore separated by *where a request stops*,
//! measured over the same channel under the same conditions:
//!
//! | Probe        | Stops at                                    | Includes |
//! |--------------|---------------------------------------------|----------|
//! | `rtt`        | tonic's router (unknown method)             | TLS + HTTP/2 + gRPC round trip only |
//! | `admission`  | `IngestRequest::from_validated_transport`   | + bearer verify, admission bucket, blocking-pool handoff, adapter mutex, decode, validate, JCS canonicalize, SHA-256 compare |
//! | `duplicate`  | `IdempotencyStore::reserve` -> Duplicate    | + committed-key lookup |
//! | `full`       | acknowledged event                          | + outbox enqueue (append+fsync), JetStream publish+ack, ClickHouse POST, archive PUT+read-back verify, outbox complete (append+fsync), idempotency commit (append+fsync) |
//!
//! Differences between adjacent rows attribute cost to a stage. The `full`
//! minus `duplicate` band is the whole fanout+durability chain; splitting it
//! further requires either gateway instrumentation or peer probes against the
//! same dependency containers (`deploy/compose/loadtest/stage_probe.py`).
//!
//! ## Invocation
//!
//! ```text
//! cargo run --release --bin apex-load-baseline --features test-support -- \
//!   --endpoint https://localhost:18445 \
//!   --secrets ../../deploy/compose/live-mtls/secrets-host \
//!   --scenario all --json ../../.local/apex-lab/load-baseline.json
//! ```
//!
//! `deploy/compose/loadtest/run_load_baseline.py` builds the image, starts the
//! stack, runs this, and tears the stack down again.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use apex_event_ingest::{canonical_event_hash, proto};
use prost::Message;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DEFAULT_ENDPOINT: &str = "https://localhost:18445";
const DEFAULT_AGENT_ID: &str = "reference-agent";
const DEFAULT_WORKSPACE: &str = "acme";
const DEFAULT_NAMESPACE: &str = "prod";

#[derive(Clone, Debug)]
struct Config {
    endpoint: String,
    secrets: PathBuf,
    scenario: String,
    agent_id: String,
    workspace: String,
    /// Namespaces cycled through by multi-scope runs. One entry means every
    /// event lands in a single admission bucket and a single idempotency scope.
    namespaces: Vec<String>,
    clients: usize,
    json: Option<PathBuf>,
    /// `stages` iterations per payload size.
    stage_iterations: usize,
    /// Minimum wall time per `stages` iteration, so the probe stream itself
    /// stays under the gateway's 256 req/s per-scope admission ceiling and
    /// measures latency rather than the rate limiter.
    stage_pace_ms: u64,
    concurrency_levels: Vec<usize>,
    concurrency_requests: usize,
    sustained_rate: f64,
    sustained_secs: u64,
    burst_multipliers: Vec<f64>,
    burst_secs: u64,
    burst_inflight: usize,
    /// Fail the process when sustained accepted throughput is below this.
    /// 0 disables (the default: this is a measurement tool first).
    min_accepted_per_sec: f64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_ENDPOINT.to_owned(),
            secrets: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../deploy/compose/live-mtls/secrets-host"),
            scenario: "all".to_owned(),
            agent_id: DEFAULT_AGENT_ID.to_owned(),
            workspace: DEFAULT_WORKSPACE.to_owned(),
            namespaces: vec![DEFAULT_NAMESPACE.to_owned()],
            clients: 8,
            json: None,
            stage_iterations: 150,
            stage_pace_ms: 25,
            concurrency_levels: vec![1, 2, 4, 8, 16, 32, 64],
            concurrency_requests: 600,
            sustained_rate: 116.0,
            sustained_secs: 30,
            burst_multipliers: vec![5.0, 10.0],
            burst_secs: 10,
            burst_inflight: 128,
            min_accepted_per_sec: 0.0,
        }
    }
}

fn parse_args() -> Result<Config, String> {
    let mut config = Config::default();
    if let Ok(value) = std::env::var("APEX_LOAD_GATEWAY")
        && !value.is_empty()
    {
        config.endpoint = value;
    }
    if let Ok(value) = std::env::var("APEX_LOAD_SECRETS")
        && !value.is_empty()
    {
        config.secrets = PathBuf::from(value);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        let mut value = || -> Result<String, String> {
            index += 1;
            args.get(index)
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match flag {
            "--endpoint" => config.endpoint = value()?,
            "--secrets" => config.secrets = PathBuf::from(value()?),
            "--scenario" => config.scenario = value()?,
            "--agent-id" => config.agent_id = value()?,
            "--workspace" => config.workspace = value()?,
            "--namespaces" => {
                config.namespaces = value()?
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
            "--clients" => config.clients = parse_usize(&value()?, flag)?,
            "--json" => config.json = Some(PathBuf::from(value()?)),
            "--stage-iterations" => config.stage_iterations = parse_usize(&value()?, flag)?,
            "--stage-pace-ms" => config.stage_pace_ms = parse_usize(&value()?, flag)? as u64,
            "--concurrency-levels" => {
                config.concurrency_levels = value()?
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(|item| parse_usize(item, flag))
                    .collect::<Result<_, _>>()?;
            }
            "--concurrency-requests" => config.concurrency_requests = parse_usize(&value()?, flag)?,
            "--sustained-rate" => config.sustained_rate = parse_f64(&value()?, flag)?,
            "--sustained-secs" => config.sustained_secs = parse_usize(&value()?, flag)? as u64,
            "--burst-multipliers" => {
                config.burst_multipliers = value()?
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(|item| parse_f64(item, flag))
                    .collect::<Result<_, _>>()?;
            }
            "--burst-secs" => config.burst_secs = parse_usize(&value()?, flag)? as u64,
            "--burst-inflight" => config.burst_inflight = parse_usize(&value()?, flag)?,
            "--min-accepted-per-sec" => config.min_accepted_per_sec = parse_f64(&value()?, flag)?,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown flag {other}")),
        }
        index += 1;
    }
    if config.namespaces.is_empty() {
        return Err("--namespaces must name at least one namespace".to_owned());
    }
    if config.clients == 0 {
        return Err("--clients must be at least 1".to_owned());
    }
    Ok(config)
}

fn parse_usize(value: &str, flag: &str) -> Result<usize, String> {
    value
        .parse()
        .map_err(|_| format!("{flag} expects a non-negative integer, got {value}"))
}

fn parse_f64(value: &str, flag: &str) -> Result<f64, String> {
    value
        .parse::<f64>()
        .ok()
        .filter(|parsed| parsed.is_finite() && *parsed >= 0.0)
        .ok_or_else(|| format!("{flag} expects a finite non-negative number, got {value}"))
}

fn print_usage() {
    println!(
        "apex-load-baseline -- throughput and per-stage latency against a live ingest gateway\n\
         \n\
         --endpoint URL             gateway (default {DEFAULT_ENDPOINT})\n\
         --secrets DIR              live-mTLS host secrets tree (ca.pem, ingest-http-client.*, ingest-bearer-token)\n\
         --scenario NAME            stages | concurrency | sustained | burst | all (default all)\n\
         --agent-id ID              bound agent id the credential carries (default {DEFAULT_AGENT_ID})\n\
         --workspace ID             workspace id (default {DEFAULT_WORKSPACE})\n\
         --namespaces A,B,C         namespaces to spread events across (default {DEFAULT_NAMESPACE})\n\
         --clients N                distinct mTLS channels (default 8)\n\
         --stage-iterations N       probe rounds per payload size (default 150)\n\
         --stage-pace-ms MS         minimum ms per probe round (default 25)\n\
         --concurrency-levels A,B   in-flight levels to sweep (default 1,2,4,8,16,32,64)\n\
         --concurrency-requests N   requests per level (default 600)\n\
         --sustained-rate R         offered events/sec (default 116)\n\
         --sustained-secs S         sustained duration (default 30)\n\
         --burst-multipliers A,B    multiples of the sustained rate (default 5,10)\n\
         --burst-secs S             burst duration each (default 10)\n\
         --burst-inflight N         in-flight ceiling during bursts (default 128)\n\
         --min-accepted-per-sec R   exit non-zero below this sustained accepted rate (default 0 = report only)\n\
         --json PATH                write the machine-readable report here\n"
    );
}

// ---------------------------------------------------------------------------
// Credentials and channels
// ---------------------------------------------------------------------------

fn read_secret(root: &Path, name: &str) -> Result<Vec<u8>, String> {
    std::fs::read(root.join(name))
        .map_err(|error| format!("missing {name} under {}: {error}", root.display()))
}

async fn build_channel(config: &Config) -> Result<Channel, String> {
    let root = &config.secrets;
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(read_secret(root, "ca.pem")?))
        .identity(Identity::from_pem(
            read_secret(root, "ingest-http-client.pem")?,
            read_secret(root, "ingest-http-client.key")?,
        ))
        // The gateway server certificate carries SAN `localhost`.
        .domain_name("localhost");
    Channel::from_shared(config.endpoint.clone())
        .map_err(|error| format!("bad endpoint {}: {error}", config.endpoint))?
        .tls_config(tls)
        .map_err(|error| format!("tls config: {error}"))?
        .connect()
        .await
        .map_err(|error| format!("connect {}: {error}", config.endpoint))
}

fn bearer_token(config: &Config) -> Result<String, String> {
    Ok(
        String::from_utf8(read_secret(&config.secrets, "ingest-bearer-token")?)
            .map_err(|_| "ingest-bearer-token is not UTF-8".to_owned())?
            .trim()
            .to_owned(),
    )
}

fn authorized<T>(message: T, token: &str) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}")
            .parse()
            .expect("bearer metadata is ASCII"),
    );
    request
}

// ---------------------------------------------------------------------------
// Request shapes
// ---------------------------------------------------------------------------

/// Payload shapes measured. "events/sec" without a payload size is not a
/// number, so both ends of the realistic range are measured and reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// A typical LLM-call event: identifiers, token counts, latency, no
    /// captured text. This is what a high-rate agent runtime actually emits
    /// most of.
    Small,
    /// An LLM event that carries a captured prompt/response excerpt, sized
    /// under the contract's 32 KiB per-field text cap.
    Large,
}

impl Shape {
    fn label(self) -> &'static str {
        match self {
            Shape::Small => "small",
            Shape::Large => "large",
        }
    }
}

fn string_value(value: &str) -> prost_types::Value {
    prost_types::Value {
        kind: Some(prost_types::value::Kind::StringValue(value.to_owned())),
    }
}

fn number_value(value: f64) -> prost_types::Value {
    prost_types::Value {
        kind: Some(prost_types::value::Kind::NumberValue(value)),
    }
}

fn event_data(shape: Shape) -> prost_types::Struct {
    let mut data = prost_types::Struct::default();
    data.fields
        .insert("operation".to_owned(), string_value("chat.completions"));
    data.fields
        .insert("provider".to_owned(), string_value("anthropic"));
    data.fields
        .insert("model".to_owned(), string_value("claude-sonnet-4-6"));
    data.fields
        .insert("input_tokens".to_owned(), number_value(1843.0));
    data.fields
        .insert("output_tokens".to_owned(), number_value(412.0));
    data.fields
        .insert("latency_ms".to_owned(), number_value(2317.0));
    data.fields
        .insert("stop_reason".to_owned(), string_value("end_turn"));
    data.fields.insert(
        "tool_names".to_owned(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::ListValue(
                prost_types::ListValue {
                    values: vec![string_value("read_file"), string_value("run_tests")],
                },
            )),
        },
    );
    if shape == Shape::Large {
        // A captured excerpt, truncated the way the SDK truncates, with the
        // sibling digest the contract requires. 8 KiB is a realistic captured
        // field; the contract caps a text field at 32 KiB.
        let excerpt = "the agent inspected the failing test and proposed a patch. ".repeat(139);
        let excerpt = format!("{}\u{2026}[truncated]", &excerpt[..8_100]);
        data.fields
            .insert("output_excerpt".to_owned(), string_value(&excerpt));
        // Named `_digest`, not the `_sha256` the event contract prescribes for
        // this sibling field. `validation/secrets.rs` exempts a 64-hex value
        // from the encoded-secret heuristic only under a key ending in
        // hash/digest/ref/id, so a producer that follows docs/event-schema.md
        // literally is answered SECRET_EXPOSURE. That is a real contract gap,
        // not something this harness should be measuring; see
        // docs/phase-0.6-load-baseline.md.
        data.fields.insert(
            "output_excerpt_digest".to_owned(),
            string_value("3f2a91c47d0b5e86af13c9d2740be5182c6ab7f905de3418c2b7069a51fd8e3c"),
        );
    }
    data
}

struct EnvelopeFactory {
    agent_id: String,
    workspace: String,
    namespaces: Vec<String>,
    run_nonce: u64,
    counter: AtomicU64,
}

impl EnvelopeFactory {
    fn new(config: &Config) -> Self {
        // The gateway's idempotency journal is durable, so ids must be unique
        // across runs against the same volume, not just within a run.
        let mut bytes = [0u8; 8];
        let nonce = if getrandom::fill(&mut bytes).is_ok() {
            u64::from_le_bytes(bytes) & 0x00ff_ffff
        } else {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos() as u64 & 0x00ff_ffff)
                .unwrap_or(0)
        };
        Self {
            agent_id: config.agent_id.clone(),
            workspace: config.workspace.clone(),
            namespaces: config.namespaces.clone(),
            run_nonce: nonce,
            counter: AtomicU64::new(0),
        }
    }

    fn next_index(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Lowercase UUIDv7 whose low 48 bits carry a per-run nonce plus a
    /// sequence number, so two runs against the same durable journal never
    /// collide and every request inside a run owns its own idempotency key.
    fn event_id(&self, index: u64) -> String {
        format!(
            "018f5c91-2d88-7c00-8000-{:012x}",
            (self.run_nonce << 24) | (index & 0x00ff_ffff)
        )
    }

    fn namespace(&self, index: u64) -> &str {
        &self.namespaces[(index as usize) % self.namespaces.len()]
    }

    fn envelope(&self, index: u64, shape: Shape) -> proto::EventEnvelope {
        let envelope = proto::EventEnvelope {
            event_id: self.event_id(index),
            timestamp: "2026-08-07T12:00:00.000000Z".to_owned(),
            r#type: 2, // LLM
            agent_id: self.agent_id.clone(),
            run_id: format!("run-{}", index % 64),
            parent_run_id: None,
            trace_id: format!("trace-{}", index % 64),
            scope: Some(proto::Scope {
                workspace_id: self.workspace.clone(),
                namespace_id: self.namespace(index).to_owned(),
                agent_group_ids: vec![],
            }),
            actor: Some(proto::Actor {
                r#type: 2, // AGENT
                id: self.agent_id.clone(),
            }),
            version: Some(proto::Version {
                agent_code: "v1.4.2".to_owned(),
                prompt: "p-2026-08".to_owned(),
                model: "claude-sonnet-4-6".to_owned(),
            }),
            data: Some(event_data(shape)),
            integrity: Some(proto::Integrity {
                prev_hash: None,
                event_hash: "0".repeat(64),
            }),
            schema_version: 1,
        };
        sign(envelope)
    }

    fn fresh(&self, shape: Shape) -> proto::EventEnvelope {
        self.envelope(self.next_index(), shape)
    }
}

fn sign(mut envelope: proto::EventEnvelope) -> proto::EventEnvelope {
    let hash = canonical_event_hash(&envelope).expect("harness envelope is canonicalizable");
    envelope
        .integrity
        .as_mut()
        .expect("integrity present")
        .event_hash = hash;
    envelope
}

// ---------------------------------------------------------------------------
// Outcome classification
// ---------------------------------------------------------------------------

/// `errors/gateway.rs` deliberately collapses `RATE_LIMITED` and
/// `ADMISSION_BUSY` into one `RESOURCE_EXHAUSTED` status carrying an identical
/// message, so a client cannot tell them apart from the response alone. Runs
/// that need the distinction keep the per-scope offered rate well under the
/// 256 req/s admission ceiling, which leaves the single-flight adapter lock as
/// the only remaining source of that status.
const CAPACITY_MESSAGE: &str = "Request capacity is temporarily unavailable.";

fn classify(result: &Result<proto::IngestResponse, tonic::Status>) -> &'static str {
    match result {
        Ok(response) if response.duplicate => "ok_duplicate",
        Ok(_) => "ok",
        Err(status) => {
            let message = status.message();
            if message.starts_with(CAPACITY_MESSAGE) {
                "busy_or_rate_limited"
            } else if let Some(code) = message.split(':').next() {
                match code {
                    "IDEMPOTENCY_CAPACITY" => "idempotency_capacity",
                    "IDEMPOTENCY_IN_PROGRESS" => "idempotency_in_progress",
                    "IDEMPOTENCY_CONFLICT" => "idempotency_conflict",
                    "PUBLISH_FAILED" => "publish_failed",
                    "PAYLOAD_TOO_LARGE" => "payload_too_large",
                    "SCOPE_DENIED" => "scope_denied",
                    "INTERNAL_FAILURE" => "internal",
                    _ => "other_error",
                }
            } else {
                "other_error"
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct Samples(Vec<u64>);

impl Samples {
    fn push(&mut self, micros: u64) {
        self.0.push(micros);
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn percentile(&mut self, fraction: f64) -> f64 {
        if self.0.is_empty() {
            return 0.0;
        }
        self.0.sort_unstable();
        let rank = ((self.0.len() - 1) as f64 * fraction).round() as usize;
        self.0[rank] as f64 / 1000.0
    }

    fn mean_ms(&self) -> f64 {
        if self.0.is_empty() {
            return 0.0;
        }
        self.0.iter().sum::<u64>() as f64 / self.0.len() as f64 / 1000.0
    }

    fn summary(&mut self) -> Json {
        Json::object([
            ("count", Json::Number(self.len() as f64)),
            ("mean_ms", Json::Number(round3(self.mean_ms()))),
            ("p50_ms", Json::Number(round3(self.percentile(0.50)))),
            ("p90_ms", Json::Number(round3(self.percentile(0.90)))),
            ("p99_ms", Json::Number(round3(self.percentile(0.99)))),
            ("max_ms", Json::Number(round3(self.percentile(1.0)))),
        ])
    }
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

// ---------------------------------------------------------------------------
// Minimal JSON writer (this crate carries serde_json already)
// ---------------------------------------------------------------------------

enum Json {
    Number(f64),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    fn object<const N: usize>(fields: [(&str, Json); N]) -> Json {
        Json::Object(
            fields
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value))
                .collect(),
        )
    }

    fn text(value: &str) -> Json {
        Json::String(value.to_owned())
    }

    fn render(&self, indent: usize, out: &mut String) {
        let pad = "  ".repeat(indent);
        let inner_pad = "  ".repeat(indent + 1);
        match self {
            Json::Number(value) => {
                if value.is_finite() {
                    out.push_str(&format!("{value}"));
                } else {
                    out.push_str("null");
                }
            }
            Json::String(value) => {
                out.push('"');
                for character in value.chars() {
                    match character {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                        c => out.push(c),
                    }
                }
                out.push('"');
            }
            Json::Array(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push_str("[\n");
                for (position, item) in items.iter().enumerate() {
                    out.push_str(&inner_pad);
                    item.render(indent + 1, out);
                    if position + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push(']');
            }
            Json::Object(fields) => {
                if fields.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push_str("{\n");
                for (position, (name, value)) in fields.iter().enumerate() {
                    out.push_str(&inner_pad);
                    Json::String(name.clone()).render(indent + 1, out);
                    out.push_str(": ");
                    value.render(indent + 1, out);
                    if position + 1 < fields.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push('}');
            }
        }
    }
}

fn histogram_json(histogram: &BTreeMap<String, u64>) -> Json {
    Json::Object(
        histogram
            .iter()
            .map(|(name, count)| (name.clone(), Json::Number(*count as f64)))
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Transport helpers
// ---------------------------------------------------------------------------

async fn send_envelope(
    channel: &Channel,
    token: &str,
    envelope: proto::EventEnvelope,
) -> Result<proto::IngestResponse, tonic::Status> {
    let mut client = proto::event_ingest_client::EventIngestClient::new(channel.clone());
    client
        .ingest(authorized(envelope, token))
        .await
        .map(|response| response.into_inner())
}

/// A full TLS + HTTP/2 + gRPC round trip that reaches tonic's router and stops
/// there. No handler runs, no auth, no admission bucket, so the result is the
/// transport floor every other measurement sits on top of.
async fn send_rtt_probe(channel: &Channel, token: &str) -> Result<(), tonic::Status> {
    let mut grpc = tonic::client::Grpc::new(channel.clone());
    grpc.ready()
        .await
        .map_err(|error| tonic::Status::unavailable(error.to_string()))?;
    let codec: tonic_prost::ProstCodec<proto::EventEnvelope, proto::IngestResponse> =
        Default::default();
    let path =
        tonic::codegen::http::uri::PathAndQuery::from_static("/apex.v1.EventIngest/RttProbeNoOp");
    match grpc
        .unary(
            authorized(proto::EventEnvelope::default(), token),
            path,
            codec,
        )
        .await
    {
        Ok(_) => Ok(()),
        // Unimplemented is the expected answer: the router matched the service
        // prefix and refused the method without entering a handler.
        Err(status) if status.code() == tonic::Code::Unimplemented => Ok(()),
        Err(status) => Err(status),
    }
}

// ---------------------------------------------------------------------------
// Scenario: per-stage latency (serial, one request in flight)
// ---------------------------------------------------------------------------

struct StageResult {
    shape: Shape,
    envelope_bytes: usize,
    rtt: Samples,
    admission: Samples,
    duplicate: Samples,
    full: Samples,
    histogram: BTreeMap<String, u64>,
    /// `full` latency for the first and last tenth of the run, to expose any
    /// per-event cost that grows with journal size.
    first_decile_p50_ms: f64,
    last_decile_p50_ms: f64,
}

async fn scenario_stages(
    config: &Config,
    channel: &Channel,
    token: &str,
    factory: &EnvelopeFactory,
    shape: Shape,
) -> Result<StageResult, String> {
    let mut result = StageResult {
        shape,
        envelope_bytes: factory.envelope(0, shape).encoded_len(),
        rtt: Samples::default(),
        admission: Samples::default(),
        duplicate: Samples::default(),
        full: Samples::default(),
        histogram: BTreeMap::new(),
        first_decile_p50_ms: 0.0,
        last_decile_p50_ms: 0.0,
    };

    // Anchor: one accepted event whose id every duplicate probe reuses.
    let anchor = factory.fresh(shape);
    let anchor_outcome = send_envelope(channel, token, anchor.clone()).await;
    if let Err(status) = &anchor_outcome {
        return Err(format!(
            "the anchor event was not accepted, so no stage probe is meaningful: {status}"
        ));
    }

    let mut ordered_full: Vec<u64> = Vec::with_capacity(config.stage_iterations);
    for _ in 0..config.stage_iterations {
        let round_started = Instant::now();

        let started = Instant::now();
        send_rtt_probe(channel, token)
            .await
            .map_err(|status| format!("rtt probe failed: {status}"))?;
        result.rtt.push(started.elapsed().as_micros() as u64);

        // Admission probe: a structurally valid envelope whose integrity hash
        // is well formed but wrong. It is rejected inside
        // `from_validated_transport`, after the full canonicalization it
        // exists to measure and before any durability work.
        let mut forged = factory.fresh(shape);
        forged
            .integrity
            .as_mut()
            .expect("integrity present")
            .event_hash = "b".repeat(64);
        let started = Instant::now();
        let outcome = send_envelope(channel, token, forged).await;
        let elapsed = started.elapsed().as_micros() as u64;
        match &outcome {
            Err(status) if status.code() == tonic::Code::InvalidArgument => {
                result.admission.push(elapsed)
            }
            other => {
                return Err(format!(
                    "admission probe did not stop at canonicalization: {other:?}"
                ));
            }
        }

        // Duplicate probe: the anchor again. Stops at the committed-key lookup
        // in `IdempotencyStore::reserve`, before the outbox is touched.
        let started = Instant::now();
        let outcome = send_envelope(channel, token, anchor.clone()).await;
        let elapsed = started.elapsed().as_micros() as u64;
        match &outcome {
            Ok(response) if response.duplicate => result.duplicate.push(elapsed),
            other => return Err(format!("duplicate probe was not answered duplicate: {other:?}")),
        }

        // Full path.
        let started = Instant::now();
        let outcome = send_envelope(channel, token, factory.fresh(shape)).await;
        let elapsed = started.elapsed().as_micros() as u64;
        *result
            .histogram
            .entry(classify(&outcome).to_owned())
            .or_insert(0) += 1;
        if outcome.is_ok() {
            result.full.push(elapsed);
            ordered_full.push(elapsed);
        }

        let pace = Duration::from_millis(config.stage_pace_ms);
        if let Some(remaining) = pace.checked_sub(round_started.elapsed()) {
            tokio::time::sleep(remaining).await;
        }
    }

    if !ordered_full.is_empty() {
        let decile = (ordered_full.len() / 10).max(1);
        let mut first = Samples(ordered_full[..decile].to_vec());
        let mut last = Samples(ordered_full[ordered_full.len() - decile..].to_vec());
        result.first_decile_p50_ms = first.percentile(0.5);
        result.last_decile_p50_ms = last.percentile(0.5);
    }
    Ok(result)
}

fn stage_json(result: &mut StageResult) -> Json {
    let full_p50 = result.full.percentile(0.5);
    let duplicate_p50 = result.duplicate.percentile(0.5);
    let admission_p50 = result.admission.percentile(0.5);
    let rtt_p50 = result.rtt.percentile(0.5);
    Json::object([
        ("payload", Json::text(result.shape.label())),
        (
            "envelope_bytes",
            Json::Number(result.envelope_bytes as f64),
        ),
        ("transport_rtt", result.rtt.summary()),
        ("admission_stop", result.admission.summary()),
        ("duplicate_stop", result.duplicate.summary()),
        ("full_path", result.full.summary()),
        (
            "derived_p50_ms",
            Json::object([
                ("transport_rtt", Json::Number(round3(rtt_p50))),
                (
                    "admission_auth_validate_canonicalize",
                    Json::Number(round3(admission_p50 - rtt_p50)),
                ),
                (
                    "idempotency_lookup",
                    Json::Number(round3(duplicate_p50 - admission_p50)),
                ),
                (
                    "outbox_and_fanout",
                    Json::Number(round3(full_p50 - duplicate_p50)),
                ),
                ("full_path_total", Json::Number(round3(full_p50))),
            ]),
        ),
        (
            "serial_ceiling_events_per_sec",
            Json::Number(round3(if full_p50 > 0.0 { 1000.0 / full_p50 } else { 0.0 })),
        ),
        (
            "drift",
            Json::object([
                (
                    "first_decile_p50_ms",
                    Json::Number(round3(result.first_decile_p50_ms)),
                ),
                (
                    "last_decile_p50_ms",
                    Json::Number(round3(result.last_decile_p50_ms)),
                ),
            ]),
        ),
        ("outcomes", histogram_json(&result.histogram)),
    ])
}

// ---------------------------------------------------------------------------
// Load generation shared by the concurrency, sustained, and burst scenarios
// ---------------------------------------------------------------------------

struct LoadOutcome {
    offered: u64,
    wall_secs: f64,
    /// Time from the request actually leaving the harness to its answer.
    service: Samples,
    /// Time from the moment the request was *scheduled* to leave. Diverges
    /// from `service` exactly when the harness could not dispatch on time,
    /// which is the honest way to report an open-loop target the system did
    /// not keep up with.
    arrival: Samples,
    histogram: BTreeMap<String, u64>,
}

impl LoadOutcome {
    fn accepted(&self) -> u64 {
        self.histogram.get("ok").copied().unwrap_or(0)
            + self.histogram.get("ok_duplicate").copied().unwrap_or(0)
    }

    fn accepted_per_sec(&self) -> f64 {
        if self.wall_secs > 0.0 {
            self.accepted() as f64 / self.wall_secs
        } else {
            0.0
        }
    }

    fn json(&mut self, label: &str, extra: Vec<(String, Json)>) -> Json {
        let mut fields = vec![
            ("phase".to_owned(), Json::text(label)),
            ("offered".to_owned(), Json::Number(self.offered as f64)),
            (
                "wall_secs".to_owned(),
                Json::Number(round3(self.wall_secs)),
            ),
            ("accepted".to_owned(), Json::Number(self.accepted() as f64)),
            (
                "accepted_per_sec".to_owned(),
                Json::Number(round3(self.accepted_per_sec())),
            ),
            (
                "offered_per_sec".to_owned(),
                Json::Number(round3(if self.wall_secs > 0.0 {
                    self.offered as f64 / self.wall_secs
                } else {
                    0.0
                })),
            ),
            ("service_latency".to_owned(), self.service.summary()),
            ("arrival_latency".to_owned(), self.arrival.summary()),
            ("outcomes".to_owned(), histogram_json(&self.histogram)),
        ];
        fields.extend(extra);
        Json::Object(fields)
    }
}

struct Attempt {
    scheduled_at: Instant,
    sent_at: Instant,
    finished_at: Instant,
    outcome: &'static str,
}

/// Drives `total` requests at `rate` events/sec (or as fast as the in-flight
/// ceiling allows when `rate` is `None`), across `channels`, with at most
/// `max_inflight` requests outstanding.
async fn drive_load(
    channels: &[Channel],
    token: &str,
    factory: &Arc<EnvelopeFactory>,
    shape: Shape,
    total: u64,
    rate: Option<f64>,
    max_inflight: usize,
) -> LoadOutcome {
    let permits = Arc::new(tokio::sync::Semaphore::new(max_inflight));
    let started = Instant::now();
    let interval = rate.filter(|value| *value > 0.0).map(|value| value.recip());
    let mut tasks = Vec::with_capacity(total as usize);

    for sequence in 0..total {
        let scheduled_at = match interval {
            Some(step) => started + Duration::from_secs_f64(step * sequence as f64),
            None => Instant::now(),
        };
        if let Some(remaining) = scheduled_at.checked_duration_since(Instant::now()) {
            tokio::time::sleep(remaining).await;
        }
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore is never closed");
        let channel = channels[(sequence as usize) % channels.len()].clone();
        let token = token.to_owned();
        let factory = factory.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            let envelope = factory.fresh(shape);
            let sent_at = Instant::now();
            let outcome = send_envelope(&channel, &token, envelope).await;
            Attempt {
                scheduled_at,
                sent_at,
                finished_at: Instant::now(),
                outcome: classify(&outcome),
            }
        }));
    }

    let mut result = LoadOutcome {
        offered: total,
        wall_secs: 0.0,
        service: Samples::default(),
        arrival: Samples::default(),
        histogram: BTreeMap::new(),
    };
    for task in tasks {
        match task.await {
            Ok(attempt) => {
                result
                    .service
                    .push(attempt.finished_at.duration_since(attempt.sent_at).as_micros() as u64);
                result.arrival.push(
                    attempt
                        .finished_at
                        .duration_since(attempt.scheduled_at)
                        .as_micros() as u64,
                );
                *result
                    .histogram
                    .entry(attempt.outcome.to_owned())
                    .or_insert(0) += 1;
            }
            Err(_) => {
                *result
                    .histogram
                    .entry("harness_task_failed".to_owned())
                    .or_insert(0) += 1;
            }
        }
    }
    result.wall_secs = started.elapsed().as_secs_f64();
    result
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let config = match parse_args() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("apex-load-baseline: {error}");
            print_usage();
            std::process::exit(2);
        }
    };
    apex_event_ingest::install_rustls_provider();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("harness runtime");
    let code = runtime.block_on(run(config));
    std::process::exit(code);
}

async fn run(config: Config) -> i32 {
    let token = match bearer_token(&config) {
        Ok(token) => token,
        Err(error) => {
            eprintln!("apex-load-baseline: {error}");
            return 2;
        }
    };
    let mut channels = Vec::with_capacity(config.clients);
    for _ in 0..config.clients {
        match build_channel(&config).await {
            Ok(channel) => channels.push(channel),
            Err(error) => {
                eprintln!("apex-load-baseline: {error}");
                return 2;
            }
        }
    }
    let factory = Arc::new(EnvelopeFactory::new(&config));
    let run_all = config.scenario == "all";
    let mut sections: Vec<(String, Json)> = Vec::new();
    let mut failed = false;
    let mut sustained_rate_achieved = f64::NAN;

    println!("apex-load-baseline");
    println!("  endpoint   {}", config.endpoint);
    println!("  clients    {}", config.clients);
    println!(
        "  scopes     {} ({})",
        config.namespaces.len(),
        config
            .namespaces
            .iter()
            .map(|namespace| format!("{}/{namespace}", config.workspace))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!();

    if run_all || config.scenario == "stages" {
        let mut entries = Vec::new();
        for shape in [Shape::Small, Shape::Large] {
            match scenario_stages(&config, &channels[0], &token, &factory, shape).await {
                Ok(mut result) => {
                    print_stage(&mut result);
                    entries.push(stage_json(&mut result));
                }
                Err(error) => {
                    eprintln!("apex-load-baseline: stages/{}: {error}", shape.label());
                    failed = true;
                }
            }
        }
        sections.push(("stages".to_owned(), Json::Array(entries)));
    }

    if run_all || config.scenario == "concurrency" {
        let mut entries = Vec::new();
        println!("== concurrency sweep (closed loop, small payload) ==");
        println!(
            "{:>6}  {:>9}  {:>11}  {:>9}  {:>9}  {:>7}",
            "inflight", "accepted", "accepted/s", "p50 ms", "p99 ms", "busy%"
        );
        for level in config.concurrency_levels.clone() {
            let mut outcome = drive_load(
                &channels,
                &token,
                &factory,
                Shape::Small,
                config.concurrency_requests as u64,
                None,
                level,
            )
            .await;
            let busy = outcome
                .histogram
                .get("busy_or_rate_limited")
                .copied()
                .unwrap_or(0);
            let busy_share = if outcome.offered > 0 {
                busy as f64 * 100.0 / outcome.offered as f64
            } else {
                0.0
            };
            println!(
                "{:>6}  {:>9}  {:>11.1}  {:>9.2}  {:>9.2}  {:>6.1}%",
                level,
                outcome.accepted(),
                outcome.accepted_per_sec(),
                outcome.service.percentile(0.5),
                outcome.service.percentile(0.99),
                busy_share
            );
            entries.push(outcome.json(
                &format!("inflight={level}"),
                vec![
                    ("max_inflight".to_owned(), Json::Number(level as f64)),
                    (
                        "busy_or_rate_limited_share_pct".to_owned(),
                        Json::Number(round3(busy_share)),
                    ),
                ],
            ));
        }
        println!();
        sections.push(("concurrency".to_owned(), Json::Array(entries)));
    }

    if run_all || config.scenario == "sustained" {
        let total = (config.sustained_rate * config.sustained_secs as f64).round() as u64;
        println!(
            "== sustained: {:.0} events/sec offered for {}s (small payload) ==",
            config.sustained_rate, config.sustained_secs
        );
        let mut outcome = drive_load(
            &channels,
            &token,
            &factory,
            Shape::Small,
            total,
            Some(config.sustained_rate),
            config.burst_inflight,
        )
        .await;
        sustained_rate_achieved = outcome.accepted_per_sec();
        print_load(&mut outcome);
        sections.push((
            "sustained".to_owned(),
            outcome.json(
                &format!("sustained@{:.0}/s", config.sustained_rate),
                vec![(
                    "target_per_sec".to_owned(),
                    Json::Number(config.sustained_rate),
                )],
            ),
        ));
    }

    if run_all || config.scenario == "burst" {
        let mut entries = Vec::new();
        for multiplier in config.burst_multipliers.clone() {
            let rate = config.sustained_rate * multiplier;
            let total = (rate * config.burst_secs as f64).round() as u64;
            println!(
                "== burst: {multiplier}x = {rate:.0} events/sec offered for {}s (small payload) ==",
                config.burst_secs
            );
            let mut outcome = drive_load(
                &channels,
                &token,
                &factory,
                Shape::Small,
                total,
                Some(rate),
                config.burst_inflight,
            )
            .await;
            print_load(&mut outcome);
            entries.push(outcome.json(
                &format!("burst@{rate:.0}/s"),
                vec![
                    ("multiplier".to_owned(), Json::Number(multiplier)),
                    ("target_per_sec".to_owned(), Json::Number(round3(rate))),
                ],
            ));
        }
        sections.push(("burst".to_owned(), Json::Array(entries)));
    }

    let report = Json::Object({
        let mut fields = vec![
            (
                "generated_at".to_owned(),
                Json::text(&rfc3339_now()),
            ),
            ("endpoint".to_owned(), Json::text(&config.endpoint)),
            (
                "config".to_owned(),
                Json::object([
                    ("clients", Json::Number(config.clients as f64)),
                    ("workspace", Json::text(&config.workspace)),
                    (
                        "namespaces",
                        Json::Array(
                            config
                                .namespaces
                                .iter()
                                .map(|namespace| Json::text(namespace))
                                .collect(),
                        ),
                    ),
                    (
                        "stage_iterations",
                        Json::Number(config.stage_iterations as f64),
                    ),
                    (
                        "concurrency_requests",
                        Json::Number(config.concurrency_requests as f64),
                    ),
                    ("sustained_rate", Json::Number(config.sustained_rate)),
                    (
                        "sustained_secs",
                        Json::Number(config.sustained_secs as f64),
                    ),
                    ("burst_secs", Json::Number(config.burst_secs as f64)),
                    (
                        "burst_inflight",
                        Json::Number(config.burst_inflight as f64),
                    ),
                ]),
            ),
        ];
        fields.extend(sections);
        fields
    });
    let mut rendered = String::new();
    report.render(0, &mut rendered);
    rendered.push('\n');
    if let Some(path) = &config.json {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::write(path, &rendered) {
            Ok(()) => println!("report written to {}", path.display()),
            Err(error) => {
                eprintln!("apex-load-baseline: could not write {}: {error}", path.display());
                failed = true;
            }
        }
    } else {
        println!("{rendered}");
    }

    if config.min_accepted_per_sec > 0.0
        && sustained_rate_achieved.is_finite()
        && sustained_rate_achieved < config.min_accepted_per_sec
    {
        eprintln!(
            "apex-load-baseline: sustained accepted rate {sustained_rate_achieved:.1}/s is below the \
             --min-accepted-per-sec floor of {:.1}/s",
            config.min_accepted_per_sec
        );
        failed = true;
    }

    if failed { 1 } else { 0 }
}

fn print_stage(result: &mut StageResult) {
    let rtt = result.rtt.percentile(0.5);
    let admission = result.admission.percentile(0.5);
    let duplicate = result.duplicate.percentile(0.5);
    let full = result.full.percentile(0.5);
    println!(
        "== per-stage latency, {} payload ({} bytes on the wire) ==",
        result.shape.label(),
        result.envelope_bytes
    );
    println!(
        "{:<44}{:>9}{:>9}{:>9}",
        "probe (p50 / p99 / max, ms)", "p50", "p99", "max"
    );
    for (label, samples) in [
        ("transport round trip (no handler)", &mut result.rtt),
        ("+ auth, admission, validate, canonicalize", &mut result.admission),
        ("+ idempotency lookup (duplicate)", &mut result.duplicate),
        ("+ outbox, JetStream, ClickHouse, archive", &mut result.full),
    ] {
        println!(
            "{label:<44}{:>9.2}{:>9.2}{:>9.2}",
            samples.percentile(0.5),
            samples.percentile(0.99),
            samples.percentile(1.0)
        );
    }
    println!("  attributed p50 (ms):");
    println!("    transport                              {rtt:>8.2}");
    println!(
        "    admission (auth+validate+canonicalize) {:>8.2}",
        admission - rtt
    );
    println!(
        "    idempotency lookup                     {:>8.2}",
        duplicate - admission
    );
    println!(
        "    outbox commit + fanout                 {:>8.2}",
        full - duplicate
    );
    if admission - rtt <= 0.05 {
        println!(
            "    (admission work is at or below the transport round-trip noise floor: it does not\n\
             \x20    resolve as a separate cost at this sample size)"
        );
    }
    println!(
        "  serial ceiling: {:.1} events/sec at p50, first-decile p50 {:.2} ms -> last-decile p50 {:.2} ms",
        if full > 0.0 { 1000.0 / full } else { 0.0 },
        result.first_decile_p50_ms,
        result.last_decile_p50_ms
    );
    println!("  outcomes: {:?}", result.histogram);
    println!();
}

fn print_load(outcome: &mut LoadOutcome) {
    println!(
        "  offered {} in {:.1}s ({:.1}/s), accepted {} ({:.1}/s)",
        outcome.offered,
        outcome.wall_secs,
        outcome.offered as f64 / outcome.wall_secs.max(f64::MIN_POSITIVE),
        outcome.accepted(),
        outcome.accepted_per_sec()
    );
    println!(
        "  service latency  p50 {:.2} ms  p99 {:.2} ms  max {:.2} ms",
        outcome.service.percentile(0.5),
        outcome.service.percentile(0.99),
        outcome.service.percentile(1.0)
    );
    println!(
        "  arrival latency  p50 {:.2} ms  p99 {:.2} ms  max {:.2} ms",
        outcome.arrival.percentile(0.5),
        outcome.arrival.percentile(0.99),
        outcome.arrival.percentile(1.0)
    );
    println!("  outcomes: {:?}", outcome.histogram);
    println!();
}

fn rfc3339_now() -> String {
    // Whole seconds are enough for a report header, and this avoids adding a
    // date/time dependency to a crate that deliberately has none.
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let days = seconds / 86_400;
    let time_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60
    )
}

/// Howard Hinnant's `civil_from_days`, for a Unix day number.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}
