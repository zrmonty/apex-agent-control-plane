//! **The live end-to-end proof of this pass**: an operator's `stop` reaches a
//! real agent process and halts it.
//!
//! Everything in this file runs against real containers and real processes:
//!
//! - a real `control-plane-api` container terminating mTLS
//!   (`deploy/compose/compose.gateway-ref.yaml`),
//! - a real Python process using the product SDK's own
//!   `GrpcControlTransport` and `ReferenceReasonActLoop`
//!   (`deploy/compose/gateway-ref/agent_under_control.py`),
//! - a real `SubmitCommand` call over mTLS with an operator credential, using
//!   the RPC that already worked and is not modified here.
//!
//! The causality claim is deliberately not "the process exited". A process can
//! exit for a dozen reasons. What is asserted is that the `command_id` the
//! gateway minted for *this* submission is the same `command_id` the agent
//! printed when it halted, that the agent completed whole iterations before
//! the submission and none after, and that the agent's own JSONL trace
//! contains the terminal `control` + `turn_end(stopped)` pair naming it. A
//! coincidental exit cannot produce a freshly-minted UUIDv7 it never saw.
//!
//! Opt-in via `APEX_CONTROL_LIVE_POLL=1`, so offline unit CI stays green.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use apex_control_plane_api::proto;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

fn live_enabled() -> bool {
    std::env::var("APEX_CONTROL_LIVE_POLL").ok().as_deref() == Some("1")
}

fn endpoint_url() -> String {
    std::env::var("APEX_CONTROL_LIVE_ENDPOINT")
        .unwrap_or_else(|_| "https://localhost:18446".to_owned())
}

/// `host:port` form for the Python client, which takes a bare authority rather
/// than a URL (see `GrpcControlTransport`'s refusal of a scheme).
fn endpoint_authority() -> String {
    endpoint_url()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_owned()
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root must resolve")
}

fn secrets_dir() -> PathBuf {
    if let Ok(path) = std::env::var("APEX_CONTROL_LIVE_SECRETS") {
        return PathBuf::from(path);
    }
    repo_root().join("deploy/compose/live-mtls/secrets-host")
}

fn python_executable() -> String {
    std::env::var("APEX_CONTROL_LIVE_PYTHON").unwrap_or_else(|_| "python3".to_owned())
}

fn require_secret(name: &str) -> Vec<u8> {
    let path = secrets_dir().join(name);
    assert!(
        path.is_file(),
        "missing live-mTLS fixture {name} under {}; run generate_pki.py",
        secrets_dir().display()
    );
    std::fs::read(&path).expect("fixture must be readable")
}

/// Splits `token|...` from the right, the way both credential-table parsers do.
fn table_token(name: &str, fields_to_the_right: usize) -> String {
    let raw = String::from_utf8(require_secret(name)).expect("credential table must be UTF-8");
    let entry = raw
        .split(';')
        .map(str::trim)
        .find(|entry| !entry.is_empty())
        .expect("credential table must have at least one entry");
    let mut parts: Vec<&str> = entry.rsplitn(fields_to_the_right + 1, '|').collect();
    parts.reverse();
    parts[0].to_owned()
}

fn operator_token() -> String {
    table_token("control-operator-tokens", 1)
}

fn agent_token(table: &str) -> String {
    table_token(table, 3)
}

fn tls_config(identity: Identity) -> ClientTlsConfig {
    ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(require_secret("ca.pem")))
        .domain_name("localhost")
        .identity(identity)
}

fn identity(basename: &str) -> Identity {
    Identity::from_pem(
        require_secret(&format!("{basename}.pem")),
        require_secret(&format!("{basename}.key")),
    )
}

async fn channel(basename: &str) -> tonic::transport::Channel {
    Endpoint::from_shared(endpoint_url())
        .expect("endpoint must parse")
        .tls_config(tls_config(identity(basename)))
        .expect("tls config must build")
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(15))
        .connect()
        .await
        .expect("the control gateway must be reachable over mTLS")
}

fn control_command(
    agent_id: &str,
    action: proto::ControlAction,
    reason_code: Option<&str>,
) -> proto::ControlCommandRequest {
    proto::ControlCommandRequest {
        // None: the gateway mints the canonical UUIDv7 itself, which is what
        // makes the id in the response unforgeable evidence -- the agent
        // cannot have known it before this call.
        command_id: None,
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        agent_id: agent_id.to_owned(),
        run_id: "live-poll-run".to_owned(),
        parent_run_id: None,
        trace_id: "live-poll-trace".to_owned(),
        action: action as i32,
        reason_code: reason_code.map(str::to_owned),
        parameters: Some(prost_types::Struct::default()),
    }
}

fn stop_command(agent_id: &str) -> proto::ControlCommandRequest {
    control_command(agent_id, proto::ControlAction::Stop, Some("operator.request"))
}

/// Submits one command as a real operator over real mTLS, through the
/// already-working `SubmitCommand` RPC that none of these passes modify.
async fn submit(request: proto::ControlCommandRequest) -> proto::ControlCommandResponse {
    let mut client =
        proto::control_gateway_client::ControlGatewayClient::new(channel("control-operator-client").await);
    let mut request = tonic::Request::new(request);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", operator_token())
            .parse()
            .expect("token must be header-safe"),
    );
    client
        .submit_command(request)
        .await
        .expect("the operator must be able to submit a command")
        .into_inner()
}

async fn submit_stop(agent_id: &str) -> proto::ControlCommandResponse {
    submit(stop_command(agent_id)).await
}

/// Submits `action` and returns the `command_id` the gateway minted for it.
///
/// The id is the evidence: the agent cannot have known it before this call, so
/// an agent transcript naming it cannot be a coincidence.
async fn submit_action(
    agent_id: &str,
    action: proto::ControlAction,
    reason_code: Option<&str>,
) -> String {
    let response = submit(control_command(agent_id, action, reason_code)).await;
    assert!(!response.duplicate, "this must be a first acceptance");
    response.command_id
}

async fn poll_as(
    certificate_basename: &str,
    token_table: &str,
) -> Result<proto::PollCommandsResponse, tonic::Status> {
    let mut client =
        proto::control_gateway_client::ControlGatewayClient::new(channel(certificate_basename).await);
    let mut request = tonic::Request::new(proto::PollCommandsRequest {
        // Deliberately the maximum: if there were any way for a caller to
        // widen its own result set, asking for everything is how it would
        // show up.
        max_commands: u32::MAX,
    });
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", agent_token(token_table))
            .parse()
            .expect("token must be header-safe"),
    );
    client.poll_commands(request).await.map(|r| r.into_inner())
}

/// A running `agent_under_control.py`, with its stdout transcript streamed onto
/// a channel so the test can wait for specific lines without deadlocking on a
/// full pipe buffer.
struct AgentProcess {
    child: Child,
    lines: mpsc::Receiver<String>,
    transcript: Vec<String>,
    trace: PathBuf,
}

impl AgentProcess {
    fn spawn(agent_id: &str, certificate_basename: &str, token_table: &str) -> Self {
        let root = repo_root();
        let trace = std::env::temp_dir().join(format!(
            "apex-live-poll-{agent_id}-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&trace);
        let mut child = Command::new(python_executable())
            .arg(root.join("deploy/compose/gateway-ref/agent_under_control.py"))
            .arg("--endpoint")
            .arg(endpoint_authority())
            .arg("--secrets")
            .arg(secrets_dir())
            .arg("--agent-id")
            .arg(agent_id)
            .arg("--certificate-basename")
            .arg(certificate_basename)
            .arg("--token-file")
            .arg(token_table)
            .arg("--trace")
            .arg(&trace)
            .arg("--max-iterations")
            .arg("60")
            .arg("--interval-seconds")
            .arg("1")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("the agent process must start; set APEX_CONTROL_LIVE_PYTHON if python3 is not on PATH");
        let stdout = child.stdout.take().expect("stdout was piped");
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    return;
                }
            }
        });
        Self {
            child,
            lines,
            transcript: Vec::new(),
            trace,
        }
    }

    /// Reads transcript lines until one starts with `prefix`, or the deadline
    /// passes. Every line read is retained so a failure can print the whole
    /// transcript rather than "timed out".
    fn wait_for(&mut self, prefix: &str, within: Duration) -> Option<String> {
        let deadline = Instant::now() + within;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match self.lines.recv_timeout(remaining) {
                Ok(line) => {
                    let matched = line.starts_with(prefix);
                    self.transcript.push(line.clone());
                    if matched {
                        return Some(line);
                    }
                }
                Err(_) => return None,
            }
        }
    }

    fn drain(&mut self) {
        while let Ok(line) = self.lines.recv_timeout(Duration::from_millis(200)) {
            self.transcript.push(line);
        }
    }

    /// Reads transcript lines for exactly `window` and returns the ones read.
    ///
    /// This is how "the agent kept polling and ran nothing" becomes checkable:
    /// waiting for a line proves something happened, but only watching a whole
    /// window can prove something did *not*.
    fn collect_for(&mut self, window: Duration) -> Vec<String> {
        let deadline = Instant::now() + window;
        let mut collected = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return collected;
            }
            match self.lines.recv_timeout(remaining) {
                Ok(line) => {
                    self.transcript.push(line.clone());
                    collected.push(line);
                }
                Err(_) => return collected,
            }
        }
    }

    fn print_transcript(&self, label: &str) {
        eprintln!("--- {label} transcript ---");
        for line in &self.transcript {
            eprintln!("  {line}");
        }
        eprintln!("--- end {label} transcript ---");
    }

    fn trace_events(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(&self.trace)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }
}

impl Drop for AgentProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.trace);
    }
}

/// The headline test. Read the assertions in order: each one removes a way the
/// result could be a coincidence.
#[tokio::test]
async fn an_operator_stop_halts_a_real_agent_process() {
    if !live_enabled() {
        eprintln!("skip live control poll: set APEX_CONTROL_LIVE_POLL=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();

    let mut agent = AgentProcess::spawn(
        "reference-agent",
        "agent-workload-client",
        "control-agent-tokens-a",
    );

    // 1. The agent authenticated with its own workload credential and the
    //    gateway resolved it as itself.
    let ready = agent.wait_for("READY", Duration::from_secs(60));
    if ready.is_none() {
        agent.drain();
        agent.print_transcript("agent");
        panic!(
            "the agent never became ready; it could not poll the control gateway. \
             Its stderr is inherited above -- a ModuleNotFoundError there means the \
             SDK and its dependencies are not installed in this environment \
             (pip install -e 'packages/sdk-python[control]')."
        );
    }
    eprintln!("live proof: agent ready at {}", ready.unwrap());

    // 2. It is genuinely running turns and *not* stopping on its own. Two
    //    completed iterations before any command exists is what makes the
    //    third-iteration halt meaningful.
    for expected in 1..=2 {
        let completed = agent.wait_for(&format!("COMPLETED {expected} "), Duration::from_secs(60));
        if completed.is_none() {
            agent.drain();
            agent.print_transcript("agent");
            panic!("the agent did not complete iteration {expected} before any command was submitted");
        }
        eprintln!("live proof: {}", completed.unwrap());
    }

    // 3. A real operator submits a real stop over real mTLS, through the
    //    already-working SubmitCommand RPC.
    let submitted_at = Instant::now();
    let response = submit_stop("reference-agent").await;
    assert!(!response.duplicate, "this must be a first acceptance");
    let command_id = response.command_id.clone();
    eprintln!("live proof: operator submitted stop command_id={command_id}");

    // 4. The agent halts, and names *this* command as the reason.
    let stopped = agent.wait_for("STOPPED ", Duration::from_secs(120));
    let Some(stopped) = stopped else {
        agent.drain();
        agent.print_transcript("agent");
        panic!("the agent never halted after the stop was submitted");
    };
    let halted_after = submitted_at.elapsed();
    agent.drain();
    agent.print_transcript("agent");
    eprintln!(
        "live proof: agent halted {:.3}s after submission: {stopped}",
        halted_after.as_secs_f64()
    );

    let reported = stopped
        .split_whitespace()
        .nth(1)
        .expect("STOPPED line must carry a command_id");
    // The load-bearing assertion. The gateway minted this UUIDv7 during step
    // 3; the agent could not have produced it by coincidence, by timing out,
    // or by crashing.
    assert_eq!(
        reported, command_id,
        "the agent halted on some other command; this proves nothing about the submitted stop"
    );

    // 5. The process really exited, and exited because it enacted the stop
    //    (exit 3 is "ran out of iterations", exit 4 is "identity mismatch").
    let status = agent.child.wait().expect("the agent process must be reapable");
    assert_eq!(
        status.code(),
        Some(0),
        "the agent process must exit 0 after enacting the stop"
    );

    // 6. And the agent's own trace says so, independently of its stdout: a
    //    terminal `control` event under the agent's own actor, followed by
    //    `turn_end` naming the command.
    let events = agent.trace_events();
    assert!(!events.is_empty(), "the agent must have written a trace");
    let control = events
        .iter()
        .rev()
        .find(|event| event["type"] == "control")
        .expect("the trace must contain the enacted control event");
    assert_eq!(control["data"]["action"], "stop");
    assert_eq!(control["data"]["enforcement"], "cooperative");
    assert_eq!(control["actor"]["type"], "agent");
    let turn_end = events
        .last()
        .expect("the trace must end with a terminal event");
    assert_eq!(turn_end["type"], "turn_end");
    assert_eq!(turn_end["data"]["status"], "stopped");
    assert_eq!(turn_end["data"]["control_command_id"], command_id);

    // 7. No iteration started after the halt. A loop that kept running and
    //    merely logged a stop would fail here.
    let after_stop: Vec<&String> = agent
        .transcript
        .iter()
        .skip_while(|line| !line.starts_with("STOPPED "))
        .filter(|line| line.starts_with("ITERATION ") || line.starts_with("COMPLETED "))
        .collect();
    assert!(
        after_stop.is_empty(),
        "the agent kept working after enacting the stop: {after_stop:?}"
    );
}

/// **The live proof of `pause`/`resume`**: an operator's `pause` stops a real
/// agent process from taking any further action without killing it, and a
/// later `resume` starts it taking actions again.
///
/// Held to the same standard as the `stop` proof above. "The agent looked
/// paused" is not the claim; the claim is that the agent named *this*
/// `command_id` when it stopped acting, ran zero tool calls across a whole
/// observation window while continuing to poll, then named *that* other
/// `command_id` when it resumed and immediately completed a turn again.
///
/// It runs against its own agent identity, deliberately. The gateway's inbox
/// is at-least-once with a 30-second redelivery window, so a `stop` left over
/// from the test above would become visible again mid-run and halt this agent
/// -- which would look exactly like a pause bug.
#[tokio::test]
async fn an_operator_pause_and_resume_gate_a_real_agents_tool_calls() {
    if !live_enabled() {
        eprintln!("skip live control poll: set APEX_CONTROL_LIVE_POLL=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();

    let agent_id = "reference-agent-pause";
    let mut agent = AgentProcess::spawn(
        agent_id,
        "agent-workload-pause-client",
        "control-agent-tokens-pause",
    );

    // 1. Live, authenticated as itself.
    let ready = agent.wait_for("READY", Duration::from_secs(60));
    if ready.is_none() {
        agent.drain();
        agent.print_transcript("agent");
        panic!("the agent never became ready; it could not poll the control gateway");
    }
    eprintln!("live proof: agent ready at {}", ready.unwrap());

    // 2. Running turns under its own power, tool included.
    for expected in 1..=2 {
        let completed = agent.wait_for(&format!("COMPLETED {expected} "), Duration::from_secs(60));
        if completed.is_none() {
            agent.drain();
            agent.print_transcript("agent");
            panic!("the agent did not complete iteration {expected} before any command was submitted");
        }
        eprintln!("live proof: {}", completed.unwrap());
    }

    // 3. A real operator submits a real pause.
    let paused_at = Instant::now();
    let pause_id = submit_action(agent_id, proto::ControlAction::Pause, Some("operator.request")).await;
    eprintln!("live proof: operator submitted pause command_id={pause_id}");

    let paused = agent.wait_for("PAUSED ", Duration::from_secs(120));
    let Some(paused) = paused else {
        agent.drain();
        agent.print_transcript("agent");
        panic!("the agent never paused after the pause was submitted");
    };
    eprintln!(
        "live proof: agent paused {:.3}s after submission: {paused}",
        paused_at.elapsed().as_secs_f64()
    );
    // The load-bearing assertion, same shape as the stop proof's: the gateway
    // minted this UUIDv7 during step 3.
    assert_eq!(
        paused.split_whitespace().nth(1),
        Some(pause_id.as_str()),
        "the agent paused on some other command; this proves nothing about the submitted pause"
    );

    // 4. **It stays paused, and it stays alive.** Both halves matter: a
    //    process that exited would also stop running tools, and would also be
    //    useless to resume. Five seconds is five poll cadences.
    let window = agent.collect_for(Duration::from_secs(5));
    let acted: Vec<&String> = window
        .iter()
        .filter(|line| line.starts_with("COMPLETED ") || line.starts_with("RESUMED "))
        .collect();
    assert!(
        acted.is_empty(),
        "a paused agent executed a tool call: {acted:?}"
    );
    let still_polling = window.iter().filter(|line| line.starts_with("PAUSED ")).count();
    assert!(
        still_polling >= 2,
        "a paused agent must keep polling so a resume can reach it; saw {still_polling} paused turns in 5s: {window:?}"
    );
    assert!(
        window
            .iter()
            .filter(|line| line.starts_with("PAUSED "))
            .all(|line| line.split_whitespace().nth(1) == Some(pause_id.as_str())),
        "every paused turn must name the pause in force: {window:?}"
    );
    assert!(
        agent
            .child
            .try_wait()
            .expect("the agent process must be waitable")
            .is_none(),
        "a paused agent must still be running -- pause is not stop"
    );

    // 5. A real operator submits a real resume.
    let resumed_at = Instant::now();
    let resume_id = submit_action(agent_id, proto::ControlAction::Resume, None).await;
    eprintln!("live proof: operator submitted resume command_id={resume_id}");

    let resumed = agent.wait_for("RESUMED ", Duration::from_secs(120));
    let Some(resumed) = resumed else {
        agent.drain();
        agent.print_transcript("agent");
        panic!("the agent never resumed after the resume was submitted");
    };
    eprintln!(
        "live proof: agent resumed {:.3}s after submission: {resumed}",
        resumed_at.elapsed().as_secs_f64()
    );
    assert_eq!(
        resumed.split_whitespace().nth(1),
        Some(resume_id.as_str()),
        "the agent resumed on some other command"
    );

    // 6. And it is really working again, not merely logging that it resumed.
    let resumed_iteration: u32 = resumed
        .split_whitespace()
        .nth(2)
        .and_then(|value| value.parse().ok())
        .expect("RESUMED line must carry its iteration number");
    let completed = agent.wait_for(
        &format!("COMPLETED {resumed_iteration} "),
        Duration::from_secs(60),
    );
    agent.drain();
    agent.print_transcript("agent");
    assert!(
        completed.is_some(),
        "the resuming turn must have run its tool and completed"
    );

    // 7. The agent's own JSONL trace, read independently of its stdout.
    let events = agent.trace_events();
    let control: Vec<&serde_json::Value> = events
        .iter()
        .filter(|event| event["type"] == "control")
        .collect();
    assert_eq!(
        control
            .iter()
            .map(|event| event["data"]["action"].as_str().unwrap_or_default())
            .collect::<Vec<_>>(),
        vec!["pause", "resume"],
        "the trace must contain exactly one enacted pause and one enacted resume"
    );
    assert!(control
        .iter()
        .all(|event| event["data"]["enforcement"] == "cooperative"
            && event["actor"]["type"] == "agent"));

    // Every paused turn terminated honestly, naming the pause in force, and
    // ran no tool -- asserted against the durable trace rather than stdout.
    let paused_turns: Vec<&serde_json::Value> = events
        .iter()
        .filter(|event| event["type"] == "turn_end" && event["data"]["status"] == "paused")
        .collect();
    assert!(
        paused_turns.len() >= 2,
        "the trace must record every paused turn, not only the transition"
    );
    assert!(paused_turns
        .iter()
        .all(|event| event["data"]["control_command_id"] == pause_id));
    let paused_runs: std::collections::HashSet<&str> = paused_turns
        .iter()
        .filter_map(|event| event["run_id"].as_str())
        .collect();
    assert!(
        !events.iter().any(|event| event["type"] == "tool"
            && event["run_id"]
                .as_str()
                .is_some_and(|run| paused_runs.contains(run))),
        "a paused turn emitted a tool event"
    );

    let resumed_turn = events
        .iter()
        .find(|event| event["type"] == "turn_end" && event["data"]["status"] == "resumed")
        .expect("the trace must record the resuming turn");
    assert_eq!(resumed_turn["data"]["control_command_id"], resume_id);
    // ... and that same turn really ran its tool.
    let resumed_run = resumed_turn["run_id"].as_str().expect("run_id must be text");
    assert!(
        events
            .iter()
            .any(|event| event["type"] == "tool" && event["run_id"] == resumed_run),
        "the resuming turn must have emitted its tool event"
    );
}

/// The cross-agent isolation claim, live. Two real workloads, two real client
/// certificates, one workspace/namespace between them: agent B must not be
/// able to retrieve a command targeting agent A, and asking for the maximum
/// number of commands must not change that.
#[tokio::test]
async fn a_second_agent_workload_cannot_retrieve_the_first_ones_commands() {
    if !live_enabled() {
        eprintln!("skip live control poll: set APEX_CONTROL_LIVE_POLL=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();

    let response = submit_stop("reference-agent-isolation").await;
    let command_id = response.command_id;

    // Agent B: authenticates fine, resolves as itself, and sees nothing.
    let as_b = poll_as("agent-workload-b-client", "control-agent-tokens-b")
        .await
        .expect("agent B is a legitimate caller");
    assert_eq!(as_b.agent_id, "reference-agent-b");
    assert!(
        !as_b
            .commands
            .iter()
            .any(|command| command.command_id == command_id),
        "agent B retrieved a command targeting another agent"
    );

    // Agent A's credential presented from agent B's connection: refused. The
    // bearer credential is pinned to one client certificate, so a leaked token
    // is not by itself a way in.
    let mut client = proto::control_gateway_client::ControlGatewayClient::new(
        channel("agent-workload-b-client").await,
    );
    let mut request = tonic::Request::new(proto::PollCommandsRequest { max_commands: 0 });
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", agent_token("control-agent-tokens-a"))
            .parse()
            .unwrap(),
    );
    let status = client
        .poll_commands(request)
        .await
        .expect_err("agent A's token from agent B's certificate must be refused");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

/// ADR-0006's credential separation, carried inward to the two RPCs. Issuing a
/// command and retrieving one are different authorities.
#[tokio::test]
async fn the_operator_and_agent_credential_spaces_do_not_overlap() {
    if !live_enabled() {
        eprintln!("skip live control poll: set APEX_CONTROL_LIVE_POLL=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();

    // Operator certificate + operator token on the poll path: refused.
    let mut client = proto::control_gateway_client::ControlGatewayClient::new(
        channel("control-operator-client").await,
    );
    let mut poll = tonic::Request::new(proto::PollCommandsRequest { max_commands: 0 });
    poll.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", operator_token()).parse().unwrap(),
    );
    assert_eq!(
        client
            .poll_commands(poll)
            .await
            .expect_err("an operator credential must not be able to poll")
            .code(),
        tonic::Code::Unauthenticated
    );

    // Agent certificate + agent token on the submit path: refused.
    let mut agent_client = proto::control_gateway_client::ControlGatewayClient::new(
        channel("agent-workload-client").await,
    );
    let mut submit = tonic::Request::new(stop_command("reference-agent"));
    submit.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", agent_token("control-agent-tokens-a"))
            .parse()
            .unwrap(),
    );
    assert_eq!(
        agent_client
            .submit_command(submit)
            .await
            .expect_err("an agent credential must not be able to submit")
            .code(),
        tonic::Code::Unauthenticated
    );
}
