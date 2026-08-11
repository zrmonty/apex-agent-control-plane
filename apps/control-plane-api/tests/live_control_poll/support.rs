use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use apex_control_plane_api::proto;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

pub(crate) fn live_enabled() -> bool {
    std::env::var("APEX_CONTROL_LIVE_POLL").ok().as_deref() == Some("1")
}

pub(crate) fn endpoint_url() -> String {
    std::env::var("APEX_CONTROL_LIVE_ENDPOINT")
        .unwrap_or_else(|_| "https://localhost:18446".to_owned())
}

/// `host:port` form for the Python client, which takes a bare authority rather
/// than a URL (see `GrpcControlTransport`'s refusal of a scheme).
pub(crate) fn endpoint_authority() -> String {
    endpoint_url()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_owned()
}

pub(crate) fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root must resolve")
}

pub(crate) fn secrets_dir() -> PathBuf {
    if let Ok(path) = std::env::var("APEX_CONTROL_LIVE_SECRETS") {
        return PathBuf::from(path);
    }
    repo_root().join("deploy/compose/live-mtls/secrets-host")
}

pub(crate) fn python_executable() -> String {
    std::env::var("APEX_CONTROL_LIVE_PYTHON").unwrap_or_else(|_| "python3".to_owned())
}

pub(crate) fn require_secret(name: &str) -> Vec<u8> {
    let path = secrets_dir().join(name);
    assert!(
        path.is_file(),
        "missing live-mTLS fixture {name} under {}; run generate_pki.py",
        secrets_dir().display()
    );
    std::fs::read(&path).expect("fixture must be readable")
}

/// Splits `token|...` from the right, the way both credential-table parsers do.
pub(crate) fn table_token(name: &str, fields_to_the_right: usize) -> String {
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

pub(crate) fn operator_token() -> String {
    table_token("control-operator-tokens", 1)
}

pub(crate) fn agent_token(table: &str) -> String {
    table_token(table, 3)
}

pub(crate) fn tls_config(identity: Identity) -> ClientTlsConfig {
    ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(require_secret("ca.pem")))
        .domain_name("localhost")
        .identity(identity)
}

pub(crate) fn identity(basename: &str) -> Identity {
    Identity::from_pem(
        require_secret(&format!("{basename}.pem")),
        require_secret(&format!("{basename}.key")),
    )
}

pub(crate) async fn channel(basename: &str) -> tonic::transport::Channel {
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

pub(crate) fn control_command(
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

pub(crate) fn stop_command(agent_id: &str) -> proto::ControlCommandRequest {
    control_command(agent_id, proto::ControlAction::Stop, Some("operator.request"))
}

/// Submits one command as a real operator over real mTLS, through the
/// already-working `SubmitCommand` RPC that none of these passes modify.
pub(crate) async fn submit(request: proto::ControlCommandRequest) -> proto::ControlCommandResponse {
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

pub(crate) async fn submit_stop(agent_id: &str) -> proto::ControlCommandResponse {
    submit(stop_command(agent_id)).await
}

/// Submits `action` and returns the `command_id` the gateway minted for it.
///
/// The id is the evidence: the agent cannot have known it before this call, so
/// an agent transcript naming it cannot be a coincidence.
pub(crate) async fn submit_action(
    agent_id: &str,
    action: proto::ControlAction,
    reason_code: Option<&str>,
) -> String {
    let response = submit(control_command(agent_id, action, reason_code)).await;
    assert!(!response.duplicate, "this must be a first acceptance");
    response.command_id
}

pub(crate) async fn poll_as(
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
pub(crate) struct AgentProcess {
    pub(crate) child: Child,
    lines: mpsc::Receiver<String>,
    pub(crate) transcript: Vec<String>,
    trace: PathBuf,
}

impl AgentProcess {
    pub(crate) fn spawn(agent_id: &str, certificate_basename: &str, token_table: &str) -> Self {
        Self::spawn_with(agent_id, certificate_basename, token_table, &[])
    }

    /// `extra` is appended verbatim, for proofs that need the harness
    /// configured (a non-zero synthetic per-turn cost, for instance).
    pub(crate) fn spawn_with(
        agent_id: &str,
        certificate_basename: &str,
        token_table: &str,
        extra: &[&str],
    ) -> Self {
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
            .args(extra)
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
    pub(crate) fn wait_for(&mut self, prefix: &str, within: Duration) -> Option<String> {
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

    pub(crate) fn drain(&mut self) {
        while let Ok(line) = self.lines.recv_timeout(Duration::from_millis(200)) {
            self.transcript.push(line);
        }
    }

    /// Reads transcript lines for exactly `window` and returns the ones read.
    ///
    /// This is how "the agent kept polling and ran nothing" becomes checkable:
    /// waiting for a line proves something happened, but only watching a whole
    /// window can prove something did *not*.
    pub(crate) fn collect_for(&mut self, window: Duration) -> Vec<String> {
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

    pub(crate) fn print_transcript(&self, label: &str) {
        eprintln!("--- {label} transcript ---");
        for line in &self.transcript {
            eprintln!("  {line}");
        }
        eprintln!("--- end {label} transcript ---");
    }

    pub(crate) fn trace_events(&self) -> Vec<serde_json::Value> {
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
