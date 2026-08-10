//! Process wiring for `apps/agent-supervisor`. See `src/lib.rs` for what this
//! binary is and why it exists.
//!
//! Pure process-wiring code, deliberately not unit tested here -- the same
//! carve-out `apps/event-ingest`/`apps/control-plane-api`'s own `main.rs`/
//! `startup/service.rs` take (see `CLAUDE.md`'s coverage note): every branch
//! below is env parsing, file loading, or wiring already-tested components
//! together, and the properties that actually matter (credential isolation,
//! process-group termination) are proven directly against real spawned
//! processes in `tests/`.

use std::collections::BTreeMap;
use std::process::ExitCode;

use apex_agent_supervisor::config::SupervisorConfig;
use apex_agent_supervisor::control_client::ControlClient;
use apex_agent_supervisor::credentials::{SupervisorCredentials, confine_to_base};
use apex_agent_supervisor::proto;
use apex_agent_supervisor::{child_env, config, process_group};

/// Exit code this process uses when it force-stopped its own supervised
/// agent. Distinct from the agent's own exit codes (which this process
/// forwards verbatim when the agent exits on its own) so an orchestrator
/// restarting this container can tell "the agent finished/crashed" apart
/// from "an operator force-stopped it" from the exit code alone, without
/// having to correlate against the control-plane trace.
const EXIT_CODE_FORCE_STOPPED: u8 = 137; // 128 + SIGKILL(9), the conventional shell/container meaning.

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("apex-agent-supervisor: failed to start the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(run())
}

async fn run() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let Some((program, agent_args)) = config::split_agent_argv(&args) else {
        eprintln!(
            "apex-agent-supervisor: usage: apex-agent-supervisor -- <agent program> [agent args...]"
        );
        return ExitCode::FAILURE;
    };
    let agent_args: Vec<String> = agent_args.to_vec();

    let config = match SupervisorConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("apex-agent-supervisor: configuration error: {error}");
            return ExitCode::FAILURE;
        }
    };

    let (server_ca_file, client_cert_file, client_key_file, token_file) = match confine_all(&config) {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("apex-agent-supervisor: {error}");
            return ExitCode::FAILURE;
        }
    };

    let credentials = match SupervisorCredentials::load(&server_ca_file, &client_cert_file, &client_key_file, &token_file) {
        Ok(credentials) => credentials,
        Err(error) => {
            eprintln!("apex-agent-supervisor: {error}");
            return ExitCode::FAILURE;
        }
    };

    let agent_env = match load_agent_env(&config) {
        Ok(env) => env,
        Err(error) => {
            eprintln!("apex-agent-supervisor: {error}");
            return ExitCode::FAILURE;
        }
    };

    // The supervisor's own environment is read *only* here, and only for the
    // explicitly allow-listed names -- never as a wholesale source for the
    // child. See `child_env::build_child_env`'s doc comment.
    let supervisor_env: BTreeMap<String, String> = std::env::vars().collect();
    let child_environment = child_env::build_child_env(&supervisor_env, &config.agent_env_allowlist, &agent_env);

    let mut child = match process_group::spawn(program, &agent_args, &child_environment) {
        Ok(child) => child,
        Err(error) => {
            eprintln!("apex-agent-supervisor: failed to spawn the agent process: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "apex-agent-supervisor: spawned agent pid={} program={program:?}",
        child.id().unwrap_or_default()
    );

    let mut control = match ControlClient::connect(
        &config.control_endpoint,
        &credentials.server_ca_pem,
        &credentials.client_cert_pem,
        &credentials.client_key_pem,
        &credentials.token,
    )
    .await
    {
        Ok(control) => control,
        Err(error) => {
            eprintln!(
                "apex-agent-supervisor: could not connect to the control gateway ({error}); supervising without a force_stop channel"
            );
            // A control-plane outage must not prevent the agent itself from
            // running -- the same "degraded but not blocked" principle
            // ADR-0006 already applies to the cooperative channel. This
            // process still supervises the child (and still forwards its
            // eventual exit code); it just cannot receive `force_stop` until
            // a connection succeeds, which the retry loop below keeps
            // attempting.
            return supervise_without_control(child).await;
        }
    };

    supervise(&mut child, &mut control, config.poll_interval).await
}

fn confine_all(
    config: &SupervisorConfig,
) -> Result<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf, std::path::PathBuf), String> {
    let confine = |path: &std::path::Path| {
        confine_to_base(path, &config.trusted_secret_base).map_err(|error| error.to_string())
    };
    Ok((
        confine(&config.server_ca_file)?,
        confine(&config.client_cert_file)?,
        confine(&config.client_key_file)?,
        confine(&config.token_file)?,
    ))
}

fn load_agent_env(config: &SupervisorConfig) -> Result<BTreeMap<String, String>, String> {
    let Some(path) = &config.agent_env_file else {
        return Ok(BTreeMap::new());
    };
    let confined = confine_to_base(path, &config.trusted_secret_base).map_err(|error| error.to_string())?;
    let raw = std::fs::read_to_string(&confined)
        .map_err(|_| "APEX_SUPERVISOR_AGENT_ENV_FILE could not be read".to_owned())?;
    config::parse_agent_env_file(&raw).map_err(|error| error.to_string())
}

async fn supervise_without_control(mut child: process_group::SupervisedChild) -> ExitCode {
    match child.wait().await {
        Ok(status) => exit_code_for(status),
        Err(error) => {
            eprintln!("apex-agent-supervisor: failed to wait on the agent process: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The main supervision loop: race the agent's own exit against the next
/// poll tick. A `force_stop` received on a tick kills the whole process
/// group immediately and acknowledges the command; any other action
/// reaching this identity is logged and acknowledged away without being
/// enacted -- this supervisor enacts exactly one action, deliberately.
async fn supervise(
    child: &mut process_group::SupervisedChild,
    control: &mut ControlClient,
    poll_interval: std::time::Duration,
) -> ExitCode {
    let mut ticker = tokio::time::interval(poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            status = child.wait() => {
                return match status {
                    Ok(status) => exit_code_for(status),
                    Err(error) => {
                        eprintln!("apex-agent-supervisor: failed to wait on the agent process: {error}");
                        ExitCode::FAILURE
                    }
                };
            }
            _ = ticker.tick() => {
                match control.poll(0).await {
                    Ok(response) => {
                        if let Some(exit) = handle_poll_response(child, control, response).await {
                            return exit;
                        }
                    }
                    Err(error) => {
                        eprintln!("apex-agent-supervisor: poll failed, will retry: {error}");
                    }
                }
            }
        }
    }
}

/// Returns `Some(exit_code)` when a `force_stop` was enacted and this process
/// should exit; `None` to keep supervising.
async fn handle_poll_response(
    child: &mut process_group::SupervisedChild,
    control: &mut ControlClient,
    response: proto::PollCommandsResponse,
) -> Option<ExitCode> {
    for command in &response.commands {
        if command.action == proto::ControlAction::ForceStop as i32 {
            eprintln!(
                "apex-agent-supervisor: force_stop received (command_id={}); killing the agent's process group",
                command.command_id
            );
            if let Err(error) = child.terminate_tree() {
                eprintln!("apex-agent-supervisor: terminate_tree failed: {error}");
            }
            // Best-effort: the gateway's own redelivery already covers a
            // lost ack (see `apps/control-plane-api/src/inbox.rs`), so a
            // failed ack here does not leave the kill un-enacted, only
            // un-acknowledged until redelivery.
            let _ = control.ack(command).await;
            return Some(ExitCode::from(EXIT_CODE_FORCE_STOPPED));
        }
        // Any other action reaching this identity is unexpected -- an
        // operator should target the *agent's* own identity for cooperative
        // controls, never the supervisor's -- but acknowledging it away
        // (without enacting it) keeps a misdirected command from being
        // redelivered forever rather than pretending it was handled.
        eprintln!(
            "apex-agent-supervisor: ignoring unexpected action {} for the supervisor's own identity (command_id={})",
            command.action, command.command_id
        );
        let _ = control.ack(command).await;
    }
    None
}

#[cfg(unix)]
fn exit_code_for(status: std::process::ExitStatus) -> ExitCode {
    use std::os::unix::process::ExitStatusExt;
    match status.code() {
        Some(code) => ExitCode::from(code as u8),
        None => ExitCode::from(128u8.saturating_add(status.signal().unwrap_or(0) as u8)),
    }
}

#[cfg(not(unix))]
fn exit_code_for(status: std::process::ExitStatus) -> ExitCode {
    ExitCode::from(status.code().unwrap_or(1) as u8)
}
