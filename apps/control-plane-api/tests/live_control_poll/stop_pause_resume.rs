//! The live proofs of `stop` and `pause`/`resume`.

use std::time::{Duration, Instant};

use apex_control_plane_api::proto;

use super::support::*;

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
