//! **The most important test in this feature.** Proves, against a real
//! spawned OS process (not the pure `child_env::build_child_env` function in
//! isolation, and not a mock), that the supervisor's own credential value
//! never appears in the spawned agent's observed environment -- while a
//! legitimately allow-listed passthrough and an agent-provisioned value both
//! actually arrive, so the property under test is "isolated", not merely
//! "broken".
//!
//! This is the property the whole feature depends on: if a fully compromised
//! agent process could read the supervisor's credential out of its own
//! environment, it could poll-and-ack its own `force_stop` exactly the way
//! `OOB Control Gateway — Command Delivery Gap` describes for the cooperative
//! `stop`, and this crate would add OS kill authority to the system without
//! adding the one thing that makes it trustworthy.
//!
//! Cross-platform: `process_group::spawn_with_stdio` and the
//! `env_dump_test_helper` binary both work identically on Unix and Windows,
//! so this test runs and proves something on every platform this crate
//! builds for -- unlike the process-group *tree*-kill proof in
//! `tests/process_group_kill.rs`, which is inherently POSIX-specific.

use std::collections::BTreeMap;
use std::process::Stdio;
use std::time::Duration;

use apex_agent_supervisor::{child_env, process_group};

#[tokio::test]
async fn a_spawned_agent_never_observes_the_supervisors_credential() {
    let mut supervisor_env = BTreeMap::new();
    supervisor_env.insert(
        "APEX_SUPERVISOR_TOKEN".to_owned(),
        "top-secret-supervisor-credential-9f3a1c".to_owned(),
    );
    supervisor_env.insert(
        "APEX_TEST_ALLOWLISTED".to_owned(),
        "should-be-forwarded".to_owned(),
    );
    supervisor_env.insert(
        "APEX_TEST_NOT_ALLOWLISTED".to_owned(),
        "should-never-appear".to_owned(),
    );

    let allowlist = vec!["APEX_TEST_ALLOWLISTED".to_owned()];

    let mut agent_env = BTreeMap::new();
    agent_env.insert(
        "APEX_CONTROL_AGENT_TOKEN".to_owned(),
        "agents-own-legitimate-token".to_owned(),
    );

    let child_environment = child_env::build_child_env(&supervisor_env, &allowlist, &agent_env);

    let helper = env!("CARGO_BIN_EXE_env_dump_test_helper");
    let mut child = process_group::spawn_with_stdio(
        helper,
        &[],
        &child_environment,
        Stdio::null(),
        Stdio::piped(),
        Stdio::inherit(),
    )
    .expect("spawning the env-dump test helper must succeed");

    let stdout = process_group::take_stdout(&mut child).expect("stdout must be piped");
    let output = read_all(stdout).await;
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("the helper process must exit promptly")
        .expect("waiting on the helper process must succeed");
    assert!(status.success(), "the env-dump helper must exit successfully");

    // The property this whole feature exists for.
    assert!(
        !output.contains("top-secret-supervisor-credential-9f3a1c"),
        "the supervisor's credential VALUE leaked into the spawned agent's observed environment:\n{output}"
    );
    assert!(
        !output.contains("APEX_SUPERVISOR_TOKEN="),
        "the supervisor's credential NAME leaked into the spawned agent's observed environment:\n{output}"
    );
    // A name the operator never allow-listed does not appear either, even
    // though the supervisor's own process had it set.
    assert!(!output.contains("APEX_TEST_NOT_ALLOWLISTED"));
    assert!(!output.contains("should-never-appear"));

    // Not a case of blocking everything: an explicit allow-listed
    // passthrough and an agent-provisioned value both actually arrive.
    assert!(
        output.contains("APEX_TEST_ALLOWLISTED=should-be-forwarded"),
        "an allow-listed variable must still reach the child:\n{output}"
    );
    assert!(
        output.contains("APEX_CONTROL_AGENT_TOKEN=agents-own-legitimate-token"),
        "an agent-provisioned variable must still reach the child:\n{output}"
    );
}

async fn read_all(mut stdout: tokio::process::ChildStdout) -> String {
    use tokio::io::AsyncReadExt;
    let mut buffer = String::new();
    tokio::time::timeout(Duration::from_secs(10), stdout.read_to_string(&mut buffer))
        .await
        .expect("reading the helper's stdout must not hang")
        .expect("reading the helper's stdout must succeed");
    buffer
}
