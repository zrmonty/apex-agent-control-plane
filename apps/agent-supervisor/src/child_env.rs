//! Builds the supervised agent child's environment **from scratch**.
//!
//! The default behavior of `std::process::Command` is to inherit the calling
//! process's entire environment. For every other process this codebase
//! spawns, that default is fine. For this one it is not: this supervisor
//! process loads its own workload credential (see `crate::credentials`) into
//! its own environment or its own memory before spawning the agent, and that
//! credential is precisely the thing `apps/agent-supervisor`'s whole design
//! depends on the agent process never being able to read (see the crate-level
//! docs for why). Inheriting the environment by default would put it there
//! anyway, silently, the first time an operator wires a supervisor credential
//! in via an environment variable instead of a file -- which this crate does
//! not require but also cannot forbid a deployment from choosing.
//!
//! So the child's environment is built positively, not filtered negatively:
//! `main.rs` calls `std::process::Command::env_clear()` before spawning (see
//! `process_group::build_command`) and this module computes the *complete*
//! set of variables to re-add. There is no code path in this crate that
//! copies the supervisor's environment into the child wholesale, with or
//! without exclusions -- "start from everything and subtract the secret" is
//! the shape of bug this design avoids by construction, not the shape it
//! relies on getting right by enumeration.

use std::collections::BTreeMap;

/// Computes the exact environment a supervised agent child process will see.
///
/// Two inputs, both explicit, and nothing else:
///
/// - `allowlist` names variables to copy verbatim from `supervisor_env` --
///   ordinary runtime plumbing (`PATH`, `LANG`, `TZ`, and similar) that the
///   agent legitimately needs and that carries no secret of the supervisor's
///   own. A name not on this list is never copied, no matter what it is or
///   what value it holds in `supervisor_env` -- including, critically, the
///   name(s) the supervisor's own control-gateway token or key material
///   happen to be loaded under, if a deployment chose to load them from the
///   environment rather than a file.
/// - `agent_env` supplies values provisioned *specifically* for the agent --
///   its own control-plane credentials, task parameters, and so on -- from a
///   source entirely separate from the supervisor's own process environment
///   (`main.rs` reads this from an operator-provisioned file, never from
///   `std::env::vars()`). An agent-provisioned value wins over an
///   allow-listed passthrough of the same name, so an operator who
///   deliberately sets `FOO` for the agent is never silently overridden by
///   whatever the supervisor process happened to inherit for `FOO`.
///
/// The supervisor's own credential is not filtered out of the result -- it
/// is structurally not a candidate to appear in it, because it is never one
/// of this function's two inputs. `tests/credential_isolation.rs` proves this
/// holds through a real spawned process, not just through this pure
/// function's own logic.
pub fn build_child_env(
    supervisor_env: &BTreeMap<String, String>,
    allowlist: &[String],
    agent_env: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut child_env = BTreeMap::new();
    for name in allowlist {
        if let Some(value) = supervisor_env.get(name) {
            child_env.insert(name.clone(), value.clone());
        }
    }
    for (name, value) in agent_env {
        child_env.insert(name.clone(), value.clone());
    }
    child_env
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn only_allow_listed_names_are_copied_from_the_supervisor_environment() {
        let supervisor_env = map(&[
            ("PATH", "/usr/bin"),
            ("APEX_SUPERVISOR_TOKEN", "top-secret-supervisor-credential"),
            ("HOME", "/home/apex"),
        ]);
        let child = build_child_env(&supervisor_env, &["PATH".to_owned()], &BTreeMap::new());
        assert_eq!(child.get("PATH"), Some(&"/usr/bin".to_owned()));
        assert!(!child.contains_key("APEX_SUPERVISOR_TOKEN"));
        assert!(!child.contains_key("HOME"));
    }

    #[test]
    fn an_allow_listed_name_absent_from_the_supervisor_environment_is_simply_absent() {
        let child = build_child_env(&BTreeMap::new(), &["PATH".to_owned()], &BTreeMap::new());
        assert!(child.is_empty());
    }

    #[test]
    fn agent_provisioned_values_are_included_even_when_not_allow_listed() {
        let agent_env = map(&[("APEX_CONTROL_AGENT_TOKEN", "agents-own-token")]);
        let child = build_child_env(&BTreeMap::new(), &[], &agent_env);
        assert_eq!(
            child.get("APEX_CONTROL_AGENT_TOKEN"),
            Some(&"agents-own-token".to_owned())
        );
    }

    #[test]
    fn agent_provisioned_values_win_over_an_allow_listed_passthrough_of_the_same_name() {
        let supervisor_env = map(&[("FOO", "from-supervisor-environment")]);
        let agent_env = map(&[("FOO", "deliberately-provisioned-for-the-agent")]);
        let child = build_child_env(&supervisor_env, &["FOO".to_owned()], &agent_env);
        assert_eq!(
            child.get("FOO"),
            Some(&"deliberately-provisioned-for-the-agent".to_owned())
        );
    }

    #[test]
    fn an_empty_allowlist_and_empty_agent_env_produce_a_completely_empty_child_environment() {
        let supervisor_env = map(&[
            ("PATH", "/usr/bin"),
            ("APEX_SUPERVISOR_TOKEN", "top-secret"),
            ("SSH_AUTH_SOCK", "/tmp/ssh"),
        ]);
        let child = build_child_env(&supervisor_env, &[], &BTreeMap::new());
        assert!(
            child.is_empty(),
            "with nothing allow-listed and nothing agent-provisioned, the child gets nothing"
        );
    }
}
