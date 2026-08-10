//! Configuration parsing.
//!
//! Split into pure, unit-testable `_value` functions taking already-read
//! input, plus a thin `from_env()`/CLI-reading wrapper that is not unit
//! tested directly -- the same pattern this repository's
//! `apps/event-ingest`/`apps/control-plane-api` `startup/env.rs` modules use
//! and for the same reason (`CLAUDE.md`'s own note on it): this workspace
//! forbids `unsafe_code`, and Rust 2024 requires `unsafe` to call
//! `std::env::set_var`/`remove_var`, so a test cannot set up an env var to
//! read back. Refactoring the parsing logic to take a plain `&str`/`Option<&str>`
//! rather than reading the environment itself is what keeps it testable
//! without that.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_POLL_INTERVAL_SECS: u64 = 2;
const MAX_POLL_INTERVAL_SECS: u64 = 60;
const MAX_AGENT_ENV_FILE_BYTES: usize = 256 * 1024;
const MAX_AGENT_ENV_ENTRIES: usize = 512;

/// Parses `APEX_SUPERVISOR_AGENT_ENV_ALLOWLIST`: a comma-separated list of
/// environment variable *names* (never values) to copy verbatim from this
/// supervisor process's own environment into the spawned agent's. See
/// `crate::child_env` for why this is additive-only, never a filter over the
/// supervisor's full environment.
pub fn parse_allowlist(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentEnvFileError {
    pub line_number: usize,
    pub reason: &'static str,
}

impl std::fmt::Display for AgentEnvFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "agent env file line {}: {}",
            self.line_number, self.reason
        )
    }
}

impl std::error::Error for AgentEnvFileError {}

/// Parses the operator-provisioned `KEY=VALUE` file naming exactly what the
/// agent needs (its own control-plane credentials, task parameters, and so
/// on). One entry per line; `#`-prefixed and blank lines are ignored. Every
/// malformed line is a hard error -- silently skipping one would leave the
/// agent missing a variable it needs while the supervisor still starts and
/// reports healthy, the same failure shape
/// `apps/control-plane-api/src/agent_auth.rs::parse_agent_token_table`
/// already refuses to allow for its own credential table.
///
/// This file is read directly by `main.rs`, never merged with or derived
/// from this supervisor process's own environment (see `crate::child_env`).
pub fn parse_agent_env_file(raw: &str) -> Result<BTreeMap<String, String>, AgentEnvFileError> {
    let mut env = BTreeMap::new();
    if raw.len() > MAX_AGENT_ENV_FILE_BYTES {
        return Err(AgentEnvFileError {
            line_number: 0,
            reason: "the agent env file is larger than this supervisor accepts",
        });
    }
    for (index, line) in raw.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            return Err(AgentEnvFileError {
                line_number,
                reason: "expected KEY=VALUE",
            });
        };
        let key = key.trim();
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || key.as_bytes()[0].is_ascii_digit()
        {
            return Err(AgentEnvFileError {
                line_number,
                reason: "the variable name must be a non-empty run of ASCII letters, digits, and underscores, and must not start with a digit",
            });
        }
        if env.len() >= MAX_AGENT_ENV_ENTRIES && !env.contains_key(key) {
            return Err(AgentEnvFileError {
                line_number,
                reason: "too many agent env entries",
            });
        }
        env.insert(key.to_owned(), value.to_owned());
    }
    Ok(env)
}

/// Resolves `APEX_SUPERVISOR_POLL_INTERVAL_SECONDS`: a positive integer,
/// clamped to a sane ceiling, defaulting when unset or unparsable rather than
/// refusing to start over a cosmetic misconfiguration.
pub fn poll_interval_value(raw: Option<&str>) -> Duration {
    let secs = raw
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_POLL_INTERVAL_SECS);
    Duration::from_secs(secs.min(MAX_POLL_INTERVAL_SECS))
}

/// Splits this process's own CLI arguments into "everything before `--`"
/// (this supervisor's own flags -- currently unused, reserved) and "the
/// agent's own program and argv" (everything after `--`). Returns `None`
/// when there is no `--` or nothing follows it: a supervisor with nothing to
/// supervise is a configuration error, not a default.
pub fn split_agent_argv(args: &[String]) -> Option<(&str, &[String])> {
    let separator = args.iter().position(|arg| arg == "--")?;
    let rest = &args[separator + 1..];
    let (program, argv) = rest.split_first()?;
    Some((program.as_str(), argv))
}

/// Everything this binary needs, loaded once at startup.
pub struct SupervisorConfig {
    pub control_endpoint: String,
    pub server_ca_file: PathBuf,
    pub client_cert_file: PathBuf,
    pub client_key_file: PathBuf,
    pub token_file: PathBuf,
    pub trusted_secret_base: PathBuf,
    pub agent_env_allowlist: Vec<String>,
    pub agent_env_file: Option<PathBuf>,
    pub poll_interval: Duration,
}

fn required_env(name: &'static str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is required and was not set"))
}

impl SupervisorConfig {
    /// Reads every `APEX_SUPERVISOR_*` variable this binary uses. Not unit
    /// tested directly for the reason this module's own doc comment gives;
    /// every branch here is a thin `env::var` read, and the actual parsing
    /// logic it calls into (`parse_allowlist`, `poll_interval_value`) is
    /// tested above.
    pub fn from_env() -> Result<Self, String> {
        let poll_interval = poll_interval_value(std::env::var("APEX_SUPERVISOR_POLL_INTERVAL_SECONDS").ok().as_deref());
        let agent_env_allowlist = std::env::var("APEX_SUPERVISOR_AGENT_ENV_ALLOWLIST")
            .ok()
            .map(|raw| parse_allowlist(&raw))
            .unwrap_or_default();
        Ok(Self {
            control_endpoint: required_env("APEX_SUPERVISOR_CONTROL_ENDPOINT")?,
            server_ca_file: PathBuf::from(required_env("APEX_SUPERVISOR_SERVER_CA_FILE")?),
            client_cert_file: PathBuf::from(required_env("APEX_SUPERVISOR_CLIENT_CERT_FILE")?),
            client_key_file: PathBuf::from(required_env("APEX_SUPERVISOR_CLIENT_KEY_FILE")?),
            // Deliberately file-only -- unlike the operator/agent token
            // tables elsewhere in this project, which also accept an inline
            // environment-variable form for lab/CI convenience -- there is
            // no `APEX_SUPERVISOR_TOKEN` inline variant. This is the one
            // credential in the system that must never be readable from a
            // process's own environment even in principle, and an inline
            // env var is exactly the shape that risk takes.
            token_file: PathBuf::from(required_env("APEX_SUPERVISOR_TOKEN_FILE")?),
            trusted_secret_base: PathBuf::from(required_env("APEX_SUPERVISOR_TRUSTED_SECRET_BASE")?),
            agent_env_allowlist,
            agent_env_file: std::env::var("APEX_SUPERVISOR_AGENT_ENV_FILE").ok().map(PathBuf::from),
            poll_interval,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_allowlist_trims_and_drops_empty_entries() {
        assert_eq!(
            parse_allowlist(" PATH , LANG,, TZ "),
            vec!["PATH".to_owned(), "LANG".to_owned(), "TZ".to_owned()]
        );
        assert!(parse_allowlist("").is_empty());
    }

    #[test]
    fn parse_agent_env_file_reads_key_value_lines_and_skips_comments_and_blanks() {
        let raw = "# comment\n\nAPEX_CONTROL_AGENT_TOKEN=abc123\nAGENT_NAME=my-agent\n";
        let env = parse_agent_env_file(raw).unwrap();
        assert_eq!(env.get("APEX_CONTROL_AGENT_TOKEN"), Some(&"abc123".to_owned()));
        assert_eq!(env.get("AGENT_NAME"), Some(&"my-agent".to_owned()));
        assert_eq!(env.len(), 2);
    }

    #[test]
    fn parse_agent_env_file_allows_an_equals_sign_inside_the_value() {
        let env = parse_agent_env_file("QUERY=a=b=c\n").unwrap();
        assert_eq!(env.get("QUERY"), Some(&"a=b=c".to_owned()));
    }

    #[test]
    fn parse_agent_env_file_rejects_a_line_without_an_equals_sign() {
        assert!(parse_agent_env_file("NOT_KEY_VALUE\n").is_err());
    }

    #[test]
    fn parse_agent_env_file_rejects_an_invalid_variable_name() {
        assert!(parse_agent_env_file("has space=value\n").is_err());
        assert!(parse_agent_env_file("1STARTSWITHDIGIT=value\n").is_err());
        assert!(parse_agent_env_file("=novariablename\n").is_err());
    }

    #[test]
    fn poll_interval_value_defaults_and_clamps() {
        assert_eq!(poll_interval_value(None), Duration::from_secs(2));
        assert_eq!(poll_interval_value(Some("not-a-number")), Duration::from_secs(2));
        assert_eq!(poll_interval_value(Some("0")), Duration::from_secs(2));
        assert_eq!(poll_interval_value(Some("5")), Duration::from_secs(5));
        assert_eq!(poll_interval_value(Some("999999")), Duration::from_secs(60));
    }

    #[test]
    fn split_agent_argv_finds_the_separator() {
        let args: Vec<String> = ["apex-agent-supervisor", "--", "python3", "agent.py", "--flag"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let (program, argv) = split_agent_argv(&args).expect("must find the separator");
        assert_eq!(program, "python3");
        assert_eq!(argv, ["agent.py".to_owned(), "--flag".to_owned()]);
    }

    #[test]
    fn split_agent_argv_requires_a_program_after_the_separator() {
        let args: Vec<String> = ["apex-agent-supervisor", "--"].into_iter().map(str::to_owned).collect();
        assert!(split_agent_argv(&args).is_none());
    }

    #[test]
    fn split_agent_argv_requires_the_separator_to_be_present() {
        let args: Vec<String> = ["apex-agent-supervisor", "python3", "agent.py"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert!(split_agent_argv(&args).is_none());
    }
}
