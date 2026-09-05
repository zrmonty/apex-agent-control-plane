//! Startup-policy tests.
//!
//! These cover the parts of process wiring that encode a security decision --
//! bind policy, credential-source ambiguity, and the bounded/path-confined
//! secret reader the TLS material goes through -- rather than the `env::var`
//! plumbing around them, which this crate's `unsafe_code = "forbid"` makes
//! structurally untestable (Rust 2024 requires `unsafe` for `env::set_var`).

use std::fs;
use std::path::{Path, PathBuf};

use super::env::{
    AgentRevocationEnv, AgentTokenSource, DEFAULT_BIND_ADDR, OperatorTokenSource,
    admission_limit_value, agent_revocation_env_value, agent_token_source_value,
    bounded_secs_value, command_retention_value, control_postgres_url_value,
    control_valkey_host_value, expected_token_typ_value, fanout_interval_value,
    global_subjects_value, inbox_scope_quota_value, metrics_bind_addr_value,
    nats_retry_attempts_value, operator_token_source_value, resolve_bind_addr_value,
};
use super::secrets::{read_bounded, read_credential_table, trusted_secret_path};

fn scratch(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "apex-control-startup-{label}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    root
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> bool {
    std::os::unix::fs::symlink(target, link).is_ok()
}

#[cfg(windows)]
fn create_symlink(target: &Path, link: &Path) -> bool {
    std::os::windows::fs::symlink_file(target, link).is_ok()
}

include!("tests/credentials.rs");
include!("tests/network.rs");
include!("tests/limits.rs");
include!("tests/secrets.rs");
include!("tests/runtime.rs");
include!("tests/browser.rs");

#[cfg(feature = "postgres")]
#[path = "tests/root_browser.rs"]
mod root_browser;

#[cfg(feature = "postgres")]
#[path = "tests/root_runtime_authority.rs"]
mod root_runtime_authority;
