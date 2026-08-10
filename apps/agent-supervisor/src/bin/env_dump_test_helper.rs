//! Test-only helper binary: prints this process's own environment, one
//! `KEY=VALUE` line per variable, to stdout, and exits immediately.
//!
//! Exists so `tests/credential_isolation.rs` can assert what a *real* spawned
//! child process observes, rather than trusting `crate::child_env`'s pure
//! function alone -- the whole point of that test is that nothing between
//! "build the intended environment" and "the child process's own view of its
//! environment" leaked the supervisor's credential back in (an `env_clear()`
//! that silently didn't take effect, a shell wrapper re-exporting the parent
//! environment, and so on). Never built into the release binary; not
//! referenced by `main.rs`.

fn main() {
    for (key, value) in std::env::vars() {
        println!("{key}={value}");
    }
}
