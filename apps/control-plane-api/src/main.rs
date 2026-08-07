//! Runnable OOB control gateway binary.
//!
//! Configuration is environment-driven, matching `apps/event-ingest`'s
//! convention:
//!
//! - `APEX_CONTROL_BIND_ADDR` -- listen address (default `127.0.0.1:9443`).
//!   Binding anything other than a loopback address additionally requires
//!   `APEX_CONTROL_ALLOW_NONLOCAL_BIND=true`. This is now a defence-in-depth
//!   acknowledgement rather than a plaintext mitigation -- see
//!   `startup::env::resolve_bind_addr_value` for why it was kept after native
//!   TLS landed. It mirrors the `APEX_ALLOW_NONLOCAL_INGEST_BIND` gate the
//!   Compose preflight already applies to the ingest gateway.
//! - `APEX_CONTROL_TRUSTED_SECRET_BASE` -- required. Every secret path below
//!   must canonicalize inside this directory, so a tampered env var cannot
//!   point the process at arbitrary host files.
//! - `APEX_CONTROL_SERVER_CERT_FILE` / `APEX_CONTROL_SERVER_KEY_FILE` /
//!   `APEX_CONTROL_CLIENT_CA_FILE` -- required mTLS material. See "Transport
//!   security" below.
//! - `APEX_CONTROL_OUTBOX_BASE` / `APEX_CONTROL_OUTBOX_FILE` -- durable file
//!   outbox location (defaults under `./data/control-outbox`). This is a
//!   distinct outbox file from event-ingest's, by design: the two services
//!   must not share a durability boundary any more than they share auth.
//! - `APEX_CONTROL_OPERATOR_TOKENS_FILE` (production) or
//!   `APEX_CONTROL_OPERATOR_TOKENS` (local/lab, CI) -- operator credential
//!   table: `token1|workspace/ns[,workspace/ns...];token2|*;...`. `*` grants
//!   a global (break-glass) operator scope. The token and its scopes are
//!   separated by `|`, not `:`, so a token containing a colon cannot be
//!   silently truncated into a shorter credential (see
//!   `auth::parse_operator_token_table`). A malformed entry aborts startup
//!   rather than being skipped. Setting both variables is refused. This is
//!   deliberately a distinct credential space from event-ingest's ingest
//!   bearer tokens -- per [[Authentication and Identity]] the production path
//!   is a short-lived Keycloak-issued operator credential exchanged in front
//!   of this process; this static table is the local/lab and CI seam for that.
//!
//! Transport security: this binary terminates mTLS natively via
//! `tonic::transport::ServerTlsConfig`, presenting its own server identity
//! and requiring a client certificate that chains to
//! `APEX_CONTROL_CLIENT_CA_FILE`. TLS is **mandatory** -- there is no
//! plaintext or optional-client-auth mode, matching `event-ingest`, which has
//! no such fallback either. A deployment that wants a terminating proxy in
//! front of this process still gets one; it simply speaks mTLS to the process
//! behind it rather than plaintext.

mod startup;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Must run before any TLS client or server is constructed, including the
    // `ServerTlsConfig` built during startup.
    apex_control_plane_api::install_rustls_provider();
    startup::run().await
}
