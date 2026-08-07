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
//! - `APEX_CONTROL_POSTGRES_URL` -- selects the multi-writer Postgres outbox
//!   instead of the single-writer file outbox above. Requires a binary built
//!   with `--features postgres`; setting it without that is a hard startup
//!   error rather than a silent downgrade to the file backend. **It must
//!   resolve to a database or schema of the control gateway's own.**
//!   `apex_event_ingest::PostgresOutbox` hardcodes the `apex_event_outbox`
//!   table name, so pointing both services at one database gives them one
//!   outbox table -- where each service's replay worker would claim the
//!   other's rows (`FOR UPDATE SKIP LOCKED`) and republish them through its
//!   own sinks. Give it a separate database, or a separate schema via
//!   `?options=-c%20search_path%3Dapex_control`. Setting `APEX_POSTGRES_URL`
//!   (event-ingest's variable) on this process is refused for the same
//!   reason. This is the Postgres equivalent of the separate `control-outbox`
//!   volume the file backend already gets.
//! - `APEX_CONTROL_NATS_URL` / `APEX_CONTROL_NATS_CA_FILE` /
//!   `APEX_CONTROL_NATS_CLIENT_CERT_FILE` / `APEX_CONTROL_NATS_CLIENT_KEY_FILE`
//!   / `APEX_CONTROL_NATS_USERNAME_FILE` / `APEX_CONTROL_NATS_PASSWORD_FILE`
//!   -- the JetStream client the background fanout worker publishes accepted
//!   commands through, so a `control` event actually reaches the queryable
//!   trace. Its own NATS client identity, not the ingest gateway's, for the
//!   same reason it has its own TLS material and its own operator credential
//!   table. The URL is optional: unset means no fanout, and the process says
//!   so loudly on stderr, because commands would then be durably recorded and
//!   never delivered. Once the URL is set the three TLS paths are required;
//!   username/password are both-or-neither. Configuration is validated at
//!   startup, but the **connection is not**: an unreachable broker must never
//!   stop this gateway from starting or from accepting commands (ADR-0006).
//! - `APEX_CONTROL_FANOUT_INTERVAL_SECS` -- fanout tick, default 5 (1..=3600).
//!   See `startup::env::DEFAULT_FANOUT_INTERVAL_SECS` for why 5.
//! - `APEX_CONTROL_NATS_RETRY_ATTEMPTS` -- bounded publish retry ladder,
//!   default 3 (1..=8), mirroring event-ingest's `APEX_RETRY_ATTEMPTS`.
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

/// Deliberately **not** `#[tokio::main]`, matching `apps/event-ingest`'s own
/// `main`. `startup::run` constructs clients that own an internal runtime and
/// `block_on` it -- `PostgresOutbox::connect` is one -- and those panic with
/// "Cannot start a runtime from within a runtime" on a thread that already
/// has one entered. `run` builds the serving runtime itself, after
/// construction is complete.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Must run before any TLS client or server is constructed, including the
    // `ServerTlsConfig` built during startup.
    apex_control_plane_api::install_rustls_provider();
    startup::run()
}
