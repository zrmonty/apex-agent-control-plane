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
//!   and shared command inbox instead of the single-writer file stores above. Requires a binary built
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
//! - `APEX_CONTROL_POSTGRES_POOL_SIZE` -- bounded number of independent
//!   synchronous Postgres outbox connections, default 4 (1..=16). Each
//!   connection owns its own client runtime so submissions, replay, retention,
//!   and reconciliation can make progress concurrently.
//! - `APEX_CONTROL_METRICS_ADDR` -- optional loopback-only Prometheus text
//!   endpoint (for example `127.0.0.1:9943`) exposing counters and health
//!   gauges without adding a remote control surface.
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
//! - `APEX_CONTROL_COMMAND_RETENTION_SECS` -- settled command-id retention,
//!   default 30 days (3600..=31536000). Reusing a command_id is rejected
//!   during this window and allowed after it expires.
//! - `APEX_CONTROL_INBOX_MAX_COMMANDS_PER_SCOPE` -- per-`(workspace_id,
//!   namespace_id)` ceiling on tracked inbox commands, default 20,000,
//!   enforced in *addition* to the shared global inbox capacity (see
//!   `apex_control_plane_api::DEFAULT_INBOX_SCOPE_QUOTA`). An operator
//!   credential is commonly scoped to a single workspace/namespace
//!   (`OperatorCaller::scoped`, and every Keycloak-issued credential maps
//!   down to the same narrow scopes); without this ceiling one scoped
//!   credential -- compromised, buggy automation, or just an unlucky burst --
//!   could fill the entire shared inbox and block delivery, including an
//!   emergency `stop`, to every other tenant. Must be a positive integer no
//!   greater than the inbox capacity; zero and out-of-range values abort
//!   startup rather than being silently clamped.
//! - `APEX_CONTROL_NATS_RETRY_ATTEMPTS` -- bounded publish retry ladder,
//!   default 3 (1..=8), mirroring event-ingest's `APEX_RETRY_ATTEMPTS`.
//! - `APEX_CONTROL_OPERATOR_TOKENS_FILE` or `APEX_CONTROL_OPERATOR_TOKENS`
//!   (local/lab, CI) -- static operator credential table:
//!   `token1|workspace/ns[,workspace/ns...];token2|*;...`. `*` grants a global
//!   (break-glass) operator scope. The token and its scopes are separated by
//!   `|`, not `:`, so a token containing a colon cannot be silently truncated
//!   into a shorter credential (see `auth::parse_operator_token_table`). A
//!   malformed entry aborts startup rather than being skipped. This is
//!   deliberately a distinct credential space from event-ingest's ingest
//!   bearer tokens.
//! - `APEX_CONTROL_KEYCLOAK_ISSUER` -- **the production credential path**, and
//!   the variable that selects it. Verifies short-lived, scope-bound operator
//!   credentials Keycloak issued through RFC 8693 token exchange, per
//!   [[Authentication and Identity]]. Keycloak performs the exchange; this
//!   process is a resource server that holds no client secret and only
//!   verifies. Setting it alongside either static source is refused, for the
//!   same reason those two refuse each other: two configured credential
//!   sources means one is silently ignored. Companion settings:
//!   - `APEX_CONTROL_KEYCLOAK_AUDIENCE` (required) -- this gateway's expected
//!     `aud`. `iss` and `aud` are *required* claims here, not
//!     validated-only-if-present.
//!   - `APEX_CONTROL_KEYCLOAK_CA_FILE` (required) -- CA the JWKS endpoint's
//!     certificate must chain to. It **replaces** the trust store rather than
//!     adding to it, so a publicly-trusted certificate cannot stand in for the
//!     realm.
//!   - `APEX_CONTROL_KEYCLOAK_JWKS_URL` -- defaults to
//!     `{issuer}/protocol/openid-connect/certs`. Overriding it is supported
//!     for split-horizon deployments and is an assertion that the URL serves
//!     the configured issuer's keys.
//!   - `APEX_CONTROL_KEYCLOAK_JWKS_REFRESH_SECS` (default 300, 30..=3600) --
//!     also the bound on how long a rotated-away key keeps verifying.
//!   - `APEX_CONTROL_KEYCLOAK_JWKS_MAX_AGE_SECS` (default 900, 30..=86400) --
//!     staleness ceiling. Past it the resolver refuses every credential with
//!     `CREDENTIAL_VERIFIER_UNAVAILABLE` rather than trusting keys of unknown
//!     age. Must be at least the refresh interval.
//!   - `APEX_CONTROL_KEYCLOAK_SCOPE_CLAIM` (default `apex_control_scopes`) --
//!     allow-listed claim carrying `workspace/namespace` grants. A `*` in it
//!     rejects the whole token; it never widens.
//!   - `APEX_CONTROL_KEYCLOAK_ROLE_CLAIM` (default `realm_access.roles`) --
//!     dotted path, objects only.
//!   - `APEX_CONTROL_KEYCLOAK_GLOBAL_ROLE` +
//!     `APEX_CONTROL_KEYCLOAK_GLOBAL_SUBJECTS` -- the *only* route to the `*`
//!     break-glass scope, and both are required together. A claim can never
//!     confer `*` on its own: the subject allow-list is local configuration
//!     the identity provider does not control. Unset by default, i.e. `*` is
//!     unreachable.
//!   - `APEX_CONTROL_KEYCLOAK_MAX_TOKEN_LIFETIME_SECS` (default 3600,
//!     60..=86400) -- ceiling on `exp - iat`, making "short-lived" real.
//!   - `APEX_CONTROL_KEYCLOAK_EXPECTED_TYP` (default `Bearer`) /
//!     `APEX_CONTROL_KEYCLOAK_ALLOW_ANY_TOKEN_TYP=true` -- Keycloak signs ID,
//!     access and refresh tokens with the same realm keys, and an ID token's
//!     `aud` is the client id. The waiver is exact-match and setting both is
//!     refused.
//! - `APEX_CONTROL_ADMISSION_LIMIT` (default 50, 1..=100000) and
//!   `APEX_CONTROL_ADMISSION_WINDOW_SECS` (default 1, 1..=3600) -- the
//!   per-operator admission ceiling.
//! - `APEX_CONTROL_VALKEY_HOST` / `_PORT` / `_USERNAME` / `_PASSWORD_FILE` /
//!   `_CA_FILE` / `_CLIENT_CERT_FILE` / `_CLIENT_KEY_FILE` -- optional
//!   **cross-replica** admission ceiling, reusing
//!   `apex_event_ingest`'s `EphemeralStore`/`ValkeyEphemeralStore` rather than
//!   forking a second accelerator. Requires `--features valkey`; setting the
//!   host without it is a hard startup error. Without it the ceiling is
//!   process-local, so N replicas admit N x the configured limit.
//!
//!   **This is the control gateway's own Valkey instance and its own ACL
//!   user**, never the ingest workload's -- `APEX_VALKEY_HOST` on this process
//!   is refused outright. Same rule as `APEX_CONTROL_POSTGRES_URL` and the
//!   separate NATS account, plus a concrete reason: `event-ingest`'s Valkey
//!   key prefix is the fixed literal `apex:ingest`, so a shared instance would
//!   put both services' counters in one keyspace under one credential.
//!
//!   The accelerator is **never authoritative**. The process-local ceiling
//!   remains the hard floor: an unreachable or misbehaving Valkey degrades to
//!   it rather than failing open, and a Valkey that is down at startup does
//!   not stop this gateway coming up (ADR-0006). Configuration errors still
//!   abort startup.
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
