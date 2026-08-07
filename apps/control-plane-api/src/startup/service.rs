//! Process wiring for the OOB control gateway: bind policy, TLS identity,
//! durable outbox, operator credential table, and the tonic server.
//!
//! Structurally the mirror of `apps/event-ingest/src/startup/service.rs`, and
//! deliberately so -- this service must not ship a weaker transport boundary
//! than the ingest gateway sitting next to it.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use apex_control_plane_api::{
    BoxedOperatorCredentialResolver, ControlGatewayService, ControlOutboxBackend, KeycloakConfig,
    KeycloakOperatorCredentialResolver, OperatorTokenAuthenticator, SharedEphemeralStore,
    bounded_control_gateway_server, parse_operator_token_table,
};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use super::env::{
    OperatorTokenSource, admission_limits, control_postgres_url, control_valkey_env, keycloak_env,
    operator_token_source, path, required, resolve_bind_addr,
};
use super::fanout::prepare_control_fanout;
use super::secrets::{read_bounded, read_credential_table, trusted_secret_path};

/// PEM material ceiling, matching `event-ingest`'s own 1 MiB bound on the
/// same three files.
const MAX_TLS_MATERIAL_BYTES: usize = 1024 * 1024;
/// The credential table is `token|scopes;...` with up to 256 entries of up to
/// 4096 token bytes (`auth::MAX_OPERATOR_TOKEN_ENTRIES` /
/// `MAX_OPERATOR_TOKEN_BYTES`), so 64 KiB is generous headroom while still
/// bounding what a mounted file can make this process allocate.
const MAX_OPERATOR_TABLE_BYTES: usize = 64 * 1024;
const OUTBOX_CAPACITY: usize = 1_000_000;

/// Loads the mTLS server identity and the CA that operator client
/// certificates must chain to.
///
/// **TLS is mandatory.** All three paths are `required()`, so a missing one
/// aborts startup instead of silently degrading to plaintext. This matches
/// `event-ingest` exactly: that binary has no "lab mode" TLS bypass either --
/// `APEX_GATEWAY_SERVER_CERT_FILE`/`_KEY_FILE`/`_CLIENT_CA_FILE` are all
/// `path()` (i.e. required) and its `client_auth_optional(false)` is
/// explicit. Local and CI use is served by the real PKI in
/// `deploy/compose/live-mtls/`, not by an unencrypted fallback, so adding one
/// here would invent a weaker mode that does not exist anywhere else in this
/// repository.
fn load_server_tls(trusted_base: &Path) -> Result<ServerTlsConfig, io::Error> {
    let server_cert_path = trusted_secret_path(
        &path("APEX_CONTROL_SERVER_CERT_FILE")?,
        trusted_base,
        MAX_TLS_MATERIAL_BYTES as u64,
        false,
        "APEX_CONTROL_SERVER_CERT_FILE",
    )?;
    let server_key_path = trusted_secret_path(
        &path("APEX_CONTROL_SERVER_KEY_FILE")?,
        trusted_base,
        MAX_TLS_MATERIAL_BYTES as u64,
        true,
        "APEX_CONTROL_SERVER_KEY_FILE",
    )?;
    let client_ca_path = trusted_secret_path(
        &path("APEX_CONTROL_CLIENT_CA_FILE")?,
        trusted_base,
        MAX_TLS_MATERIAL_BYTES as u64,
        false,
        "APEX_CONTROL_CLIENT_CA_FILE",
    )?;
    let server_cert = read_bounded(
        &server_cert_path,
        MAX_TLS_MATERIAL_BYTES,
        "APEX_CONTROL_SERVER_CERT_FILE",
    )?;
    let server_key = read_bounded(
        &server_key_path,
        MAX_TLS_MATERIAL_BYTES,
        "APEX_CONTROL_SERVER_KEY_FILE",
    )?;
    let client_ca = read_bounded(
        &client_ca_path,
        MAX_TLS_MATERIAL_BYTES,
        "APEX_CONTROL_CLIENT_CA_FILE",
    )?;
    Ok(ServerTlsConfig::new()
        .identity(Identity::from_pem(server_cert, server_key))
        .client_ca_root(Certificate::from_pem(client_ca))
        // Explicit, for the same reason `event-ingest` states it explicitly:
        // a tonic upgrade must not be able to make operator client
        // certificates optional at the gRPC boundary by changing a default.
        .client_auth_optional(false))
}

/// PEM ceiling for the Keycloak JWKS CA, matching the mTLS material bound.
const MAX_KEYCLOAK_CA_BYTES: usize = 1024 * 1024;

/// Selects the operator credential verifier.
///
/// Three paths, chosen by explicit configuration and never inferred from one
/// another (see [`super::env::operator_token_source_value`]):
///
/// - **Keycloak** (`APEX_CONTROL_KEYCLOAK_ISSUER`) -- the production path.
///   Verifies short-lived, scope-bound credentials Keycloak issued through
///   RFC 8693 token exchange. This process is a resource server: it holds no
///   client secret, performs no exchange, and only checks signatures and
///   claims.
/// - **File** (`APEX_CONTROL_OPERATOR_TOKENS_FILE`) and **inline**
///   (`APEX_CONTROL_OPERATOR_TOKENS`) -- the static table, unchanged, still
///   the local/lab and CI seam.
///
/// The return type is erased because the three implementations are different
/// types; `ControlGatewayService` stays generic so in-process tests keep
/// monomorphising over the resolver they actually construct.
fn build_operator_resolver(
    trusted_base: &Path,
) -> Result<BoxedOperatorCredentialResolver, Box<dyn std::error::Error>> {
    let raw = match operator_token_source()? {
        OperatorTokenSource::Keycloak(issuer) => {
            let settings = keycloak_env(issuer)?;
            let ca_path = trusted_secret_path(
                &settings.ca_file,
                trusted_base,
                MAX_KEYCLOAK_CA_BYTES as u64,
                // A CA certificate is public material, so it is not held to
                // the private-key permission policy -- the same call the
                // NATS/mTLS client CAs get.
                false,
                "APEX_CONTROL_KEYCLOAK_CA_FILE",
            )?;
            let jwks_ca_pem = read_bounded(
                &ca_path,
                MAX_KEYCLOAK_CA_BYTES,
                "APEX_CONTROL_KEYCLOAK_CA_FILE",
            )?;
            let config = KeycloakConfig {
                issuer: settings.issuer,
                audience: settings.audience,
                jwks_url: settings.jwks_url,
                jwks_ca_pem,
                jwks_refresh: settings.jwks_refresh,
                jwks_max_age: settings.jwks_max_age,
                scope_claim: settings.scope_claim,
                role_claim: settings.role_claim,
                global_role: settings.global_role,
                global_subjects: settings.global_subjects,
                max_token_lifetime: settings.max_token_lifetime,
                expected_typ: settings.expected_typ,
            };
            let break_glass = if config.global_role.is_some() {
                config.global_subjects.len()
            } else {
                0
            };
            // Constructed here, before the serving runtime exists: the JWKS
            // client is `reqwest::blocking` and owns an internal runtime, so
            // building it on a runtime thread panics -- the same hazard that
            // made `run()` synchronous for `PostgresOutbox`.
            let resolver = KeycloakOperatorCredentialResolver::start(config)?;
            println!(
                "apex-control-plane-api operator credentials: keycloak (break-glass subjects allow-listed: {break_glass})"
            );
            return Ok(Box::new(resolver));
        }
        OperatorTokenSource::File(configured) => {
            let table_path = trusted_secret_path(
                &configured,
                trusted_base,
                MAX_OPERATOR_TABLE_BYTES as u64,
                // Bearer credentials, not just a config file: held to the
                // same owner-only permission policy as a private key.
                true,
                "APEX_CONTROL_OPERATOR_TOKENS_FILE",
            )?;
            read_credential_table(
                &table_path,
                MAX_OPERATOR_TABLE_BYTES,
                "APEX_CONTROL_OPERATOR_TOKENS_FILE",
            )?
        }
        OperatorTokenSource::Inline(raw) => raw,
        OperatorTokenSource::Unset => {
            // Fail-closed, not fail-open: an empty resolver authenticates
            // nobody. Loud on stderr because a control gateway that accepts
            // no operator at all is almost never what was intended.
            eprintln!(
                "control-plane-api: none of APEX_CONTROL_KEYCLOAK_ISSUER, APEX_CONTROL_OPERATOR_TOKENS_FILE or APEX_CONTROL_OPERATOR_TOKENS is set; no operator credential will authenticate"
            );
            return Ok(Box::new(
                apex_control_plane_api::StaticOperatorTokenResolver::new(),
            ));
        }
    };
    // A malformed credential table is a configuration failure, not something
    // to log past. Skipping a bad entry would leave the gateway running with
    // an operator silently unable to act -- or, worse, acting under a
    // mis-parsed scope.
    let resolver = parse_operator_token_table(&raw)?;
    println!("apex-control-plane-api operator credentials: static table");
    Ok(Box::new(resolver))
}

/// Builds the optional cross-replica admission accelerator.
///
/// Structurally `event-ingest`'s `build_ephemeral_store`, with one deliberate
/// difference: an unreachable Valkey **does not stop this gateway starting**.
///
/// `event-ingest` refuses to come up if `ValkeyEphemeralStore::connect` fails,
/// which is defensible for the ingest data path. Doing the same here would
/// make an explicitly non-authoritative accelerator a hard startup dependency
/// of the out-of-band control channel -- the exact coupling ADR-0006 exists to
/// remove, and the same mistake the JetStream publisher already had to avoid.
/// So the split is the same one used there: **configuration errors abort
/// startup loudly, an unreachable instance does not.** A refused *config*
/// (`EphemeralErrorCode::InvalidKey` -- a path outside the trusted base, a
/// key readable beyond its owner, a malformed host) is a misconfiguration;
/// `Unavailable` is an outage, and an outage means the process runs on its
/// process-local ceiling, which is the hard floor either way.
///
/// The connection is also re-established lazily by [`LazyValkeyStore`] rather
/// than only at startup, so a Valkey that was down when this process booted is
/// picked up without a restart -- and `FallbackEphemeralStore`'s circuit
/// breaker is what keeps that retry from becoming a per-request stall.
fn build_ephemeral_store(
    trusted_base: &Path,
) -> Result<Option<SharedEphemeralStore>, Box<dyn std::error::Error>> {
    let configured = control_valkey_env()?;
    #[cfg(feature = "valkey")]
    {
        use apex_event_ingest::{EphemeralStore, FallbackEphemeralStore, InMemoryEphemeralStore};

        if let Some(settings) = configured {
            let config = apex_event_ingest::ValkeyConfig {
                host: settings.host,
                port: settings.port,
                username: settings.username,
                password_file: settings.password_file,
                ca_file: settings.ca_file,
                client_cert_file: settings.client_cert_file,
                client_key_file: settings.client_key_file,
                trusted_base: trusted_base.to_path_buf(),
            };
            // Eager *configuration* validation, deferred connection. Same
            // split as `NatsTlsConfig::validate` in `startup/fanout.rs`, and
            // for the same reason.
            config.validate().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "APEX_CONTROL_VALKEY_* configuration was refused: {}",
                        error.code.as_str()
                    ),
                )
            })?;
            let store: Box<dyn EphemeralStore> = Box::new(FallbackEphemeralStore::new(
                super::valkey::LazyValkeyStore::new(config),
                InMemoryEphemeralStore::new(),
            ));
            println!(
                "apex-control-plane-api admission ceiling: shared (valkey), local ceiling retained as the floor"
            );
            return Ok(Some(std::sync::Mutex::new(store).into()));
        }
    }
    #[cfg(not(feature = "valkey"))]
    {
        let _ = trusted_base;
        if configured.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_CONTROL_VALKEY_HOST is set but this binary was not built with --features valkey",
            )
            .into());
        }
    }
    println!("apex-control-plane-api admission ceiling: process-local only");
    Ok(None)
}

/// Selects the durable outbox backend, mirroring `event-ingest`'s
/// `open_durability_stores`: a URL selects Postgres, its absence selects the
/// file backend, and a URL set on a binary built without `--features postgres`
/// is a hard startup error rather than a silent downgrade to a single-writer
/// file.
///
/// That last case is the one this function used to get wrong in the other
/// direction. It unconditionally built a `FileOutbox`, so `--features postgres`
/// changed nothing about the running binary -- it only forwarded the feature to
/// `apex-event-ingest`. A deployment that believed it had a multi-writer
/// backend had a single-writer one, which is exactly the assumption
/// cross-replica work would have been built on top of.
fn open_outbox() -> Result<ControlOutboxBackend, Box<dyn std::error::Error>> {
    #[cfg(feature = "postgres")]
    {
        if let Some(url) = control_postgres_url()? {
            // Reused verbatim from `event-ingest`, including its multi-replica
            // fixes (advisory-locked schema DDL, `ON CONFLICT DO NOTHING` on
            // the insert race, and `FOR UPDATE SKIP LOCKED` claim leases in
            // `pending()`). See `env::control_postgres_url_value` for why this
            // must be a different database or schema from the ingest
            // gateway's, given both share the `apex_event_outbox` table name.
            let outbox = apex_event_ingest::PostgresOutbox::connect(&url, OUTBOX_CAPACITY)
                .map_err(|error| {
                    format!("failed to open control outbox: {}", error.code.as_str())
                })?;
            println!("apex-control-plane-api outbox backend: postgres");
            return Ok(ControlOutboxBackend::new(Box::new(outbox)));
        }
    }
    #[cfg(not(feature = "postgres"))]
    {
        if control_postgres_url()?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_CONTROL_POSTGRES_URL is set but this binary was not built with --features postgres",
            )
            .into());
        }
    }
    let outbox_base = PathBuf::from(
        std::env::var("APEX_CONTROL_OUTBOX_BASE")
            .unwrap_or_else(|_| "./data/control-outbox".to_owned()),
    );
    std::fs::create_dir_all(&outbox_base)?;
    let outbox_file = outbox_base.join(
        std::env::var("APEX_CONTROL_OUTBOX_FILE").unwrap_or_else(|_| "commands.jsonl".to_owned()),
    );
    let file_outbox =
        apex_event_ingest::FileOutbox::open(&outbox_file, &outbox_base, OUTBOX_CAPACITY)
            .map_err(|error| format!("failed to open control outbox: {}", error.code.as_str()))?;
    println!("apex-control-plane-api outbox backend: file");
    Ok(ControlOutboxBackend::new(Box::new(file_outbox)))
}

/// Synchronous by design, exactly as `apps/event-ingest/src/startup/service.rs`
/// is and for the same reason: some clients constructed below own an internal
/// tokio runtime and `block_on` it during construction, which **panics** on a
/// thread that already has a runtime entered.
///
/// This is not hypothetical. `run()` was `async` under `#[tokio::main]` until
/// the Postgres backend was wired in, at which point
/// `PostgresOutbox::connect` -> `postgres::Config::connect` panicked with
/// "Cannot start a runtime from within a runtime" on the first real container
/// start -- while every in-process test stayed green, because none of them
/// construct a blocking client inside an async `run()`. The runtime this
/// process serves on is therefore created at the end, once construction is
/// complete.
pub(crate) fn run() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = resolve_bind_addr()?;
    // Confines every configured secret path under one operator-owned
    // directory, so a compromised env var cannot point this process at
    // arbitrary files on the host. Same role as `APEX_TRUSTED_SECRET_BASE`
    // on the ingest side; a separate variable because these are separate
    // trust boundaries and, in Compose, separate mounts.
    let trusted_base = PathBuf::from(required("APEX_CONTROL_TRUSTED_SECRET_BASE")?);
    let tls = load_server_tls(&trusted_base)?;
    let outbox = Arc::new(open_outbox()?);
    let resolver = build_operator_resolver(&trusted_base)?;
    let auth = OperatorTokenAuthenticator::new(resolver);
    // Resolved and validated here, with no runtime entered; spawned below,
    // inside one. No socket is opened either way -- an unreachable broker
    // must never stop this gateway from starting (ADR-0006).
    let fanout = prepare_control_fanout(&trusted_base)?;
    let (admission_limit, admission_window) = admission_limits()?;
    // Built here, with no runtime entered: `ValkeyEphemeralStore::connect`
    // is synchronous and the wrapper around it must not be constructed on a
    // runtime thread any more than the Postgres client may be.
    let ephemeral = build_ephemeral_store(&trusted_base)?;
    let mut service = ControlGatewayService::new(auth, Arc::clone(&outbox))
        .with_admission_limits(admission_limit, admission_window);
    if let Some(store) = ephemeral {
        service = service.with_ephemeral_store(store);
    }
    println!(
        "apex-control-plane-api admission limit: {admission_limit} command(s) per operator per {}s",
        admission_window.as_secs()
    );

    // Everything above is built without a runtime entered. Same comment, same
    // reason, as `event-ingest`'s own `run()`.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        // Bound to a named variable, not `_`, and kept alive until `serve`
        // returns: this is the only thing that turns a durably accepted
        // command into an observable `control` event. Nothing on the accept
        // path touches it -- `ControlGatewayService` never sees the publisher
        // -- so a JetStream outage delays `delivered` and defers the trace
        // write without affecting whether a command is accepted (ADR-0006).
        let _fanout_worker = fanout.map(|fanout| fanout.spawn(outbox));
        println!(
            "apex-control-plane-api listening on {bind_addr} (mTLS, client certificate required)"
        );
        Server::builder()
            .tls_config(tls)?
            .add_service(bounded_control_gateway_server(service))
            .serve(bind_addr)
            .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
