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
    ControlGatewayService, ControlOutboxBackend, OperatorTokenAuthenticator,
    StaticOperatorTokenResolver, bounded_control_gateway_server, parse_operator_token_table,
};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use super::env::{OperatorTokenSource, operator_token_source, path, required, resolve_bind_addr};
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

/// Builds the operator credential table from a file secret (production) or an
/// inline env var (local/lab and CI). See
/// [`super::env::operator_token_source`] for why both exist and why setting
/// both is refused.
fn build_operator_resolver(
    trusted_base: &Path,
) -> Result<StaticOperatorTokenResolver, Box<dyn std::error::Error>> {
    let raw = match operator_token_source()? {
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
                "control-plane-api: neither APEX_CONTROL_OPERATOR_TOKENS_FILE nor APEX_CONTROL_OPERATOR_TOKENS is set; no operator credential will authenticate"
            );
            return Ok(StaticOperatorTokenResolver::new());
        }
    };
    // A malformed credential table is a configuration failure, not something
    // to log past. Skipping a bad entry would leave the gateway running with
    // an operator silently unable to act -- or, worse, acting under a
    // mis-parsed scope.
    Ok(parse_operator_token_table(&raw)?)
}

fn open_outbox() -> Result<ControlOutboxBackend, Box<dyn std::error::Error>> {
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
    Ok(ControlOutboxBackend::new(Box::new(file_outbox)))
}

pub(crate) async fn run() -> Result<(), Box<dyn std::error::Error>> {
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
    let service = ControlGatewayService::new(auth, outbox);

    println!("apex-control-plane-api listening on {bind_addr} (mTLS, client certificate required)");
    Server::builder()
        .tls_config(tls)?
        .add_service(bounded_control_gateway_server(service))
        .serve(bind_addr)
        .await?;
    Ok(())
}
