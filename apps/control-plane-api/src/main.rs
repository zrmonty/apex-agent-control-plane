//! Runnable OOB control gateway binary.
//!
//! Configuration is environment-driven, matching `apps/event-ingest`'s
//! convention:
//!
//! - `APEX_CONTROL_BIND_ADDR` -- listen address (default `127.0.0.1:9443`).
//!   Binding anything other than a loopback address additionally requires
//!   `APEX_CONTROL_ALLOW_NONLOCAL_BIND=true`, because this process serves an
//!   unencrypted gRPC port (see "Transport security" below) and its operator
//!   bearer credential would otherwise travel in cleartext to anyone on the
//!   path. This mirrors the `APEX_ALLOW_NONLOCAL_INGEST_BIND` gate the
//!   Compose preflight already applies to the ingest gateway.
//! - `APEX_CONTROL_OUTBOX_BASE` / `APEX_CONTROL_OUTBOX_FILE` -- durable file
//!   outbox location (defaults under `./data/control-outbox`). This is a
//!   distinct outbox file from event-ingest's, by design: the two services
//!   must not share a durability boundary any more than they share auth.
//! - `APEX_CONTROL_OPERATOR_TOKENS` -- operator credential table:
//!   `token1|workspace/ns[,workspace/ns...];token2|*;...`. `*` grants a
//!   global (break-glass) operator scope. The token and its scopes are
//!   separated by `|`, not `:`, so a token containing a colon cannot be
//!   silently truncated into a shorter credential (see
//!   `auth::parse_operator_token_table`). A malformed entry aborts startup
//!   rather than being skipped. This is deliberately a distinct credential
//!   space from event-ingest's ingest bearer tokens -- per
//!   [[Authentication and Identity]] the production path is a short-lived
//!   Keycloak-issued operator credential exchanged in front of this
//!   process; this static table is the local/lab and CI seam for that.
//!
//! Transport security: this binary listens in plaintext and expects a
//! TLS-terminating proxy or an mTLS sidecar in front of it in any
//! non-loopback deployment, matching the trust boundary
//! `event-ingest`'s own strict-TLS mode documents. It therefore defaults to
//! loopback and refuses to bind elsewhere without an explicit
//! acknowledgement. Wiring native `tonic::transport::ServerTlsConfig` here is
//! a straightforward follow-up once an operator PKI profile is chosen; it is
//! not required for the durability and auth-independence guarantees ADR-0006
//! asks for.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use apex_control_plane_api::{
    ControlGatewayService, ControlOutboxBackend, OperatorTokenAuthenticator,
    StaticOperatorTokenResolver, bounded_control_gateway_server, install_rustls_provider,
    parse_operator_token_table,
};

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:9443";

fn build_operator_resolver() -> Result<StaticOperatorTokenResolver, Box<dyn std::error::Error>> {
    let Ok(raw) = std::env::var("APEX_CONTROL_OPERATOR_TOKENS") else {
        eprintln!(
            "control-plane-api: APEX_CONTROL_OPERATOR_TOKENS is unset; no operator credential will authenticate"
        );
        return Ok(StaticOperatorTokenResolver::new());
    };
    // A malformed credential table is a configuration failure, not something
    // to log past. Skipping a bad entry would leave the gateway running with
    // an operator silently unable to act -- or, worse, acting under a
    // mis-parsed scope.
    Ok(parse_operator_token_table(&raw)?)
}

/// Refuses a non-loopback bind address unless the operator has explicitly
/// acknowledged it. This process speaks plaintext gRPC, so a `0.0.0.0` bind
/// without a TLS terminator in front of it exposes operator bearer tokens
/// and control commands to anyone on the network path.
fn resolve_bind_addr() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let raw =
        std::env::var("APEX_CONTROL_BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_owned());
    let addr: SocketAddr = raw.parse()?;
    let acknowledged = std::env::var("APEX_CONTROL_ALLOW_NONLOCAL_BIND")
        .ok()
        .as_deref()
        == Some("true");
    if !addr.ip().is_loopback() && !acknowledged {
        return Err(format!(
            "APEX_CONTROL_BIND_ADDR={raw} is not a loopback address. This gateway serves plaintext gRPC; put a TLS-terminating proxy or mTLS sidecar in front of it and set APEX_CONTROL_ALLOW_NONLOCAL_BIND=true to acknowledge."
        )
        .into());
    }
    Ok(addr)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    install_rustls_provider();

    let bind_addr = resolve_bind_addr()?;

    let outbox_base = PathBuf::from(
        std::env::var("APEX_CONTROL_OUTBOX_BASE").unwrap_or_else(|_| "./data/control-outbox".to_owned()),
    );
    std::fs::create_dir_all(&outbox_base)?;
    let outbox_file = outbox_base.join(
        std::env::var("APEX_CONTROL_OUTBOX_FILE").unwrap_or_else(|_| "commands.jsonl".to_owned()),
    );
    let file_outbox = apex_event_ingest::FileOutbox::open(&outbox_file, &outbox_base, 1_000_000)
        .map_err(|error| format!("failed to open control outbox: {}", error.code.as_str()))?;
    let outbox = Arc::new(ControlOutboxBackend::new(Box::new(file_outbox)));

    let resolver = build_operator_resolver()?;
    let auth = OperatorTokenAuthenticator::new(resolver);
    let service = ControlGatewayService::new(auth, outbox);

    println!("apex-control-plane-api listening on {bind_addr}");
    tonic::transport::Server::builder()
        .add_service(bounded_control_gateway_server(service))
        .serve(bind_addr)
        .await?;
    Ok(())
}
