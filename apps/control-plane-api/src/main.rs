//! Runnable OOB control gateway binary.
//!
//! Configuration is environment-driven, matching `apps/event-ingest`'s
//! convention:
//!
//! - `APEX_CONTROL_BIND_ADDR` -- listen address (default `0.0.0.0:9443`).
//! - `APEX_CONTROL_OUTBOX_BASE` / `APEX_CONTROL_OUTBOX_FILE` -- durable file
//!   outbox location (defaults under `./data/control-outbox`). This is a
//!   distinct outbox file from event-ingest's, by design: the two services
//!   must not share a durability boundary any more than they share auth.
//! - `APEX_CONTROL_OPERATOR_TOKENS` -- operator credential table:
//!   `token1:workspace/ns[,workspace/ns...];token2:*;...`. `*` grants a
//!   global (break-glass) operator scope. This is deliberately a distinct
//!   credential space from event-ingest's ingest bearer tokens -- per
//!   [[Authentication and Identity]] the production path is a short-lived
//!   Keycloak-issued operator credential exchanged in front of this
//!   process; this static table is the local/lab and CI seam for that.
//!
//! Transport security: this binary listens in plaintext by default and
//! expects a TLS-terminating proxy or an mTLS sidecar in front of it in any
//! non-loopback deployment, matching the trust boundary
//! `event-ingest`'s own strict-TLS mode documents. Wiring native
//! `tonic::transport::ServerTlsConfig` here is a straightforward follow-up
//! once an operator PKI profile is chosen; it is not required for the
//! durability and auth-independence guarantees ADR-0006 asks for.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use apex_control_plane_api::{
    ControlGatewayService, ControlOutboxBackend, OperatorCaller, OperatorTokenAuthenticator,
    StaticOperatorTokenResolver, bounded_control_gateway_server, install_rustls_provider,
};

fn build_operator_resolver() -> StaticOperatorTokenResolver {
    let mut resolver = StaticOperatorTokenResolver::new();
    let Ok(raw) = std::env::var("APEX_CONTROL_OPERATOR_TOKENS") else {
        return resolver;
    };
    for (index, entry) in raw.split(';').filter(|entry| !entry.is_empty()).enumerate() {
        let Some((token, scopes)) = entry.split_once(':') else {
            eprintln!("control-plane-api: skipping malformed operator token entry {index}");
            continue;
        };
        let subject = format!("operator:static:{index}");
        let caller = if scopes.trim() == "*" {
            OperatorCaller::global(subject)
        } else {
            OperatorCaller::scoped(subject, scopes.split(',').map(str::trim).filter(|s| !s.is_empty()))
        };
        match caller {
            Ok(caller) => resolver = resolver.with_token(token, caller),
            Err(_) => eprintln!(
                "control-plane-api: skipping operator token entry {index}: invalid scope"
            ),
        }
    }
    resolver
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    install_rustls_provider();

    let bind_addr: SocketAddr = std::env::var("APEX_CONTROL_BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:9443".to_owned())
        .parse()?;

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

    let resolver = build_operator_resolver();
    let auth = OperatorTokenAuthenticator::new(resolver);
    let service = ControlGatewayService::new(auth, outbox);

    println!("apex-control-plane-api listening on {bind_addr}");
    tonic::transport::Server::builder()
        .add_service(bounded_control_gateway_server(service))
        .serve(bind_addr)
        .await?;
    Ok(())
}
