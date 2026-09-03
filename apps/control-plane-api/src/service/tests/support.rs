//! Fixtures shared by more than one of this module's sibling test groups.

use std::sync::Arc;

use apex_auth::PeerIdentity;
use apex_durability::InMemoryOutbox;
use prost_types::Struct as ProstStruct;

use crate::auth::{OperatorCaller, OperatorTokenAuthenticator, StaticOperatorTokenResolver};
use crate::outbox::ControlOutboxBackend;
use crate::proto;
use crate::service::ControlGatewayService;

pub(super) fn service() -> ControlGatewayService<StaticOperatorTokenResolver> {
    let resolver = StaticOperatorTokenResolver::new().with_token(
        "op-token",
        OperatorCaller::scoped("operator:zack", ["acme/prod"]).unwrap(),
    );
    let outbox: Box<dyn apex_durability::EventOutbox + Send> =
        Box::new(InMemoryOutbox::new(64).unwrap());
    ControlGatewayService::new(
        OperatorTokenAuthenticator::new(resolver),
        Arc::new(ControlOutboxBackend::new(outbox)),
    )
}

/// Certificate fingerprint fixture. `PeerIdentity` is a plain
/// SHA-256-of-leaf value, so a test can construct one directly without a
/// TLS session; the live tests in `tests/live_control_poll.rs` are what
/// prove the real extraction path.
pub(super) fn peer(byte: u8) -> PeerIdentity {
    PeerIdentity {
        certificate_sha256: [byte; 32],
    }
}

pub(super) fn hex32(byte: u8) -> String {
    (0..32).map(|_| format!("{byte:02x}")).collect()
}

/// A gateway serving one operator and two agent workloads in the same
/// workspace/namespace, each with its own credential and its own pinned
/// client certificate. This is the shape every isolation assertion below
/// needs: same tenant, different agents, so a leak cannot be explained
/// away by the scope check alone.
pub(super) fn service_with_two_agents() -> ControlGatewayService<StaticOperatorTokenResolver> {
    let agents = crate::agent_auth::parse_agent_token_table(&format!(
        "agent-a-token-abcdefgh|{}|agent-a|acme/prod;agent-b-token-abcdefgh|{}|agent-b|acme/prod",
        hex32(0xaa),
        hex32(0xbb)
    ))
    .expect("agent table must parse");
    service().with_agent_resolver(crate::agent_auth::BoxedAgentWorkloadResolver::new(agents))
}

pub(super) fn poll_request(
    bearer: &str,
    peer: PeerIdentity,
) -> tonic::Request<proto::PollCommandsRequest> {
    poll_request_for(bearer, peer, proto::PollCommandsRequest { max_commands: 0 })
}

pub(super) fn poll_request_for(
    bearer: &str,
    peer: PeerIdentity,
    body: proto::PollCommandsRequest,
) -> tonic::Request<proto::PollCommandsRequest> {
    let mut request = tonic::Request::new(body);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {bearer}").parse().unwrap());
    // Stands in for what `peer_identity_from_request` reads off a real TLS
    // connection. The in-process service is not served over TLS, so the
    // extension has to be injected; `poll_commands` reads it through the
    // same function either way.
    request.extensions_mut().insert(peer);
    request
}

pub(super) fn authed_request(
    body: proto::ControlCommandRequest,
) -> tonic::Request<proto::ControlCommandRequest> {
    let mut request = tonic::Request::new(body);
    request
        .metadata_mut()
        .insert("authorization", "Bearer op-token".parse().unwrap());
    request
}

/// A canonical lowercase UUIDv7 stamped with a recent millisecond, so it
/// stays inside the gateway's `command_id` clock-acceptance window (see
/// `envelope::command_millis_within_acceptance_window`). `suffix`
/// distinguishes ids for tests that need several.
///
/// The millisecond is captured once per test binary rather than read per
/// call: idempotency tests submit the *same* id twice and must get the
/// same string back, which a per-call clock read would not guarantee
/// across a millisecond boundary.
pub(super) fn fresh_command_id(suffix: u64) -> String {
    static BASE_MILLIS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let ms = *BASE_MILLIS.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
            & 0xFFFF_FFFF_FFFF
    });
    format!(
        "{:08x}-{:04x}-7000-8000-{:012x}",
        (ms >> 16) as u32,
        (ms & 0xFFFF) as u16,
        suffix & 0xFFFF_FFFF_FFFF
    )
}

pub(super) fn stop_request() -> proto::ControlCommandRequest {
    proto::ControlCommandRequest {
        command_id: None,
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        agent_id: "agent-1".to_owned(),
        run_id: "run-1".to_owned(),
        parent_run_id: None,
        trace_id: "trace-1".to_owned(),
        action: proto::ControlAction::Stop as i32,
        reason_code: Some("operator.request".to_owned()),
        parameters: Some(ProstStruct::default()),
    }
}

/// Submits a `stop` for `agent_id` and returns the accepted `command_id`.
/// Shared by the `poll` and `query` test groups: both need at least one
/// durably recorded command targeting a specific agent before they can
/// exercise retrieval/listing/cancellation of it.
pub(super) async fn submit_stop_for(
    service: &ControlGatewayService<StaticOperatorTokenResolver>,
    agent_id: &str,
    suffix: u64,
) -> String {
    use crate::proto::control_gateway_server::ControlGateway as _;

    let mut request = stop_request();
    request.agent_id = agent_id.to_owned();
    request.command_id = Some(fresh_command_id(suffix));
    service
        .submit_command(authed_request(request))
        .await
        .expect("the operator must be able to submit")
        .into_inner()
        .command_id
}
