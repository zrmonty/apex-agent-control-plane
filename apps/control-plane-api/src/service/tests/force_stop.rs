//! `force_stop`'s dual-approval gate: the one action `SubmitCommand`
//! requires two distinct operator approvals to record. See
//! `crate::dual_approval`.

use apex_event_ingest::InMemoryOutbox;
use prost_types::Struct as ProstStruct;

use crate::auth::{OperatorCaller, StaticOperatorTokenResolver};
use crate::proto;
use crate::proto::control_gateway_server::ControlGateway as _;
use crate::service::*;

use super::support::*;

// --- force_stop dual approval ---------------------------------------

/// Two distinct, separately-scoped operator credentials plus one agent
/// workload credential ("agent-a"), the shape `apps/agent-supervisor`
/// would register its own credential under in a real deployment (a
/// distinct agent_id, e.g. `agent-a.supervisor` -- `poll_commands` here
/// does not care which agent_id it is, only that the credential is
/// distinct, which `service_with_two_agents`'s existing pattern already
/// proves the gateway supports).
fn service_with_two_operators_and_one_agent()
-> ControlGatewayService<StaticOperatorTokenResolver> {
    let resolver = StaticOperatorTokenResolver::new()
        .with_token(
            "op-token-alice",
            OperatorCaller::scoped("operator:alice", ["acme/prod"]).unwrap(),
        )
        .with_token(
            "op-token-bob",
            OperatorCaller::scoped("operator:bob", ["acme/prod"]).unwrap(),
        );
    let outbox: Box<dyn apex_event_ingest::EventOutbox + Send> =
        Box::new(InMemoryOutbox::new(64).unwrap());
    let service = ControlGatewayService::new(
        OperatorTokenAuthenticator::new(resolver),
        Arc::new(ControlOutboxBackend::new(outbox)),
    );
    let agents = crate::agent_auth::parse_agent_token_table(&format!(
        "agent-a-token-abcdefgh|{}|agent-a|acme/prod",
        hex32(0xaa)
    ))
    .expect("agent table must parse");
    service.with_agent_resolver(crate::agent_auth::BoxedAgentWorkloadResolver::new(agents))
}

fn authed_request_as(
    bearer: &str,
    body: proto::ControlCommandRequest,
) -> tonic::Request<proto::ControlCommandRequest> {
    let mut request = tonic::Request::new(body);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {bearer}").parse().unwrap());
    request
}

fn force_stop_request(command_id: &str) -> proto::ControlCommandRequest {
    proto::ControlCommandRequest {
        command_id: Some(command_id.to_owned()),
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        agent_id: "agent-a".to_owned(),
        run_id: "run-1".to_owned(),
        parent_run_id: None,
        trace_id: "trace-1".to_owned(),
        action: proto::ControlAction::ForceStop as i32,
        reason_code: Some("incident.42".to_owned()),
        parameters: Some(ProstStruct::default()),
    }
}

/// The headline property: one operator's approval alone never enqueues a
/// `force_stop`, and it takes effect the moment -- and only the moment --
/// a second, distinct operator approves the identical command.
#[tokio::test]
async fn force_stop_requires_two_distinct_operator_approvals() {
    let service = service_with_two_operators_and_one_agent();
    let command_id = fresh_command_id(0x9000);
    let request = force_stop_request(&command_id);

    // First approval: recorded nowhere. The target's poll must see
    // nothing, and the response must say so rather than `delivered`.
    let first = service
        .submit_command(authed_request_as("op-token-alice", request.clone()))
        .await
        .expect("a well-formed first approval must be accepted")
        .into_inner();
    assert!(first.awaiting_second_approval);
    assert!(!first.delivered);
    assert!(!first.duplicate);
    assert_eq!(first.command_id, command_id);
    let after_first = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .unwrap()
        .into_inner();
    assert!(
        after_first.commands.is_empty(),
        "a single operator's approval must never be observable by the target"
    );

    // The same operator submitting again is not progress.
    let repeat = service
        .submit_command(authed_request_as("op-token-alice", request.clone()))
        .await
        .expect("a repeated identical submission is not an error")
        .into_inner();
    assert!(repeat.awaiting_second_approval);
    assert!(!repeat.delivered);

    // A second, distinct operator approves the identical command: now it
    // is recorded and the target agent can retrieve it.
    let second = service
        .submit_command(authed_request_as("op-token-bob", request))
        .await
        .expect("the second, distinct approval must be accepted")
        .into_inner();
    assert!(!second.awaiting_second_approval);
    assert!(!second.duplicate);
    assert_eq!(second.command_id, command_id);

    let delivered = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(delivered.commands.len(), 1);
    assert_eq!(delivered.commands[0].command_id, command_id);
    assert_eq!(
        delivered.commands[0].action,
        proto::ControlAction::ForceStop as i32
    );
}

/// A second submission under the same `command_id` that describes a
/// *different* command is refused, not treated as an approval -- the same
/// idempotency-conflict shape every other action already enforces,
/// applied before the command is ever recorded.
#[tokio::test]
async fn force_stop_second_approval_with_different_fields_is_refused() {
    let service = service_with_two_operators_and_one_agent();
    let command_id = fresh_command_id(0x9001);
    let first = force_stop_request(&command_id);
    service
        .submit_command(authed_request_as("op-token-alice", first))
        .await
        .expect("first approval must be accepted");

    let mut different = force_stop_request(&command_id);
    different.reason_code = Some("a-completely-different-reason".to_owned());
    let status = service
        .submit_command(authed_request_as("op-token-bob", different))
        .await
        .expect_err("mismatched fields under a reused command_id must be refused");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);

    // The original pending approval survives a rejected mismatch, so the
    // real second approver can still complete it.
    let matching = force_stop_request(&command_id);
    let second = service
        .submit_command(authed_request_as("op-token-bob", matching))
        .await
        .expect("the legitimate second approval must still succeed")
        .into_inner();
    assert!(!second.awaiting_second_approval);
}

/// Once a `force_stop` has actually been recorded, a later idempotent
/// resubmission (the approving operator retrying after a lost response,
/// for example -- the realistic retry case, since bob's own client is
/// what resubmits its own unacknowledged call) is treated as an ordinary
/// duplicate, not sent back through the approval gate a second time.
#[tokio::test]
async fn an_already_recorded_force_stop_is_idempotent_not_re_gated() {
    let service = service_with_two_operators_and_one_agent();
    let command_id = fresh_command_id(0x9002);
    let request = force_stop_request(&command_id);
    service
        .submit_command(authed_request_as("op-token-alice", request.clone()))
        .await
        .unwrap();
    service
        .submit_command(authed_request_as("op-token-bob", request.clone()))
        .await
        .expect("second approval records the command");

    // Bob's own retry of the exact call that recorded it must not reset
    // the gate and must not require finding a second approver again.
    let retry = service
        .submit_command(authed_request_as("op-token-bob", request))
        .await
        .expect("an idempotent retry of an already-recorded force_stop must succeed")
        .into_inner();
    assert!(
        !retry.awaiting_second_approval,
        "an already-recorded command must never re-enter the approval gate"
    );
    assert!(retry.duplicate);
}

/// The control property this whole gate exists for: every other action
/// keeps its single-operator path completely unchanged. One operator, one
/// submission, immediately recorded and immediately visible to the
/// target -- contrasted directly against `force_stop` above.
#[tokio::test]
async fn only_force_stop_requires_dual_approval() {
    let service = service_with_two_operators_and_one_agent();
    for action in [
        proto::ControlAction::Stop,
        proto::ControlAction::Pause,
        proto::ControlAction::Resume,
        proto::ControlAction::Inject,
        proto::ControlAction::SetBudget,
    ] {
        let mut request = force_stop_request(&fresh_command_id(0xA000 + action as u64));
        request.action = action as i32;
        if action == proto::ControlAction::Inject {
            let mut fields = std::collections::BTreeMap::new();
            fields.insert(
                "content".to_owned(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue("hi".to_owned())),
                },
            );
            fields.insert(
                "content_classification".to_owned(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue("untrusted".to_owned())),
                },
            );
            request.parameters = Some(ProstStruct {
                fields: fields.into_iter().collect(),
            });
        }
        if action == proto::ControlAction::SetBudget {
            let mut fields = std::collections::BTreeMap::new();
            fields.insert(
                "budget_kind".to_owned(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue("tokens".to_owned())),
                },
            );
            fields.insert(
                "limit".to_owned(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::NumberValue(1000.0)),
                },
            );
            request.parameters = Some(ProstStruct {
                fields: fields.into_iter().collect(),
            });
        }
        let response = service
            .submit_command(authed_request_as("op-token-alice", request))
            .await
            .unwrap_or_else(|status| {
                panic!("a single operator must be able to submit {action:?}: {status:?}")
            })
            .into_inner();
        assert!(
            !response.awaiting_second_approval,
            "{action:?} must not require a second approval"
        );
    }
    let delivered = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        delivered.commands.len(),
        5,
        "every non-force_stop action must be immediately visible after one operator's submission"
    );
}

/// An operator without scope over the target workspace/namespace cannot
/// even register a first approval -- the scope check runs before the
/// approval gate, not after.
#[tokio::test]
async fn force_stop_rejects_a_scope_the_operator_does_not_hold() {
    let service = service_with_two_operators_and_one_agent();
    let mut request = force_stop_request(&fresh_command_id(0x9003));
    request.workspace_id = "other-workspace".to_owned();
    let status = service
        .submit_command(authed_request_as("op-token-alice", request))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}
