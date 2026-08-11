//! `SubmitBulkCommand` tests: the fan-out write path.

use prost_types::Struct as ProstStruct;

use crate::proto;
use crate::proto::control_gateway_server::ControlGateway as _;
use crate::service::*;

use super::support::*;

// --- SubmitBulkCommand -----------------------------------------------

fn bulk_target(
    workspace_id: &str,
    namespace_id: &str,
    agent_id: &str,
    run_id: &str,
    trace_id: &str,
) -> proto::BulkCommandTarget {
    proto::BulkCommandTarget {
        workspace_id: workspace_id.to_owned(),
        namespace_id: namespace_id.to_owned(),
        agent_id: agent_id.to_owned(),
        run_id: run_id.to_owned(),
        parent_run_id: None,
        trace_id: trace_id.to_owned(),
    }
}

fn bulk_stop_request(targets: Vec<proto::BulkCommandTarget>) -> proto::SubmitBulkCommandRequest {
    proto::SubmitBulkCommandRequest {
        bulk_id: None,
        targets,
        action: proto::ControlAction::Stop as i32,
        reason_code: Some("operator.request".to_owned()),
        parameters: Some(ProstStruct::default()),
    }
}

fn authed_bulk_request(
    body: proto::SubmitBulkCommandRequest,
) -> tonic::Request<proto::SubmitBulkCommandRequest> {
    let mut request = tonic::Request::new(body);
    request
        .metadata_mut()
        .insert("authorization", "Bearer op-token".parse().unwrap());
    request
}

#[tokio::test]
async fn submit_bulk_command_accepts_a_well_formed_request_and_fans_out_distinct_command_ids()
{
    let service = service();
    let targets = vec![
        bulk_target("acme", "prod", "agent-a", "run-a", "trace-a"),
        bulk_target("acme", "prod", "agent-b", "run-b", "trace-b"),
    ];
    let response = service
        .submit_bulk_command(authed_bulk_request(bulk_stop_request(targets)))
        .await
        .unwrap()
        .into_inner();
    assert!(!response.bulk_id.is_empty());
    assert_eq!(response.results.len(), 2);
    assert!(response.results.iter().all(|result| result.accepted));
    let ids: std::collections::HashSet<_> = response
        .results
        .iter()
        .map(|result| result.command_id.clone().unwrap())
        .collect();
    assert_eq!(ids.len(), 2, "every target must get its own command_id");
}

#[tokio::test]
async fn submit_bulk_command_rejects_an_empty_target_list() {
    let service = service();
    let status = service
        .submit_bulk_command(authed_bulk_request(bulk_stop_request(vec![])))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

/// The documented, hard ceiling on how many targets one call may name.
#[tokio::test]
async fn submit_bulk_command_rejects_a_request_over_the_target_ceiling() {
    let service = service();
    let targets: Vec<_> = (0..=MAX_BULK_COMMAND_TARGETS)
        .map(|index| bulk_target("acme", "prod", &format!("agent-{index}"), "run-1", "trace-1"))
        .collect();
    assert_eq!(targets.len(), MAX_BULK_COMMAND_TARGETS + 1);
    let status = service
        .submit_bulk_command(authed_bulk_request(bulk_stop_request(targets)))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);

    // Exactly at the ceiling must still be accepted.
    let at_ceiling: Vec<_> = (0..MAX_BULK_COMMAND_TARGETS)
        .map(|index| bulk_target("acme", "prod", &format!("agent-{index}"), "run-1", "trace-1"))
        .collect();
    let response = service
        .submit_bulk_command(authed_bulk_request(bulk_stop_request(at_ceiling)))
        .await
        .expect("exactly the ceiling must be accepted")
        .into_inner();
    assert_eq!(response.results.len(), MAX_BULK_COMMAND_TARGETS);
}

#[tokio::test]
async fn submit_bulk_command_rejects_an_unspecified_action_up_front() {
    let service = service();
    let mut request =
        bulk_stop_request(vec![bulk_target("acme", "prod", "agent-a", "run-a", "trace-a")]);
    request.action = proto::ControlAction::Unspecified as i32;
    let status = service
        .submit_bulk_command(authed_bulk_request(request))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn submit_bulk_command_rejects_missing_authentication() {
    let service = service();
    let request = tonic::Request::new(bulk_stop_request(vec![bulk_target(
        "acme", "prod", "agent-a", "run-a", "trace-a",
    )]));
    let status = service.submit_bulk_command(request).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

/// Partial failure is the normal outcome: some targets succeed, others
/// fail, and the response says exactly which failed and why -- using this
/// gateway's existing error taxonomy, not a bulk-specific one.
#[tokio::test]
async fn submit_bulk_command_reports_partial_failure_with_the_correct_per_target_reason() {
    let service = service();
    let targets = vec![
        bulk_target("acme", "prod", "agent-a", "run-a", "trace-a"),
        bulk_target("other-workspace", "prod", "agent-b", "run-b", "trace-b"),
    ];
    let response = service
        .submit_bulk_command(authed_bulk_request(bulk_stop_request(targets)))
        .await
        .expect("a bulk call with at least one authorized target must not fail wholesale")
        .into_inner();
    assert_eq!(response.results.len(), 2);

    let ok = &response.results[0];
    assert!(ok.accepted);
    assert_eq!(ok.agent_id, "agent-a");
    assert!(ok.command_id.is_some());
    assert!(ok.error_code.is_none());

    let denied = &response.results[1];
    assert!(!denied.accepted);
    assert_eq!(denied.agent_id, "agent-b");
    assert!(denied.command_id.is_none());
    assert_eq!(denied.error_code.as_deref(), Some("SCOPE_DENIED"));
    assert!(denied.error_message.is_some());
}

/// **The mandatory isolation test.** An operator scoped to exactly one
/// workspace/namespace must not be able to reach a different one by
/// folding it into a bulk call alongside targets it actually holds. Every
/// target's scope is checked independently -- the same
/// `operator.allows_scope` check `SubmitCommand` already applies, run
/// once per target -- so smuggling an out-of-scope target in among
/// in-scope ones changes nothing about whether that target is denied.
#[tokio::test]
async fn submit_bulk_command_cannot_reach_a_scope_the_operator_could_not_target_individually()
{
    let service = service(); // operator:zack is scoped to exactly acme/prod.
    let in_scope = bulk_target("acme", "prod", "agent-a", "run-a", "trace-a");
    let different_namespace = bulk_target("acme", "staging", "agent-b", "run-b", "trace-b");
    let different_workspace =
        bulk_target("other-workspace", "prod", "agent-c", "run-c", "trace-c");

    let response = service
        .submit_bulk_command(authed_bulk_request(bulk_stop_request(vec![
            in_scope,
            different_namespace,
            different_workspace,
        ])))
        .await
        .expect("the in-scope target must still be accepted")
        .into_inner();

    assert_eq!(response.results.len(), 3);
    assert!(
        response.results[0].accepted,
        "the in-scope target must be accepted"
    );
    for out_of_scope in &response.results[1..] {
        assert!(
            !out_of_scope.accepted,
            "a scope the operator does not hold must never be reachable via bulk: {out_of_scope:?}"
        );
        assert_eq!(out_of_scope.error_code.as_deref(), Some("SCOPE_DENIED"));
    }

    // Cross-check against the single-target path: the same scope is
    // refused there too, proving bulk grants nothing beyond what N
    // individual `SubmitCommand` calls would have.
    let mut single = stop_request();
    single.workspace_id = "acme".to_owned();
    single.namespace_id = "staging".to_owned();
    let status = service
        .submit_command(authed_request(single))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

/// Every fanned-out command is a real, independently-tracked command:
/// each agent polls and sees only its own, each is ackable on its own,
/// and `GetCommandStatus` reports each one's own state -- exactly the
/// same paths a single-target `SubmitCommand` already exercises.
#[tokio::test]
async fn each_bulk_fanned_out_command_is_independently_pollable_ackable_and_queryable() {
    let service = service_with_two_agents();
    let targets = vec![
        bulk_target("acme", "prod", "agent-a", "run-a", "trace-a"),
        bulk_target("acme", "prod", "agent-b", "run-b", "trace-b"),
    ];
    let response = service
        .submit_bulk_command(authed_bulk_request(bulk_stop_request(targets)))
        .await
        .unwrap()
        .into_inner();
    assert!(response.results.iter().all(|result| result.accepted));
    let command_id_a = response.results[0].command_id.clone().unwrap();
    let command_id_b = response.results[1].command_id.clone().unwrap();
    assert_ne!(command_id_a, command_id_b);

    // Each agent polls and sees only the command fanned out to it.
    let delivered_a = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(delivered_a.commands.len(), 1);
    assert_eq!(delivered_a.commands[0].command_id, command_id_a);

    let delivered_b = service
        .poll_commands(poll_request("agent-b-token-abcdefgh", peer(0xbb)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(delivered_b.commands.len(), 1);
    assert_eq!(delivered_b.commands[0].command_id, command_id_b);

    // Agent A acks its own delivery.
    let mut ack_a = tonic::Request::new(proto::AckCommandRequest {
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        command_id: command_id_a.clone(),
        delivery_attempt: 1,
    });
    ack_a.metadata_mut().insert(
        "authorization",
        "Bearer agent-a-token-abcdefgh".parse().unwrap(),
    );
    ack_a.extensions_mut().insert(peer(0xaa));
    let ack_a_result = service.ack_command(ack_a).await.unwrap().into_inner();
    assert!(ack_a_result.acknowledged);

    // Querying each is independent: A is acknowledged, B is merely
    // delivered -- acking one fanned-out command must never affect
    // another's state.
    let mut status_a = tonic::Request::new(proto::GetCommandStatusRequest {
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        command_id: command_id_a,
    });
    status_a
        .metadata_mut()
        .insert("authorization", "Bearer op-token".parse().unwrap());
    let status_a = service
        .get_command_status(status_a)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        status_a.state,
        proto::CommandDeliveryState::CommandDeliveryAcknowledged as i32
    );

    let mut status_b = tonic::Request::new(proto::GetCommandStatusRequest {
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        command_id: command_id_b,
    });
    status_b
        .metadata_mut()
        .insert("authorization", "Bearer op-token".parse().unwrap());
    let status_b = service
        .get_command_status(status_b)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        status_b.state,
        proto::CommandDeliveryState::CommandDeliveryDelivered as i32
    );
}

/// Resubmitting the same `bulk_id` against the same targets must be a
/// no-op duplicate for every target -- the same idempotency contract
/// `SubmitCommand` gives one `command_id`, extended across the batch via
/// `derive_target_command_id` rather than requiring the operator to track
/// one idempotency key per target.
#[tokio::test]
async fn resubmitting_the_same_bulk_id_and_targets_is_idempotent_for_every_target() {
    let service = service_with_two_agents();
    let mut request = bulk_stop_request(vec![
        bulk_target("acme", "prod", "agent-a", "run-a", "trace-a"),
        bulk_target("acme", "prod", "agent-b", "run-b", "trace-b"),
    ]);
    request.bulk_id = Some(fresh_command_id(0x900));

    let first = service
        .submit_bulk_command(authed_bulk_request(request.clone()))
        .await
        .unwrap()
        .into_inner();
    let second = service
        .submit_bulk_command(authed_bulk_request(request))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(first.bulk_id, second.bulk_id);
    assert_eq!(first.results.len(), second.results.len());
    for (initial, retry) in first.results.iter().zip(second.results.iter()) {
        assert!(initial.accepted && retry.accepted);
        assert_eq!(initial.command_id, retry.command_id);
        assert_eq!(initial.duplicate, Some(false));
        assert_eq!(retry.duplicate, Some(true));
    }

    // And the retry did not queue a second delivery for either agent.
    let delivered_a = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(delivered_a.commands.len(), 1);
}

/// The per-operator admission ceiling `SubmitCommand` enforces once per
/// call is charged once per *target* inside a bulk call -- a bulk call
/// cannot admit more durable commands per second than the same operator
/// issuing them one at a time already could.
#[tokio::test]
async fn submit_bulk_command_charges_the_admission_ceiling_once_per_target() {
    let service = service();
    // Consume all but 2 units of the operator's per-window budget with
    // ordinary single-target submissions first.
    for index in 0..(DEFAULT_MAX_COMMANDS_PER_WINDOW - 2) {
        let mut request = stop_request();
        request.command_id = Some(fresh_command_id(u64::from(index)));
        service
            .submit_command(authed_request(request))
            .await
            .unwrap();
    }

    let targets = vec![
        bulk_target("acme", "prod", "agent-a", "run-a", "trace-a"),
        bulk_target("acme", "prod", "agent-b", "run-b", "trace-b"),
        bulk_target("acme", "prod", "agent-c", "run-c", "trace-c"),
    ];
    let response = service
        .submit_bulk_command(authed_bulk_request(bulk_stop_request(targets)))
        .await
        .unwrap()
        .into_inner();

    let accepted = response.results.iter().filter(|r| r.accepted).count();
    assert_eq!(
        accepted, 2,
        "only the 2 remaining units of admission budget must be granted"
    );
    let denied = response
        .results
        .iter()
        .find(|r| !r.accepted)
        .expect("the third target must have been rejected");
    assert_eq!(denied.error_code.as_deref(), Some("RATE_LIMITED"));
}
