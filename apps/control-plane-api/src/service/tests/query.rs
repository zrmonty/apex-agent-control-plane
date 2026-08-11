//! The operator query/management path: `ListCommands` and `CancelCommand`.

use crate::auth::StaticOperatorTokenResolver;
use crate::inbox::*;
use crate::proto;
use crate::proto::control_gateway_server::ControlGateway as _;
use crate::service::*;

use super::support::*;

// --- ListCommands -----------------------------------------------------

fn list_request(
    bearer: &str,
    body: proto::ListCommandsRequest,
) -> tonic::Request<proto::ListCommandsRequest> {
    let mut request = tonic::Request::new(body);
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {bearer}").parse().unwrap());
    request
}

fn list_commands_request(
    workspace_id: &str,
    namespace_id: &str,
    agent_id: Option<&str>,
    state: proto::CommandDeliveryState,
    page_size: u32,
    page_token: &str,
) -> proto::ListCommandsRequest {
    proto::ListCommandsRequest {
        workspace_id: workspace_id.to_owned(),
        namespace_id: namespace_id.to_owned(),
        agent_id: agent_id.map(str::to_owned),
        state: state as i32,
        page_size,
        page_token: page_token.to_owned(),
    }
}

/// Seeds a command directly into the inbox's delivery state, bypassing
/// `submit_command`'s outbox write and operator admission ceiling. These
/// tests need many commands recorded quickly and are exercising
/// `ListCommands`, not admission or outbox durability, which are already
/// covered elsewhere.
fn seed_command(
    service: &ControlGatewayService<StaticOperatorTokenResolver>,
    workspace_id: &str,
    namespace_id: &str,
    agent_id: &str,
    command_id: &str,
) {
    let command = crate::inbox::PendingCommand {
        command_id: command_id.to_owned(),
        workspace_id: workspace_id.to_owned(),
        namespace_id: namespace_id.to_owned(),
        agent_id: agent_id.to_owned(),
        run_id: "run-1".to_owned(),
        trace_id: "trace-1".to_owned(),
        action: "stop".to_owned(),
        reason_code: Some("operator.request".to_owned()),
        parameters: Vec::new(),
        issued_at: "2026-08-08T00:00:00.000000Z".to_owned(),
        delivery_attempt: 0,
    };
    service
        .inbox
        .with_lock(|inbox| inbox.record(&command))
        .expect("lock must not be poisoned")
        .expect("a fresh command_id must record");
}

/// A second page requested with the first page's cursor must return the
/// next commands, not a repeat, and the response's `next_page_token`
/// must accurately signal whether more are available.
#[tokio::test]
async fn list_commands_pages_through_results_without_repeats_or_gaps() {
    let service = service();
    for index in 0..5 {
        seed_command(&service, "acme", "prod", "agent-a", &format!("cmd-{index}"));
    }

    let first = service
        .list_commands(list_request(
            "op-token",
            list_commands_request(
                "acme",
                "prod",
                None,
                proto::CommandDeliveryState::Unspecified,
                2,
                "",
            ),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        first
            .commands
            .iter()
            .map(|c| c.command_id.as_str())
            .collect::<Vec<_>>(),
        vec!["cmd-0", "cmd-1"]
    );
    assert!(!first.next_page_token.is_empty());

    let second = service
        .list_commands(list_request(
            "op-token",
            list_commands_request(
                "acme",
                "prod",
                None,
                proto::CommandDeliveryState::Unspecified,
                2,
                &first.next_page_token,
            ),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        second
            .commands
            .iter()
            .map(|c| c.command_id.as_str())
            .collect::<Vec<_>>(),
        vec!["cmd-2", "cmd-3"],
        "the second page must return the *next* commands, not a repeat of the first"
    );
    assert!(!second.next_page_token.is_empty());

    let third = service
        .list_commands(list_request(
            "op-token",
            list_commands_request(
                "acme",
                "prod",
                None,
                proto::CommandDeliveryState::Unspecified,
                2,
                &second.next_page_token,
            ),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        third.commands.iter().map(|c| c.command_id.as_str()).collect::<Vec<_>>(),
        vec!["cmd-4"]
    );
    assert!(
        third.next_page_token.is_empty(),
        "the last page must not claim more are available"
    );
}

/// The page-size ceiling is enforced even when a caller asks for more
/// than `MAX_LIST_COMMANDS_PAGE_SIZE`.
#[tokio::test]
async fn list_commands_enforces_the_page_size_ceiling() {
    let service = service();
    let total = crate::inbox::MAX_LIST_COMMANDS_PAGE_SIZE + 25;
    for index in 0..total {
        seed_command(&service, "acme", "prod", "agent-a", &format!("cmd-{index}"));
    }

    let response = service
        .list_commands(list_request(
            "op-token",
            list_commands_request(
                "acme",
                "prod",
                None,
                proto::CommandDeliveryState::Unspecified,
                u32::MAX,
                "",
            ),
        ))
        .await
        .expect("a clamped page_size must not be an error")
        .into_inner();
    assert_eq!(
        response.commands.len(),
        crate::inbox::MAX_LIST_COMMANDS_PAGE_SIZE,
        "asking for more than the ceiling must still be clamped to it"
    );
    assert!(
        !response.next_page_token.is_empty(),
        "more commands exist past the ceiling, so the response must say so"
    );
}

/// Mirrors `submit_command_rejects_a_scope_the_operator_does_not_hold`:
/// an operator cannot list another workspace's commands.
#[tokio::test]
async fn list_commands_rejects_a_scope_the_operator_does_not_hold() {
    let service = service();
    seed_command(&service, "acme", "prod", "agent-a", "cmd-scoped");

    let status = service
        .list_commands(list_request(
            "op-token",
            list_commands_request(
                "other-workspace",
                "prod",
                None,
                proto::CommandDeliveryState::Unspecified,
                0,
                "",
            ),
        ))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

/// `agent_id` and `state` both narrow the result, independently and
/// combined -- and combined means AND, not OR.
#[tokio::test]
async fn list_commands_filters_by_agent_id_and_state_and_can_combine_both() {
    let service = service_with_two_agents();
    seed_command(&service, "acme", "prod", "agent-a", "cmd-a1");
    // Deliver cmd-a1 so it is no longer Pending, before recording the
    // rest -- a poll claims every deliverable command for the agent, so
    // seeding cmd-a2 first would deliver both in one poll.
    service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .unwrap();
    seed_command(&service, "acme", "prod", "agent-a", "cmd-a2");
    seed_command(&service, "acme", "prod", "agent-b", "cmd-b1");

    let by_agent = service
        .list_commands(list_request(
            "op-token",
            list_commands_request(
                "acme",
                "prod",
                Some("agent-a"),
                proto::CommandDeliveryState::Unspecified,
                0,
                "",
            ),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(by_agent.commands.len(), 2);
    assert!(by_agent.commands.iter().all(|c| c.agent_id == "agent-a"));

    let by_state = service
        .list_commands(list_request(
            "op-token",
            list_commands_request(
                "acme",
                "prod",
                None,
                proto::CommandDeliveryState::CommandDeliveryPending,
                0,
                "",
            ),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(by_state.commands.len(), 2);
    assert!(
        by_state
            .commands
            .iter()
            .all(|c| c.state == proto::CommandDeliveryState::CommandDeliveryPending as i32)
    );

    let combined = service
        .list_commands(list_request(
            "op-token",
            list_commands_request(
                "acme",
                "prod",
                Some("agent-a"),
                proto::CommandDeliveryState::CommandDeliveryPending,
                0,
                "",
            ),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        combined.commands.len(),
        1,
        "agent-a AND Pending must match only cmd-a2, not every agent-a command"
    );
    assert_eq!(combined.commands[0].command_id, "cmd-a2");
}

// --- CancelCommand ----------------------------------------------------

fn cancel_request(
    workspace_id: &str,
    namespace_id: &str,
    command_id: &str,
) -> tonic::Request<proto::CancelCommandRequest> {
    let mut request = tonic::Request::new(proto::CancelCommandRequest {
        workspace_id: workspace_id.to_owned(),
        namespace_id: namespace_id.to_owned(),
        command_id: command_id.to_owned(),
    });
    request
        .metadata_mut()
        .insert("authorization", "Bearer op-token".parse().unwrap());
    request
}

fn status_request(
    workspace_id: &str,
    namespace_id: &str,
    command_id: &str,
) -> tonic::Request<proto::GetCommandStatusRequest> {
    let mut request = tonic::Request::new(proto::GetCommandStatusRequest {
        workspace_id: workspace_id.to_owned(),
        namespace_id: namespace_id.to_owned(),
        command_id: command_id.to_owned(),
    });
    request
        .metadata_mut()
        .insert("authorization", "Bearer op-token".parse().unwrap());
    request
}

/// The success path: an undelivered command can be cancelled, a repeat
/// cancellation is idempotent, and -- the property that actually matters
/// -- the target agent never sees it on a subsequent poll.
#[tokio::test]
async fn cancel_command_of_an_undelivered_command_succeeds_and_it_is_never_polled() {
    let service = service_with_two_agents();
    let command_id = submit_stop_for(&service, "agent-a", 0x800).await;

    let first = service
        .cancel_command(cancel_request("acme", "prod", &command_id))
        .await
        .unwrap()
        .into_inner();
    assert!(first.cancelled);
    assert!(!first.already_cancelled);

    let second = service
        .cancel_command(cancel_request("acme", "prod", &command_id))
        .await
        .unwrap()
        .into_inner();
    assert!(!second.cancelled);
    assert!(second.already_cancelled);

    let polled = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .unwrap()
        .into_inner();
    assert!(
        polled.commands.is_empty(),
        "a cancelled command must never be delivered to its agent"
    );

    let status = service
        .get_command_status(status_request("acme", "prod", &command_id))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        status.state,
        proto::CommandDeliveryState::CommandDeliveryCancelled as i32
    );
}

/// The refusal path: once a poll has handed a command to its agent even
/// once, the gateway must not cancel it out from under that delivery.
#[tokio::test]
async fn cancel_command_of_an_already_delivered_command_is_refused() {
    let service = service_with_two_agents();
    let command_id = submit_stop_for(&service, "agent-a", 0x801).await;
    let delivered = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(delivered.commands.len(), 1);

    let status = service
        .cancel_command(cancel_request("acme", "prod", &command_id))
        .await
        .expect_err("a delivered command must not be cancellable");
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);

    // Refused, not silently no-op'd: the command is still exactly as
    // delivered as it was, and a second poll after the redelivery window
    // must still be able to hand it back.
    let status = service
        .get_command_status(status_request("acme", "prod", &command_id))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        status.state,
        proto::CommandDeliveryState::CommandDeliveryDelivered as i32
    );
}

/// Mirrors `submit_command_rejects_a_scope_the_operator_does_not_hold`:
/// an operator may only cancel within the workspace/namespace scopes its
/// own credential holds, exactly the same gate `get_command_status`
/// applies.
#[tokio::test]
async fn cancel_command_rejects_a_scope_the_operator_does_not_hold() {
    let service = service();
    let status = service
        .cancel_command(cancel_request(
            "other-workspace",
            "prod",
            &fresh_command_id(0x802),
        ))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn cancel_command_of_an_unknown_command_id_reports_neither_flag_set() {
    let service = service();
    let response = service
        .cancel_command(cancel_request("acme", "prod", &fresh_command_id(0x803)))
        .await
        .unwrap()
        .into_inner();
    assert!(!response.cancelled);
    assert!(!response.already_cancelled);
}
