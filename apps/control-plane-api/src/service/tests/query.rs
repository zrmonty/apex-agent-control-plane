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

// --- Admission (shared per-operator ceiling) ---------------------------
//
// `GetCommandStatus`, `ListCommands`, and `CancelCommand` used to be the
// only three RPCs on this service that authenticated and scope-checked the
// caller but never charged `self.admit(operator.subject())`. That let one
// valid-but-unthrottled operator credential hold an unbounded share of the
// shared `storage_slots` semaphore (`service.rs`, `MAX_STORAGE_OPERATIONS`)
// via a tight query loop, starving `SubmitCommand` calls -- including a
// `stop`/`force_stop` from a *different* operator -- of storage permits.
// These tests pin that all three now charge the same ceiling
// `SubmitCommand` already enforces, using `.with_admission_limits` (the
// pattern `admission.rs` uses) to make the ceiling reachable without
// sending dozens of real requests or racing the 1-second default window.

#[tokio::test]
async fn get_command_status_rate_limits_a_single_operator_after_the_configured_ceiling() {
    let service = service().with_admission_limits(3, std::time::Duration::from_secs(60));
    let command_id = fresh_command_id(0x900);
    for _ in 0..3 {
        service
            .get_command_status(status_request("acme", "prod", &command_id))
            .await
            .unwrap();
    }
    let status = service
        .get_command_status(status_request("acme", "prod", &command_id))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);
}

/// Also pins that the admission cost is exactly one unit per *call*, not
/// per result or per requested `page_size`: every one of the three calls
/// below asks for, and receives, a full `MAX_LIST_COMMANDS_PAGE_SIZE` page.
/// If `do_list_commands` ever charged admission proportionally to
/// `page_size` or to the number of rows returned, the 3-call ceiling would
/// be exhausted before this test reaches its final, expected rejection.
#[tokio::test]
async fn list_commands_rate_limits_a_single_operator_after_the_configured_ceiling_regardless_of_page_size() {
    let service = service().with_admission_limits(3, std::time::Duration::from_secs(60));
    for index in 0..crate::inbox::MAX_LIST_COMMANDS_PAGE_SIZE + 25 {
        seed_command(&service, "acme", "prod", "agent-a", &format!("cmd-{index}"));
    }
    let big_page_request = || {
        list_commands_request(
            "acme",
            "prod",
            None,
            proto::CommandDeliveryState::Unspecified,
            crate::inbox::MAX_LIST_COMMANDS_PAGE_SIZE as u32,
            "",
        )
    };
    for _ in 0..3 {
        let response = service
            .list_commands(list_request("op-token", big_page_request()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            response.commands.len(),
            crate::inbox::MAX_LIST_COMMANDS_PAGE_SIZE,
            "each call in this loop must return a genuinely full page"
        );
    }
    let status = service
        .list_commands(list_request("op-token", big_page_request()))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);
}

#[tokio::test]
async fn cancel_command_rate_limits_a_single_operator_after_the_configured_ceiling() {
    let service = service().with_admission_limits(3, std::time::Duration::from_secs(60));
    // An unknown command_id still returns `Ok` with both flags unset (see
    // `cancel_command_of_an_unknown_command_id_reports_neither_flag_set`
    // above), so looping on one never-recorded id isolates the admission
    // ceiling from `cancel`'s own state machine.
    let command_id = fresh_command_id(0x901);
    for _ in 0..3 {
        service
            .cancel_command(cancel_request("acme", "prod", &command_id))
            .await
            .unwrap();
    }
    let status = service
        .cancel_command(cancel_request("acme", "prod", &command_id))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);
}

/// The fix's design choice, pinned directly: these three RPCs must charge
/// the *same* per-operator bucket `SubmitCommand` does, not a second,
/// query-specific ceiling (see `service.rs`'s `admit`/`admission` doc).
/// Interleaving submissions and status checks from one operator must
/// exhaust one shared ceiling exactly as fast as either kind alone.
#[tokio::test]
async fn submit_and_query_rpcs_share_one_admission_ceiling_per_operator() {
    let service = service().with_admission_limits(4, std::time::Duration::from_secs(60));

    let mut first_submit = stop_request();
    first_submit.command_id = Some(fresh_command_id(0x9100));
    service
        .submit_command(authed_request(first_submit))
        .await
        .unwrap();
    let mut second_submit = stop_request();
    second_submit.command_id = Some(fresh_command_id(0x9101));
    service
        .submit_command(authed_request(second_submit))
        .await
        .unwrap();

    let command_id = fresh_command_id(0x902);
    service
        .get_command_status(status_request("acme", "prod", &command_id))
        .await
        .unwrap();
    service
        .get_command_status(status_request("acme", "prod", &command_id))
        .await
        .unwrap();

    // The ceiling of 4 is now spent: 2 submissions + 2 status checks. A
    // 5th call of either kind must be rejected -- proving the two RPC
    // families draw from one bucket rather than independent ones.
    let status = service
        .get_command_status(status_request("acme", "prod", &command_id))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);
}
