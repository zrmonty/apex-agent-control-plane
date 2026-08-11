//! The agent-facing path: `PollCommands` and `AckCommand`.

use prost_types::Struct as ProstStruct;

use crate::inbox::*;
use crate::proto;
use crate::proto::control_gateway_server::ControlGateway as _;
use crate::service::*;

use super::support::*;

// --- PollCommands ---------------------------------------------------

#[tokio::test]
async fn an_agent_retrieves_the_stop_command_issued_against_it() {
    let service = service_with_two_agents();
    let command_id = submit_stop_for(&service, "agent-a", 0x100).await;

    let response = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .expect("a registered agent must be able to poll")
        .into_inner();

    assert_eq!(response.agent_id, "agent-a");
    assert_eq!(response.commands.len(), 1);
    let command = &response.commands[0];
    assert_eq!(command.command_id, command_id);
    assert_eq!(command.action, proto::ControlAction::Stop as i32);
    assert_eq!(command.agent_id, "agent-a");
    assert_eq!(command.delivery_attempt, 1);
    assert!(!command.issued_at.is_empty());
    assert!(response.min_poll_interval_seconds >= 1);
}

/// `resolve_hold` delivers an operator's approve/deny decision back to an
/// agent blocked on a specific hold. Recorded directly against the
/// inbox (rather than through `submit_command`) because parameter-shape
/// validation for this action's `hold_token`/`decision`/`reason` payload
/// lives in `apex_event_ingest::validate_control_data`
/// (`apps/event-ingest/src/validation/control.rs`), a shared boundary
/// this change deliberately leaves untouched (see the commit message);
/// that crate still needs `resolve_hold` added to its own action
/// allow-list before `SubmitCommand` accepts one end to end. This test
/// proves what is in scope here: the poll/delivery path -- `is_recordable`
/// (`inbox.rs`) and the action mapping in `pending_to_proto` below --
/// carries a `resolve_hold` command and its parameters through exactly
/// like the other five actions.
#[tokio::test]
async fn an_agent_retrieves_a_directly_recorded_resolve_hold_command() {
    let service = service_with_two_agents();
    let mut fields = std::collections::BTreeMap::new();
    fields.insert(
        "hold_token".to_owned(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(
                "hold-abc123".to_owned(),
            )),
        },
    );
    fields.insert(
        "decision".to_owned(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue("approved".to_owned())),
        },
    );
    fields.insert(
        "reason".to_owned(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(
                "looks legitimate".to_owned(),
            )),
        },
    );
    let parameters = ProstStruct {
        fields: fields.into_iter().collect(),
    };
    let command = PendingCommand {
        command_id: fresh_command_id(0x900),
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        agent_id: "agent-a".to_owned(),
        run_id: "run-1".to_owned(),
        trace_id: "trace-1".to_owned(),
        action: "resolve_hold".to_owned(),
        reason_code: Some("operator.request".to_owned()),
        parameters: prost::Message::encode_to_vec(&parameters),
        issued_at: "2026-08-08T00:00:00.000000Z".to_owned(),
        delivery_attempt: 0,
    };
    service
        .inbox
        .with_lock(|inbox| inbox.record(&command))
        .unwrap()
        .unwrap();

    let response = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.commands.len(), 1);
    let delivered = &response.commands[0];
    assert_eq!(delivered.command_id, command.command_id);
    assert_eq!(delivered.action, proto::ControlAction::ResolveHold as i32);
    let delivered_parameters = delivered
        .parameters
        .as_ref()
        .expect("resolve_hold parameters must decode");
    assert_eq!(
        delivered_parameters
            .fields
            .get("hold_token")
            .and_then(|value| value.kind.as_ref()),
        Some(&prost_types::value::Kind::StringValue(
            "hold-abc123".to_owned()
        ))
    );
    assert_eq!(
        delivered_parameters
            .fields
            .get("decision")
            .and_then(|value| value.kind.as_ref()),
        Some(&prost_types::value::Kind::StringValue(
            "approved".to_owned()
        ))
    );
}

#[tokio::test]
async fn an_agent_acknowledges_a_delivery_and_retries_are_idempotent() {
    let service = service_with_two_agents();
    let command_id = submit_stop_for(&service, "agent-a", 0x101).await;
    let delivered = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .unwrap()
        .into_inner();
    let command = &delivered.commands[0];

    let mut ack = tonic::Request::new(proto::AckCommandRequest {
        workspace_id: command.workspace_id.clone(),
        namespace_id: command.namespace_id.clone(),
        command_id: command.command_id.clone(),
        delivery_attempt: command.delivery_attempt,
    });
    ack.metadata_mut().insert(
        "authorization",
        "Bearer agent-a-token-abcdefgh".parse().unwrap(),
    );
    ack.extensions_mut().insert(peer(0xaa));
    let first = service.ack_command(ack).await.unwrap().into_inner();
    assert_eq!(first.command_id, command_id);
    assert!(first.acknowledged);
    assert!(!first.already_acknowledged);

    let empty = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .unwrap()
        .into_inner();
    assert!(empty.commands.is_empty());

    let mut retry = tonic::Request::new(proto::AckCommandRequest {
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        command_id: command_id.clone(),
        delivery_attempt: 1,
    });
    retry.metadata_mut().insert(
        "authorization",
        "Bearer agent-a-token-abcdefgh".parse().unwrap(),
    );
    retry.extensions_mut().insert(peer(0xaa));
    let second = service.ack_command(retry).await.unwrap().into_inner();
    assert!(!second.acknowledged);
    assert!(second.already_acknowledged);

    let mut status = tonic::Request::new(proto::GetCommandStatusRequest {
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        command_id,
    });
    status
        .metadata_mut()
        .insert("authorization", "Bearer op-token".parse().unwrap());
    let status = service
        .get_command_status(status)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        status.state,
        proto::CommandDeliveryState::CommandDeliveryAcknowledged as i32
    );
    assert_eq!(status.delivery_attempt, 1);
}

#[tokio::test]
async fn command_status_distinguishes_pending_and_delivered_and_rejects_wrong_agent_ack() {
    let service = service_with_two_agents();
    let command_id = submit_stop_for(&service, "agent-a", 0x102).await;

    let mut status = tonic::Request::new(proto::GetCommandStatusRequest {
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        command_id: command_id.clone(),
    });
    status
        .metadata_mut()
        .insert("authorization", "Bearer op-token".parse().unwrap());
    let status = service
        .get_command_status(status)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        status.state,
        proto::CommandDeliveryState::CommandDeliveryPending as i32
    );
    assert_eq!(status.delivery_attempt, 0);

    let mut wrong_ack = tonic::Request::new(proto::AckCommandRequest {
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        command_id: command_id.clone(),
        delivery_attempt: 1,
    });
    wrong_ack.metadata_mut().insert(
        "authorization",
        "Bearer agent-b-token-abcdefgh".parse().unwrap(),
    );
    wrong_ack.extensions_mut().insert(peer(0xbb));
    let wrong_ack = service.ack_command(wrong_ack).await.unwrap().into_inner();
    assert!(!wrong_ack.acknowledged);
    assert!(!wrong_ack.already_acknowledged);

    let delivered = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(delivered.commands[0].delivery_attempt, 1);

    let mut status = tonic::Request::new(proto::GetCommandStatusRequest {
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        command_id,
    });
    status
        .metadata_mut()
        .insert("authorization", "Bearer op-token".parse().unwrap());
    let status = service
        .get_command_status(status)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        status.state,
        proto::CommandDeliveryState::CommandDeliveryDelivered as i32
    );
    assert_eq!(status.delivery_attempt, 1);
}

/// **The mandatory isolation test.** Agent B authenticates as itself and
/// polls; a `stop` targeting agent A must not come back, and there must be
/// no request field it could set to make it come back.
///
/// The second half is the part a scope check alone would not prove: both
/// agents hold `acme/prod`, so the only thing separating them is the
/// server-derived bound agent identity.
#[tokio::test]
async fn an_agent_cannot_retrieve_another_agents_commands() {
    let service = service_with_two_agents();
    let command_id = submit_stop_for(&service, "agent-a", 0x200).await;

    // Agent B polls with its own valid credential and its own certificate.
    let response = service
        .poll_commands(poll_request("agent-b-token-abcdefgh", peer(0xbb)))
        .await
        .expect("agent B is a legitimate caller")
        .into_inner();
    assert_eq!(response.agent_id, "agent-b");
    assert!(
        response.commands.is_empty(),
        "agent B retrieved a command targeting agent A: {:?}",
        response.commands
    );

    // ... and asking harder does not help: `max_commands` is the only
    // field on the request, and it can only narrow. There is no
    // agent_id/run_id/workspace selector to abuse -- which is the point,
    // and this assertion is here so that adding one is a test failure and
    // not a silent widening.
    let greedy = service
        .poll_commands(poll_request_for(
            "agent-b-token-abcdefgh",
            peer(0xbb),
            proto::PollCommandsRequest {
                max_commands: u32::MAX,
            },
        ))
        .await
        .expect("a clamped max_commands must not be an error")
        .into_inner();
    assert!(greedy.commands.is_empty());

    // The command is still there for its actual target, so the emptiness
    // above is isolation and not the command having gone missing.
    let owner = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(owner.commands.len(), 1);
    assert_eq!(owner.commands[0].command_id, command_id);
}

/// Stealing agent A's bearer token is not enough: it is bound to agent A's
/// client certificate, and agent B's connection presents a different one.
#[tokio::test]
async fn a_stolen_agent_token_is_useless_from_another_workload_connection() {
    let service = service_with_two_agents();
    submit_stop_for(&service, "agent-a", 0x300).await;
    let status = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xbb)))
        .await
        .expect_err("agent A's token from agent B's certificate must be refused");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

/// The operator credential space and the agent credential space are
/// disjoint in both directions. An operator holds the authority to *issue*
/// a stop, never the authority to read what is pending for an agent.
#[tokio::test]
async fn an_operator_credential_cannot_poll() {
    let service = service_with_two_agents();
    submit_stop_for(&service, "agent-a", 0x400).await;
    let status = service
        .poll_commands(poll_request("op-token", peer(0xaa)))
        .await
        .expect_err("an operator token must not authenticate on the poll path");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

/// ... and the reverse: an agent credential cannot submit a command.
#[tokio::test]
async fn an_agent_credential_cannot_submit_a_command() {
    let service = service_with_two_agents();
    let mut request = tonic::Request::new(stop_request());
    request.metadata_mut().insert(
        "authorization",
        "Bearer agent-a-token-abcdefgh".parse().unwrap(),
    );
    let status = service
        .submit_command(request)
        .await
        .expect_err("an agent credential must not authenticate on the submit path");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

/// A gateway that was never configured with agent credentials must serve
/// `PollCommands` to nobody, not to everybody.
#[tokio::test]
async fn a_gateway_with_no_agent_credentials_authenticates_no_agent() {
    let service = service();
    let status = service
        .poll_commands(poll_request("anything-at-all-here", peer(0xaa)))
        .await
        .expect_err("an unconfigured agent credential space must fail closed");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

/// mTLS is load-bearing on this path, not decoration: a caller the
/// transport did not give a client certificate for is refused before the
/// token is even considered.
#[tokio::test]
async fn a_poll_with_no_client_certificate_is_refused() {
    let service = service_with_two_agents();
    let mut request = tonic::Request::new(proto::PollCommandsRequest { max_commands: 0 });
    request.metadata_mut().insert(
        "authorization",
        "Bearer agent-a-token-abcdefgh".parse().unwrap(),
    );
    let status = service
        .poll_commands(request)
        .await
        .expect_err("strict peer requirement must refuse a certificate-less caller");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

/// A command an agent has already retrieved is not handed to it again on
/// the next poll, so a 1-second cadence does not re-enact a `stop` dozens
/// of times. Redelivery after the window is covered in `inbox.rs`, where
/// the clock is injectable.
#[tokio::test]
async fn a_retrieved_command_is_not_immediately_redelivered() {
    let service = service_with_two_agents();
    submit_stop_for(&service, "agent-a", 0x500).await;
    let first = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first.commands.len(), 1);
    let second = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .unwrap()
        .into_inner();
    assert!(second.commands.is_empty());
}

/// An agent polling aggressively must be bounded, or one workload can
/// degrade the control channel for every other workload sharing the
/// gateway.
#[tokio::test]
async fn poll_is_rate_limited_per_agent_after_the_ceiling() {
    let service = service_with_two_agents();
    for _ in 0..DEFAULT_MAX_POLLS_PER_WINDOW {
        service
            .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
            .await
            .expect("polls inside the ceiling must succeed");
    }
    let status = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .expect_err("the poll ceiling must be enforced");
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);

    // ... and the ceiling is per agent: a second workload is unaffected by
    // the first one's behaviour, or one noisy agent becomes an outage for
    // everybody.
    service
        .poll_commands(poll_request("agent-b-token-abcdefgh", peer(0xbb)))
        .await
        .expect("a different agent must have its own budget");
}

/// `AckCommand` shares `PollCommands`' per-agent `admit_poll` ceiling and the
/// gateway's shared `storage_slots` pool with every other RPC. Without its
/// own admission check, an agent could spend an unbounded number of
/// `AckCommand` calls against that shared pool -- starving `PollCommands`,
/// and every operator's `SubmitCommand`, for everyone else on the process.
/// The command_id here is deliberately never recorded: admission is charged
/// before the inbox is ever consulted, so an unknown command_id still counts
/// against the ceiling exactly like a real one would.
#[tokio::test]
async fn ack_command_is_rate_limited_per_agent_after_the_ceiling() {
    let service = service_with_two_agents();
    let ack_request = |token: &str, peer_id: u8| {
        let mut request = tonic::Request::new(proto::AckCommandRequest {
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            command_id: "does-not-exist".to_owned(),
            delivery_attempt: 1,
        });
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request.extensions_mut().insert(peer(peer_id));
        request
    };
    for _ in 0..DEFAULT_MAX_POLLS_PER_WINDOW {
        service
            .ack_command(ack_request("agent-a-token-abcdefgh", 0xaa))
            .await
            .expect("acks inside the ceiling must succeed");
    }
    let status = service
        .ack_command(ack_request("agent-a-token-abcdefgh", 0xaa))
        .await
        .expect_err("the poll ceiling must be enforced on AckCommand too");
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);

    // ... and the ceiling is per agent, same as PollCommands'.
    service
        .ack_command(ack_request("agent-b-token-abcdefgh", 0xbb))
        .await
        .expect("a different agent must have its own budget");
}

#[test]
fn the_poll_rate_limit_key_is_disjoint_from_the_operator_one() {
    let subject = "spiffe://apex/workload/agent-a";
    let poll = control_poll_rate_limit_key(subject);
    let operator = control_admission_rate_limit_key(subject);
    // Same namespace on purpose (see the key function's own comment: a
    // second namespace would fall outside the deployment's Valkey ACL
    // pattern and the shared ceiling would silently stop applying) ...
    assert_eq!(poll.namespace, operator.namespace);
    // ... and disjoint buckets, so an agent's polls can never consume an
    // operator's command budget or vice versa.
    assert_ne!(poll.bucket, operator.bucket);
    assert!(!poll.bucket.contains("agent-a"));
    // Both must satisfy the store's own key grammar, or every
    // check_rate_limit call errors and the shared ceiling never applies.
    let mut store = apex_event_ingest::InMemoryEphemeralStore::new();
    assert!(
        store
            .check_rate_limit(&poll, 1, Duration::from_secs(1))
            .is_ok()
    );
}

/// The delivery record has to be written by the accept path, not by some
/// later worker: a command accepted while the agent is offline must be
/// waiting when it comes back.
#[tokio::test]
async fn a_command_accepted_before_the_agent_polls_is_waiting_for_it() {
    let service = service_with_two_agents();
    submit_stop_for(&service, "agent-a", 0x600).await;
    submit_stop_for(&service, "agent-a", 0x601).await;
    let response = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.commands.len(), 2);
}

/// An operator's idempotent resubmission must not queue a second delivery
/// of the same command.
#[tokio::test]
async fn a_duplicate_submission_does_not_queue_a_second_delivery() {
    let service = service_with_two_agents();
    let mut request = stop_request();
    request.agent_id = "agent-a".to_owned();
    request.command_id = Some(fresh_command_id(0x700));
    service
        .submit_command(authed_request(request.clone()))
        .await
        .unwrap();
    service
        .submit_command(authed_request(request))
        .await
        .unwrap();
    let response = service
        .poll_commands(poll_request("agent-a-token-abcdefgh", peer(0xaa)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.commands.len(), 1);
}

#[tokio::test]
async fn submit_command_rejects_a_negative_budget_limit() {
    let service = service();
    let mut request = stop_request();
    request.action = proto::ControlAction::SetBudget as i32;
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
            kind: Some(prost_types::value::Kind::NumberValue(-1.0)),
        },
    );
    request.parameters = Some(ProstStruct {
        fields: fields.into_iter().collect(),
    });
    let status = service
        .submit_command(authed_request(request))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}
