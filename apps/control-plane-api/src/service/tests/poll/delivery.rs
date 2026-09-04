// Agent polling tests for delivery.

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
/// lives in `apex_durability::validate_control_data`
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
