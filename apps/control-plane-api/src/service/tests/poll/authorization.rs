// Agent polling tests for authorization.

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
