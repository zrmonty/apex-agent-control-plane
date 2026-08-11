//! The live proofs of cross-agent and cross-credential-space isolation.

use apex_control_plane_api::proto;

use super::support::*;

/// The cross-agent isolation claim, live. Two real workloads, two real client
/// certificates, one workspace/namespace between them: agent B must not be
/// able to retrieve a command targeting agent A, and asking for the maximum
/// number of commands must not change that.
#[tokio::test]
async fn a_second_agent_workload_cannot_retrieve_the_first_ones_commands() {
    if !live_enabled() {
        eprintln!("skip live control poll: set APEX_CONTROL_LIVE_POLL=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();

    let response = submit_stop("reference-agent-isolation").await;
    let command_id = response.command_id;

    // Agent B: authenticates fine, resolves as itself, and sees nothing.
    let as_b = poll_as("agent-workload-b-client", "control-agent-tokens-b")
        .await
        .expect("agent B is a legitimate caller");
    assert_eq!(as_b.agent_id, "reference-agent-b");
    assert!(
        !as_b
            .commands
            .iter()
            .any(|command| command.command_id == command_id),
        "agent B retrieved a command targeting another agent"
    );

    // Agent A's credential presented from agent B's connection: refused. The
    // bearer credential is pinned to one client certificate, so a leaked token
    // is not by itself a way in.
    let mut client = proto::control_gateway_client::ControlGatewayClient::new(
        channel("agent-workload-b-client").await,
    );
    let mut request = tonic::Request::new(proto::PollCommandsRequest { max_commands: 0 });
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", agent_token("control-agent-tokens-a"))
            .parse()
            .unwrap(),
    );
    let status = client
        .poll_commands(request)
        .await
        .expect_err("agent A's token from agent B's certificate must be refused");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

/// ADR-0006's credential separation, carried inward to the two RPCs. Issuing a
/// command and retrieving one are different authorities.
#[tokio::test]
async fn the_operator_and_agent_credential_spaces_do_not_overlap() {
    if !live_enabled() {
        eprintln!("skip live control poll: set APEX_CONTROL_LIVE_POLL=1");
        return;
    }
    apex_control_plane_api::install_rustls_provider();

    // Operator certificate + operator token on the poll path: refused.
    let mut client = proto::control_gateway_client::ControlGatewayClient::new(
        channel("control-operator-client").await,
    );
    let mut poll = tonic::Request::new(proto::PollCommandsRequest { max_commands: 0 });
    poll.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", operator_token()).parse().unwrap(),
    );
    assert_eq!(
        client
            .poll_commands(poll)
            .await
            .expect_err("an operator credential must not be able to poll")
            .code(),
        tonic::Code::Unauthenticated
    );

    // Agent certificate + agent token on the submit path: refused.
    let mut agent_client = proto::control_gateway_client::ControlGatewayClient::new(
        channel("agent-workload-client").await,
    );
    let mut submit = tonic::Request::new(stop_command("reference-agent"));
    submit.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", agent_token("control-agent-tokens-a"))
            .parse()
            .unwrap(),
    );
    assert_eq!(
        agent_client
            .submit_command(submit)
            .await
            .expect_err("an agent credential must not be able to submit")
            .code(),
        tonic::Code::Unauthenticated
    );
}
