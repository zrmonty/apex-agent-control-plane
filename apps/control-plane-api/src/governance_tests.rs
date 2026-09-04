use super::proto;
use super::{GatewayTokenAuthenticator, GovernanceConfig, GovernanceGatewayService};
use tonic::metadata::{MetadataMap, MetadataValue};

#[tokio::test]
async fn governance_wire_contract_exposes_typed_rpc_surface() {
    let request = proto::GovernanceAuthorizationRequest {
        caller: Some(proto::GovernanceCaller {
            principal: "spiffe://apex/agent/research".to_owned(),
            agent_id: "research-agent".to_owned(),
        }),
        scope: Some(proto::GovernanceScope {
            workspace_id: "northstar".to_owned(),
            namespace_id: "research".to_owned(),
        }),
        tool: "portfolio.read".to_owned(),
        action: "read".to_owned(),
        resource:
            "portfolio:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
        classification: "confidential".to_owned(),
        trace: Some(proto::GovernanceTrace {
            trace_id: "trace-001".to_owned(),
            span_id: "span-001".to_owned(),
        }),
    };
    assert_eq!(request.tool, "portfolio.read");
    assert_eq!(proto::GovernanceOutcome::Allowed as i32, 1);
    assert_eq!(proto::GovernanceOutcome::Denied as i32, 2);
    assert_eq!(proto::GovernanceOutcome::RequiresApproval as i32, 3);

    let _client = proto::governance_gateway_client::GovernanceGatewayClient::new(
        tonic::transport::Channel::from_static("http://127.0.0.1:1").connect_lazy(),
    );
}

fn config() -> GovernanceConfig {
    GovernanceConfig::new(
        ["northstar-401k"],
        ["northstar/research"],
        "apex-mcp-read-v1",
        1,
        [
            "client.account_number",
            "client.tax_id",
            "positions.cost_basis",
        ],
    )
    .expect("valid governance config")
}

fn request(resource: &str) -> proto::GovernanceAuthorizationRequest {
    proto::GovernanceAuthorizationRequest {
        caller: Some(proto::GovernanceCaller {
            principal: "spiffe://apex/agent/research".to_owned(),
            agent_id: "research-agent".to_owned(),
        }),
        scope: Some(proto::GovernanceScope {
            workspace_id: "northstar".to_owned(),
            namespace_id: "research".to_owned(),
        }),
        tool: "portfolio.read".to_owned(),
        action: "read".to_owned(),
        resource: resource.to_owned(),
        classification: "confidential".to_owned(),
        trace: Some(proto::GovernanceTrace {
            trace_id: "trace-001".to_owned(),
            span_id: "span-001".to_owned(),
        }),
    }
}

fn auth(token: &str) -> GatewayTokenAuthenticator {
    GatewayTokenAuthenticator::new(token).expect("valid test token")
}

fn metadata(value: &str) -> MetadataMap {
    let mut metadata = MetadataMap::new();
    metadata.insert(
        "authorization",
        MetadataValue::try_from(format!("Bearer {value}")).expect("ascii metadata"),
    );
    metadata
}

#[tokio::test]
async fn governance_authorizes_only_configured_portfolio_and_scope() {
    let service = GovernanceGatewayService::new(config(), auth("gateway-secret-123456"));
    let mut allowed = tonic::Request::new(request(
        "portfolio:sha256:8994d7d97baa4a58a0fbc8192815c60605caa16a9106d50af6548810f52eaf31",
    ));
    allowed.metadata_mut().insert(
        "authorization",
        metadata("gateway-secret-123456")
            .get("authorization")
            .expect("token")
            .clone(),
    );
    let response = <GovernanceGatewayService as proto::governance_gateway_server::GovernanceGateway>::authorize(&service, allowed)
        .await
        .expect("governance request succeeds")
        .into_inner();
    assert_eq!(response.outcome, proto::GovernanceOutcome::Allowed as i32);
    assert_eq!(response.policy_id, "apex-mcp-read-v1");
    assert_eq!(response.field_restrictions.len(), 3);

    let mut denied = tonic::Request::new(request(
        "portfolio:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ));
    denied.metadata_mut().insert(
        "authorization",
        metadata("gateway-secret-123456")
            .get("authorization")
            .expect("token")
            .clone(),
    );
    let response = <GovernanceGatewayService as proto::governance_gateway_server::GovernanceGateway>::authorize(&service, denied)
        .await
        .expect("denials are typed decisions")
        .into_inner();
    assert_eq!(response.outcome, proto::GovernanceOutcome::Denied as i32);
    assert!(response.field_restrictions.is_empty());
}

#[tokio::test]
async fn governance_rejects_missing_or_operator_credentials() {
    let service = GovernanceGatewayService::new(config(), auth("gateway-secret-123456"));
    let missing = tonic::Request::new(request(
        "portfolio:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ));
    let error = <GovernanceGatewayService as proto::governance_gateway_server::GovernanceGateway>::authorize(&service, missing)
        .await
        .expect_err("missing service credential must fail closed");
    assert_eq!(error.code(), tonic::Code::Unauthenticated);

    let mut operator = tonic::Request::new(request(
        "portfolio:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ));
    operator.metadata_mut().insert(
        "authorization",
        metadata("operator-secret-123456")
            .get("authorization")
            .expect("token")
            .clone(),
    );
    let error = <GovernanceGatewayService as proto::governance_gateway_server::GovernanceGateway>::authorize(&service, operator)
        .await
        .expect_err("operator credential must not cross into governance");
    assert_eq!(error.code(), tonic::Code::Unauthenticated);
}
