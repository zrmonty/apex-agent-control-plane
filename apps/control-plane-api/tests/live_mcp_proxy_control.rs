//! Live mTLS proof for the managed MCP proxy control surface.
//!
//! The proof is opt-in (`APEX_CONTROL_LIVE_MCP_PROXY=1`) because it needs the
//! live PKI, a running control-plane endpoint, and PostgreSQL-backed proxy
//! state. If the endpoint is serving the contract but the runtime provider or
//! durable event sink is not wired, an enabled run fails with that explicit
//! prerequisite instead of claiming a lifecycle pass.

use std::path::PathBuf;
use std::time::Duration;

use apex_control_plane_api::proto;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
use tonic::{Request, Status};

const WORKSPACE: &str = "acme";
const NAMESPACE: &str = "prod";

fn enabled() -> bool {
    std::env::var("APEX_CONTROL_LIVE_MCP_PROXY").ok().as_deref() == Some("1")
}

fn endpoint() -> String {
    std::env::var("APEX_CONTROL_LIVE_MCP_PROXY_ENDPOINT")
        .or_else(|_| std::env::var("APEX_CONTROL_LIVE_ENDPOINT"))
        .unwrap_or_else(|_| "https://localhost:18446".to_owned())
}

fn secrets_dir() -> PathBuf {
    std::env::var("APEX_CONTROL_LIVE_SECRETS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../deploy/compose/live-mtls/secrets-host")
        })
}

fn secret(name: &str) -> Vec<u8> {
    let root = secrets_dir();
    let path = root.join(name);
    assert!(
        path.is_file(),
        "missing live fixture {name} under {}",
        root.display()
    );
    std::fs::read(path).expect("live fixture must be readable")
}

fn operator_token() -> String {
    let raw =
        String::from_utf8(secret("control-operator-tokens")).expect("operator table must be UTF-8");
    raw.split(';')
        .map(str::trim)
        .find(|entry| !entry.is_empty())
        .and_then(|entry| entry.rsplit_once('|'))
        .map(|(token, _)| token.to_owned())
        .expect("operator table must contain token|scope")
}

fn identity() -> Identity {
    Identity::from_pem(
        secret("control-operator-client.pem"),
        secret("control-operator-client.key"),
    )
}

async fn client()
-> proto::mcp_proxy_service_client::McpProxyServiceClient<tonic::transport::Channel> {
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(secret("ca.pem")))
        .domain_name("localhost")
        .identity(identity());
    let channel = Endpoint::from_shared(endpoint())
        .expect("live endpoint must parse")
        .tls_config(tls)
        .expect("live TLS config must build")
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(15))
        .connect()
        .await
        .expect("live control-plane endpoint must be reachable");
    OkClient::new(channel)
}

type OkClient = proto::mcp_proxy_service_client::McpProxyServiceClient<tonic::transport::Channel>;

fn authorized<T>(value: T) -> Request<T> {
    let mut request = Request::new(value);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", operator_token())
            .parse()
            .expect("operator token must be header-safe"),
    );
    request
}

fn id() -> String {
    uuid::Uuid::now_v7().hyphenated().to_string()
}

fn proxy_id() -> String {
    uuid::Uuid::now_v7().hyphenated().to_string()
}

fn spec() -> proto::McpProxySpec {
    proto::McpProxySpec {
        ingress: Some(proto::McpProxyIngress {
            transport: proto::McpProxyTransport::StreamableHttp as i32,
            exposure: proto::McpProxyExposure::Private as i32,
            host: "proxy.apex.test".to_owned(),
            path: "/mcp".to_owned(),
            allowed_origins: vec!["https://console.apex.test".to_owned()],
            protocol_revision: "2025-11-25".to_owned(),
            inbound_authentication_required: true,
        }),
        upstreams: vec![proto::McpProxyUpstreamBinding {
            upstream_id: "portfolio-upstream".to_owned(),
            display_name: "Portfolio upstream".to_owned(),
            transport: proto::McpProxyTransport::StreamableHttp as i32,
            endpoint_or_command_ref: "https://portfolio-api.apex.test/mcp".to_owned(),
            credential_ref: "secret://vault/upstreams/portfolio-reader".to_owned(),
            secret_refs: vec![],
            server_identity: "portfolio-api.apex.test".to_owned(),
            tool_catalog_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
        }],
        exposed_tools: vec![proto::McpProxyToolExposure {
            upstream_id: "portfolio-upstream".to_owned(),
            tool_name: "portfolio.read".to_owned(),
            alias: "portfolio.read".to_owned(),
            classification: proto::McpProxyToolClassification::Read as i32,
        }],
        cli_profiles: vec![],
        auth_bindings: vec![],
        governance_binding: Some(proto::McpProxyGovernanceBinding {
            policy_id: "ria-read-v1".to_owned(),
            approval_mode: "none".to_owned(),
            data_classification: "confidential".to_owned(),
            rate_limit: "60/m".to_owned(),
            concurrency_limit: "4".to_owned(),
            budget: "5000/d".to_owned(),
            retention: "30d".to_owned(),
        }),
        runtime_profile: Some(proto::McpProxyRuntimeProfile {
            image_digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
            cpu_limit: "500m".to_owned(),
            memory_limit: "256Mi".to_owned(),
            network_policy: "default-deny".to_owned(),
            filesystem_policy: "read-only-rootfs".to_owned(),
            rootless: true,
            egress_destinations: vec![proto::McpProxyEgressDestination {
                host: "portfolio-api.apex.test".to_owned(),
                port: 443,
                private_destination_allowance: proto::McpProxyPrivateDestinationAllowance::Denied
                    as i32,
            }],
        }),
    }
}

fn is_unwired(status: &Status) -> bool {
    status.code() == tonic::Code::FailedPrecondition
        && (status.message().contains("PROXY_EVENT_SINK_UNAVAILABLE")
            || status.message().contains("PROXY_RUNTIME_UNAVAILABLE"))
}

#[tokio::test]
async fn live_proxy_control_is_scope_bound_idempotent_and_revision_safe() {
    if !enabled() {
        eprintln!("skip live MCP proxy proof: set APEX_CONTROL_LIVE_MCP_PROXY=1");
        return;
    }

    let mut client = client().await;
    let proxy_id = proxy_id();
    let create_request = proto::CreateProxyRequest {
        request_id: id(),
        workspace_id: WORKSPACE.to_owned(),
        namespace_id: NAMESPACE.to_owned(),
        proxy_id: proxy_id.clone(),
        display_name: "Live managed proxy".to_owned(),
        slug: format!("live-mcp-proxy-{}", &proxy_id[..8]),
        description: Some("live control-plane proof".to_owned()),
        owner: Some("live-proof".to_owned()),
        tags: vec!["live".to_owned()],
    };

    let created = match client
        .create_proxy(authorized(create_request.clone()))
        .await
    {
        Ok(response) => response.into_inner(),
        Err(status) if is_unwired(&status) => panic!(
            "live MCP proxy prerequisite is not wired: {status}; configure a durable event sink"
        ),
        Err(status) => panic!("create must succeed over live mTLS: {status}"),
    };
    assert!(!created.duplicate);
    let created_proxy = created.proxy.expect("create returns proxy");
    assert_eq!(created_proxy.proxy_id, proxy_id);
    assert_eq!(
        created_proxy.lifecycle_state,
        proto::McpProxyLifecycleState::Draft as i32
    );

    let replay = client
        .create_proxy(authorized(create_request))
        .await
        .expect("duplicate create must be accepted")
        .into_inner();
    assert!(replay.duplicate);
    assert_eq!(
        replay.proxy.expect("replay returns proxy").proxy_id,
        proxy_id
    );

    let denied = client
        .get_proxy(authorized(proto::GetProxyRequest {
            workspace_id: "other-workspace".to_owned(),
            namespace_id: NAMESPACE.to_owned(),
            proxy_id: proxy_id.clone(),
        }))
        .await
        .expect_err("a different workspace must not read the proxy");
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    let updated = client
        .update_proxy_draft(authorized(proto::UpdateProxyDraftRequest {
            request_id: id(),
            workspace_id: WORKSPACE.to_owned(),
            namespace_id: NAMESPACE.to_owned(),
            proxy_id: proxy_id.clone(),
            expected_revision_id: None,
            draft: Some(spec()),
        }))
        .await
        .expect("draft update must succeed")
        .into_inner();
    let draft = updated.revision.expect("update returns revision");
    let publish_request = proto::PublishProxyRevisionRequest {
        request_id: id(),
        workspace_id: WORKSPACE.to_owned(),
        namespace_id: NAMESPACE.to_owned(),
        proxy_id: proxy_id.clone(),
        expected_revision_id: None,
        draft_revision_id: draft.revision_id.clone(),
    };
    let published = client
        .publish_proxy_revision(authorized(publish_request.clone()))
        .await
        .expect("publish must succeed")
        .into_inner()
        .revision
        .expect("publish returns revision");
    assert_eq!(
        published.spec.as_ref().map(|value| value.upstreams.len()),
        Some(1)
    );
    let publish_replay = client
        .publish_proxy_revision(authorized(publish_request))
        .await
        .expect("duplicate publish must be accepted")
        .into_inner()
        .revision
        .expect("publish replay returns revision");
    assert_eq!(publish_replay.revision_id, published.revision_id);

    let deploy = client
        .deploy_proxy(authorized(proto::DeployProxyRequest {
            request_id: id(),
            workspace_id: WORKSPACE.to_owned(),
            namespace_id: NAMESPACE.to_owned(),
            proxy_id: proxy_id.clone(),
            revision_id: published.revision_id.clone(),
            expected_revision_id: None,
        }))
        .await;
    let deployed = match deploy {
        Ok(response) => response.into_inner().proxy.expect("deploy returns proxy"),
        Err(status) if is_unwired(&status) => panic!(
            "live MCP proxy runtime prerequisite is not wired: {status}; configure the real provider"
        ),
        Err(status) => panic!("deploy must succeed with a configured runtime: {status}"),
    };
    assert_eq!(deployed.active_revision_id, published.revision_id);
    assert_eq!(
        deployed.lifecycle_state,
        proto::McpProxyLifecycleState::Ready as i32
    );

    let status = client
        .get_proxy(authorized(proto::GetProxyRequest {
            workspace_id: WORKSPACE.to_owned(),
            namespace_id: NAMESPACE.to_owned(),
            proxy_id: proxy_id.clone(),
        }))
        .await
        .expect("status read must succeed")
        .into_inner()
        .proxy
        .expect("status returns proxy");
    assert_eq!(status.active_revision_id, published.revision_id);

    let paused = client
        .pause_proxy(authorized(proto::PauseProxyRequest {
            request_id: id(),
            workspace_id: WORKSPACE.to_owned(),
            namespace_id: NAMESPACE.to_owned(),
            proxy_id: proxy_id.clone(),
            revision_id: published.revision_id.clone(),
            expected_revision_id: None,
            reason_code: Some("live.pause".to_owned()),
        }))
        .await
        .expect("pause must succeed")
        .into_inner()
        .proxy
        .expect("pause returns proxy");
    assert_eq!(
        paused.lifecycle_state,
        proto::McpProxyLifecycleState::Paused as i32
    );

    let resumed = client
        .resume_proxy(authorized(proto::ResumeProxyRequest {
            request_id: id(),
            workspace_id: WORKSPACE.to_owned(),
            namespace_id: NAMESPACE.to_owned(),
            proxy_id: proxy_id.clone(),
            revision_id: published.revision_id.clone(),
            expected_revision_id: None,
        }))
        .await
        .expect("resume must succeed")
        .into_inner()
        .proxy
        .expect("resume returns proxy");
    assert_eq!(
        resumed.lifecycle_state,
        proto::McpProxyLifecycleState::Ready as i32
    );

    let rolled_back = client
        .rollback_proxy(authorized(proto::RollbackProxyRequest {
            request_id: id(),
            workspace_id: WORKSPACE.to_owned(),
            namespace_id: NAMESPACE.to_owned(),
            proxy_id: proxy_id.clone(),
            revision_id: published.revision_id.clone(),
            target_revision_id: published.revision_id.clone(),
            expected_revision_id: None,
            reason_code: Some("live.rollback".to_owned()),
        }))
        .await
        .expect("rollback must succeed")
        .into_inner()
        .proxy
        .expect("rollback returns proxy");
    assert_eq!(
        rolled_back.lifecycle_state,
        proto::McpProxyLifecycleState::Ready as i32
    );

    let retired = client
        .retire_proxy(authorized(proto::RetireProxyRequest {
            request_id: id(),
            workspace_id: WORKSPACE.to_owned(),
            namespace_id: NAMESPACE.to_owned(),
            proxy_id: proxy_id.clone(),
            revision_id: published.revision_id.clone(),
            expected_revision_id: None,
            reason_code: Some("live.retire".to_owned()),
        }))
        .await
        .expect("retire must succeed")
        .into_inner()
        .proxy
        .expect("retire returns proxy");
    assert_eq!(
        retired.lifecycle_state,
        proto::McpProxyLifecycleState::Retired as i32
    );

    let activity = client
        .list_proxy_activity(authorized(proto::ListProxyActivityRequest {
            workspace_id: WORKSPACE.to_owned(),
            namespace_id: NAMESPACE.to_owned(),
            proxy_id: proxy_id.clone(),
            page_size: 100,
            page_token: String::new(),
        }))
        .await
        .expect("activity must be readable")
        .into_inner();
    assert!(!activity.activity.is_empty());
    assert!(
        activity
            .activity
            .iter()
            .all(|entry| !entry.activity_id.is_empty())
    );
    let unique_ids = activity
        .activity
        .iter()
        .map(|entry| entry.activity_id.as_str())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(unique_ids.len(), activity.activity.len());
}
