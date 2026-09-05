#[cfg(feature = "postgres")]
use super::PostgresProxyStore;
use super::shared::{IdempotencyRecord, StoreState, parse_spec_json, spec_json};
use super::{
    CreateProxy, InMemoryProxyStore, ListProxies, ProxyLifecycleState, ProxyRevisionStore,
    ProxyStore, PublishRevision, RetireProxy, UpdateProxyDraft,
};
use crate::ExactScope;
use crate::proxy::{
    ApprovalMode, ArgSchema, ArgSchemaField, CliProfile, DataClassification, EgressDestination,
    ExposedTool, GovernanceBinding, Ingress, NetworkPolicy, PrivateDestinationAllowance, ProxyId,
    ProxyRevisionId, ProxySpec, ProxyToolClassification, ProxyTransport, RuntimeProfile, SecretRef,
    UpstreamBinding,
};

const WORKSPACE_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e80";
const NAMESPACE_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e81";
const OTHER_WORKSPACE_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e82";
const OTHER_NAMESPACE_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e83";
const PROXY_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84";
const REQUEST_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e85";
const UPDATE_REQUEST_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e86";
const PUBLISH_REQUEST_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e87";
const SECOND_PROXY_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e88";
const THIRD_PROXY_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e89";
const OTHER_SCOPE_PROXY_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e8a";
const RETIRE_REQUEST_ID: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e8b";

#[test]
fn in_memory_store_contract() {
    let store = exercise_store_contract(InMemoryProxyStore::default());
    assert_eq!(store.lifecycle_transition_count(), 8);
}

#[cfg(feature = "postgres")]
#[test]
fn postgres_store_contract() {
    let Some(url) = std::env::var("APEX_CONTROL_POSTGRES_URL")
        .ok()
        .filter(|value| !value.is_empty())
    else {
        eprintln!("skipping postgres store contract test: APEX_CONTROL_POSTGRES_URL is unset");
        return;
    };
    let store = PostgresProxyStore::connect(&url).expect("connect postgres proxy store");
    exercise_store_contract(store);
}

fn exercise_store_contract<S>(store: S) -> S
where
    S: ProxyStore + ProxyRevisionStore,
{
    let scope = scope();
    let other_scope = ExactScope {
        workspace_id: OTHER_WORKSPACE_ID.to_owned(),
        namespace_id: OTHER_NAMESPACE_ID.to_owned(),
    };

    let created = store
        .create(create_proxy(PROXY_ID, REQUEST_ID, "research-mcp-proxy"))
        .expect("create proxy");
    assert_eq!(created.proxy_id, proxy_id(PROXY_ID));
    assert_eq!(created.scope, scope);
    assert_eq!(created.lifecycle_state, ProxyLifecycleState::Draft);

    let read_back = store
        .get(scope.clone(), proxy_id(PROXY_ID))
        .expect("get proxy");
    assert_eq!(read_back, created);

    let replay = store
        .create(create_proxy(PROXY_ID, REQUEST_ID, "research-mcp-proxy"))
        .expect("create replay");
    assert_eq!(replay, created);

    let conflict = store
        .create(create_proxy(PROXY_ID, REQUEST_ID, "changed-slug"))
        .unwrap_err();
    assert_eq!(conflict.code(), "PROXY_IDEMPOTENCY_CONFLICT");

    let updated = store
        .update_draft(UpdateProxyDraft {
            request_id: UPDATE_REQUEST_ID.to_owned(),
            scope: scope.clone(),
            proxy_id: proxy_id(PROXY_ID),
            expected_revision_id: None,
            actor_id: "operator:proxy-admin".to_owned(),
            spec: publishable_portfolio_spec(),
        })
        .expect("store draft");
    let draft_revision_id = updated
        .draft_revision_id
        .clone()
        .expect("draft revision id");
    assert_eq!(
        store
            .update_draft(UpdateProxyDraft {
                request_id: UPDATE_REQUEST_ID.to_owned(),
                scope: scope.clone(),
                proxy_id: proxy_id(PROXY_ID),
                expected_revision_id: None,
                actor_id: "operator:proxy-admin".to_owned(),
                spec: publishable_portfolio_spec(),
            })
            .expect("draft replay"),
        updated
    );
    let update_conflict = store
        .update_draft(UpdateProxyDraft {
            request_id: UPDATE_REQUEST_ID.to_owned(),
            scope: scope.clone(),
            proxy_id: proxy_id(PROXY_ID),
            expected_revision_id: None,
            actor_id: "operator:other-admin".to_owned(),
            spec: publishable_portfolio_spec(),
        })
        .unwrap_err();
    assert_eq!(update_conflict.code(), "PROXY_IDEMPOTENCY_CONFLICT");

    let stale = store
        .update_draft(UpdateProxyDraft {
            request_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e8c".to_owned(),
            scope: scope.clone(),
            proxy_id: proxy_id(PROXY_ID),
            expected_revision_id: Some(proxy_revision_id("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e8d")),
            actor_id: "operator:proxy-admin".to_owned(),
            spec: publishable_portfolio_spec(),
        })
        .unwrap_err();
    assert_eq!(stale.code(), "PROXY_REVISION_CONFLICT");

    let published = store
        .publish_revision(PublishRevision {
            request_id: PUBLISH_REQUEST_ID.to_owned(),
            scope: scope.clone(),
            proxy_id: proxy_id(PROXY_ID),
            draft_revision_id: draft_revision_id.clone(),
            expected_revision_id: None,
            actor_id: "operator:proxy-admin".to_owned(),
        })
        .expect("publish");
    let published_revision_id = published.revision_id.clone();
    let published_spec = published.spec.clone();
    assert_eq!(
        store
            .publish_revision(PublishRevision {
                request_id: PUBLISH_REQUEST_ID.to_owned(),
                scope: scope.clone(),
                proxy_id: proxy_id(PROXY_ID),
                draft_revision_id: draft_revision_id.clone(),
                expected_revision_id: None,
                actor_id: "operator:proxy-admin".to_owned(),
            })
            .expect("publish replay"),
        published
    );
    let publish_conflict = store
        .publish_revision(PublishRevision {
            request_id: PUBLISH_REQUEST_ID.to_owned(),
            scope: scope.clone(),
            proxy_id: proxy_id(PROXY_ID),
            draft_revision_id: draft_revision_id.clone(),
            expected_revision_id: None,
            actor_id: "operator:other-admin".to_owned(),
        })
        .unwrap_err();
    assert_eq!(publish_conflict.code(), "PROXY_IDEMPOTENCY_CONFLICT");

    let mut changed_spec = valid_proxy_spec();
    changed_spec.exposed_tools[0].alias = "portfolio.read.v2".to_owned();
    let next_draft = store
        .update_draft(UpdateProxyDraft {
            request_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e8e".to_owned(),
            scope: scope.clone(),
            proxy_id: proxy_id(PROXY_ID),
            expected_revision_id: Some(draft_revision_id.clone()),
            actor_id: "operator:proxy-admin".to_owned(),
            spec: changed_spec,
        })
        .expect("next draft");
    let frozen = store
        .get_revision(
            scope.clone(),
            proxy_id(PROXY_ID),
            published_revision_id.clone(),
        )
        .expect("frozen revision");
    assert_eq!(frozen.spec, published_spec);
    assert_eq!(frozen.revision_id, published_revision_id);
    assert_ne!(
        next_draft.draft_revision_id,
        Some(published.revision_id.clone())
    );

    let hidden = store
        .get(other_scope.clone(), proxy_id(PROXY_ID))
        .unwrap_err();
    assert_eq!(hidden.code(), "PROXY_NOT_FOUND");

    store
        .create(create_proxy(
            SECOND_PROXY_ID,
            "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e8f",
            "alpha-proxy",
        ))
        .expect("second proxy");
    store
        .create(create_proxy(
            THIRD_PROXY_ID,
            "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e90",
            "beta-proxy",
        ))
        .expect("third proxy");
    store
        .create(CreateProxy {
            request_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e91".to_owned(),
            scope: other_scope.clone(),
            proxy_id: proxy_id(OTHER_SCOPE_PROXY_ID),
            display_name: "Other scope proxy".to_owned(),
            slug: "other-scope-proxy".to_owned(),
            description: None,
            owner: None,
        })
        .expect("other scope proxy");

    let first_page = store
        .list(ListProxies {
            scope: scope.clone(),
            page_size: 2,
            page_token: String::new(),
        })
        .expect("first page");
    assert_eq!(first_page.proxies.len(), 2);
    assert!(!first_page.next_page_token.is_empty());

    let second_page = store
        .list(ListProxies {
            scope: scope.clone(),
            page_size: 2,
            page_token: first_page.next_page_token.clone(),
        })
        .expect("second page");
    assert_eq!(second_page.proxies.len(), 1);
    assert!(second_page.next_page_token.is_empty());
    assert!(second_page.proxies.iter().all(|proxy| proxy.scope == scope));

    let retired = store
        .retire(RetireProxy {
            request_id: RETIRE_REQUEST_ID.to_owned(),
            scope: scope.clone(),
            proxy_id: proxy_id(PROXY_ID),
            expected_revision_id: Some(published_revision_id.clone()),
        })
        .expect("retire");
    assert_eq!(retired.lifecycle_state, ProxyLifecycleState::Retired);
    assert_eq!(
        store
            .retire(RetireProxy {
                request_id: RETIRE_REQUEST_ID.to_owned(),
                scope: scope.clone(),
                proxy_id: proxy_id(PROXY_ID),
                expected_revision_id: Some(published_revision_id.clone()),
            })
            .expect("retire replay"),
        retired
    );
    let retire_conflict = store
        .retire(RetireProxy {
            request_id: RETIRE_REQUEST_ID.to_owned(),
            scope: scope.clone(),
            proxy_id: proxy_id(PROXY_ID),
            expected_revision_id: None,
        })
        .unwrap_err();
    assert_eq!(retire_conflict.code(), "PROXY_IDEMPOTENCY_CONFLICT");

    let tombstone = store
        .create(create_proxy(
            "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e92",
            "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e93",
            "research-mcp-proxy",
        ))
        .unwrap_err();
    assert_eq!(tombstone.code(), "PROXY_IDENTITY_CONFLICT");
    store
}

#[test]
fn idempotency_replay_requires_matching_hash_and_scope() {
    let mut state = StoreState::default();
    let record = IdempotencyRecord {
        request_id: REQUEST_ID.to_owned(),
        operation: "create",
        payload_hash: "a".repeat(64),
        proxy_id: PROXY_ID.to_owned(),
        revision_id: None,
        scope: scope(),
    };
    state.record_idempotency(record);

    let changed_payload = state
        .check_idempotency("create", REQUEST_ID, &"b".repeat(64), &scope())
        .unwrap_err();
    assert_eq!(changed_payload.code(), "PROXY_IDEMPOTENCY_CONFLICT");

    let changed_scope = ExactScope {
        workspace_id: OTHER_WORKSPACE_ID.to_owned(),
        namespace_id: OTHER_NAMESPACE_ID.to_owned(),
    };
    let hidden_record = state
        .check_idempotency("create", REQUEST_ID, &"b".repeat(64), &changed_scope)
        .unwrap_err();
    assert_eq!(hidden_record.code(), "PROXY_NOT_FOUND");
}

#[test]
fn spec_round_trip_preserves_explicit_argv_schema() {
    let spec = valid_proxy_spec();
    let serialized = spec_json(&spec);
    let restored = parse_spec_json(&serialized).expect("stored proxy spec round trip");

    assert_eq!(restored, spec);
    assert_eq!(
        restored.cli_profiles[0].argv_schema.fields[0].name,
        "portfolio_id"
    );
}

#[test]
fn postgres_schema_and_sql_use_microsecond_revision_timestamps_and_transitions() {
    let schema = include_str!("../../../../../deploy/postgres/mcp_proxies.sql");
    let postgres = include_str!("postgres.rs");
    let idempotency = include_str!("postgres/idempotency.rs");

    assert!(schema.contains("created_at_micros BIGINT NOT NULL"));
    assert!(!schema.contains("created_at_millis"));
    assert!(schema.contains("operation TEXT NOT NULL"));
    assert!(schema.contains("workspace_id TEXT NOT NULL"));
    assert!(schema.contains("namespace_id TEXT NOT NULL"));
    assert!(schema.contains("status TEXT NOT NULL"));
    assert!(postgres.contains("created_at_micros"));
    assert!(!postgres.contains("created_at_millis"));
    assert!(postgres.matches("insert_lifecycle_transition(").count() >= 4);
    assert!(
        idempotency.contains("check_idempotency_record(&record, expected_hash, expected_scope)")
    );
}

fn scope() -> ExactScope {
    ExactScope {
        workspace_id: WORKSPACE_ID.to_owned(),
        namespace_id: NAMESPACE_ID.to_owned(),
    }
}

fn create_proxy(proxy_id_value: &str, request_id: &str, slug: &str) -> CreateProxy {
    CreateProxy {
        request_id: request_id.to_owned(),
        scope: scope(),
        proxy_id: proxy_id(proxy_id_value),
        display_name: "Research MCP proxy".to_owned(),
        slug: slug.to_owned(),
        description: Some("Managed proxy for research workflows".to_owned()),
        owner: Some("research-ops".to_owned()),
    }
}

fn proxy_id(value: &str) -> ProxyId {
    ProxyId::new(value).expect("proxy id")
}

fn proxy_revision_id(value: &str) -> ProxyRevisionId {
    ProxyRevisionId::new(value).expect("revision id")
}

fn valid_proxy_spec() -> ProxySpec {
    ProxySpec {
        ingress: Ingress {
            transport: ProxyTransport::StreamableHttp,
            exposure: crate::proxy::ProxyExposure::Private,
            host: "proxy.apex.test".to_owned(),
            path: "/mcp".to_owned(),
            allowed_origins: vec!["https://console.apex.test".to_owned()],
            protocol_revision: "2025-11-25".to_owned(),
            inbound_authentication_required: true,
        },
        upstreams: vec![UpstreamBinding {
            upstream_id: "portfolio-upstream".to_owned(),
            display_name: "Portfolio upstream".to_owned(),
            transport: ProxyTransport::StreamableHttp,
            endpoint_or_command_ref: "https://portfolio-api.apex.test/mcp".to_owned(),
            credential_ref: Some(
                SecretRef::new("secret://vault/upstreams/portfolio-reader").expect("secret ref"),
            ),
            secret_refs: vec![],
            server_identity: "portfolio-api.apex.test".to_owned(),
            tool_catalog_hash: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            ),
        }],
        exposed_tools: vec![ExposedTool {
            upstream_id: "portfolio-upstream".to_owned(),
            tool_name: "portfolio.read".to_owned(),
            alias: "portfolio.read".to_owned(),
            classification: ProxyToolClassification::Read,
        }],
        cli_profiles: vec![CliProfile {
            profile_id: "portfolio-cli".to_owned(),
            executable_ref: "image://portfolio-tools/read-portfolio".to_owned(),
            executable_digest:
                "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_owned(),
            fixed_argv: vec!["--format".to_owned(), "json".to_owned()],
            argv_schema: ArgSchema {
                fields: vec![ArgSchemaField {
                    name: "portfolio_id".to_owned(),
                    required: true,
                }],
            },
            working_directory: "/workspace/proxy".to_owned(),
            environment_allowlist: vec!["APEX_LOG_LEVEL".to_owned()],
            secret_refs: vec![
                SecretRef::new("secret://vault/cli/portfolio-token").expect("secret ref"),
            ],
            filesystem_policy: "read-only-rootfs".to_owned(),
            network_policy: "default-deny".to_owned(),
            shell: false,
            timeout_ms: 5_000,
            max_output_bytes: 16_384,
            allowed_exit_codes: vec![0],
        }],
        auth_bindings: vec![],
        governance_binding: GovernanceBinding {
            policy_id: "ria-read-v1".to_owned(),
            approval_mode: ApprovalMode::None,
            data_classification: DataClassification::Confidential,
            rate_limit_per_minute: 60,
            concurrency_limit: 4,
            budget_limit_per_day: 5_000,
            retention_days: 30,
        },
        runtime_profile: RuntimeProfile {
            image_digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
            cpu_limit: "500m".to_owned(),
            memory_limit: "256Mi".to_owned(),
            network_policy: "default-deny".to_owned(),
            filesystem_policy: "read-only-rootfs".to_owned(),
            rootless: true,
            network: NetworkPolicy {
                destinations: vec![EgressDestination::Https {
                    host: "portfolio-api.apex.test".to_owned(),
                    port: 443,
                    private_allowance: PrivateDestinationAllowance::Denied,
                }],
            },
        },
    }
}

fn publishable_portfolio_spec() -> ProxySpec {
    // Preserve the CLI-rich fixture for draft editing and argv-schema round trips.
    let mut spec = valid_proxy_spec();
    spec.cli_profiles.clear();
    spec
}
