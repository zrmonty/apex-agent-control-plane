//! Component-only trusted metadata fixture. No TLS, proof generation or attestation.
use super::*;
use crate::{
    CreateProxy, ExactScope, ProxyId, ProxySpec, ProxyStore, PublishRevision, UpdateProxyDraft,
};
use std::time::Duration;

pub(super) struct Fixture {
    pub store: PostgresProxyStore,
    pub lease: LeasedProxyOperation,
    pub registration: DeploymentRegistration,
    pub url: String,
    base_url: String,
    schema: String,
}

impl Fixture {
    pub fn new() -> Self {
        let base_url =
            std::env::var("APEX_PROXY_JOURNAL_TEST_DATABASE_URL").expect("required disposable PG");
        let config: postgres::Config = base_url.parse().unwrap();
        assert!(!config.get_hosts().is_empty());
        assert!(config.get_hosts().iter().all(|h| {
            match h {
                postgres::config::Host::Tcp(h) => h
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback()),
                #[cfg(unix)]
                postgres::config::Host::Unix(_) => false,
            }
        }));
        let schema = format!("serving_test_{}", Uuid::now_v7().simple());
        postgres::Client::connect(&base_url, postgres::NoTls)
            .unwrap()
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .unwrap();
        let url = format!("{base_url}&options=-csearch_path%3D{schema}");
        let store = PostgresProxyStore::connect(&url).unwrap();
        let control: proto::McpProxyRevision = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/fixtures/mcp-proxy/control-revision.json"
        )))
        .unwrap();
        let scope = ExactScope {
            workspace_id: "workspace".into(),
            namespace_id: "namespace".into(),
        };
        let proxy = ProxyId::new(Uuid::now_v7().to_string()).unwrap();
        store
            .create(CreateProxy {
                request_id: Uuid::now_v7().to_string(),
                scope: scope.clone(),
                proxy_id: proxy.clone(),
                display_name: "Registry fixture".into(),
                slug: proxy.to_string(),
                description: None,
                owner: None,
            })
            .unwrap();
        let draft = store
            .update_draft(UpdateProxyDraft {
                request_id: Uuid::now_v7().to_string(),
                scope: scope.clone(),
                proxy_id: proxy.clone(),
                expected_revision_id: None,
                actor_id: "operator".into(),
                spec: ProxySpec::try_from(control.spec.unwrap()).unwrap(),
            })
            .unwrap();
        let revision = store
            .publish_revision(PublishRevision {
                request_id: Uuid::now_v7().to_string(),
                scope: scope.clone(),
                proxy_id: proxy.clone(),
                draft_revision_id: draft.draft_revision_id.unwrap(),
                expected_revision_id: None,
                actor_id: "operator".into(),
            })
            .unwrap();
        let request_id = Uuid::now_v7().to_string();
        let event = crate::proxy::events::managed_event(
            &crate::ProxyLifecycleEvent {
                request_id: request_id.clone(),
                operation: "deploy".into(),
                scope: scope.clone(),
                proxy_id: proxy.clone(),
                revision_id: Some(revision.revision_id.clone()),
                actor_id: "operator".into(),
                reason_code: "proxy.deploy".into(),
            },
            &Uuid::now_v7().to_string(),
            1_788_500_000_000_000,
        )
        .unwrap();
        store
            .submit_proxy_operation(&crate::SubmitProxyOperation {
                scope: scope.clone(),
                proxy_id: proxy.clone(),
                request_id,
                expected_revision_id: Some(revision.revision_id.clone()),
                revision_id: revision.revision_id.clone(),
                expected_generation: 0,
                desired_state: proto::ProxyDesiredState::Serving,
                evidence: event,
            })
            .unwrap();
        let lease = store
            .lease_proxy_operation(&scope, &proxy, "controller-a", Duration::from_secs(300))
            .unwrap()
            .unwrap();
        let mut configuration: proto::RuntimeConfiguration =
            serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../contracts/fixtures/mcp-proxy/runtime-revision.json"
            )))
            .unwrap();
        configuration.workspace_id = scope.workspace_id;
        configuration.namespace_id = scope.namespace_id;
        configuration.proxy_id = proxy.to_string();
        configuration.revision_id = revision.revision_id.to_string();
        configuration.generation = lease.operation.generation;
        configuration.config_hash = revision.config_hash;
        configuration.runtime_manifest_hash =
            crate::proxy::runtime_manifest_hash(&configuration).unwrap();
        let target = proto::RuntimeTarget {
            workspace_id: configuration.workspace_id.clone(),
            namespace_id: configuration.namespace_id.clone(),
            proxy_id: configuration.proxy_id.clone(),
            revision_id: configuration.revision_id.clone(),
            generation: configuration.generation,
            fencing_token: lease.fencing_token,
        };
        let registration = DeploymentRegistration {
            binding: proto::ManagedDeploymentBinding {
                installation_id: Uuid::now_v7().to_string(),
                target: Some(target),
                process_instance_id: Uuid::now_v7().to_string(),
                config_hash: configuration.config_hash.clone(),
                launch_context_hash: "b".repeat(64),
            },
            configuration,
            authority_profile_ref: "authority-profile".into(),
            authority_profile_version: "v1".into(),
            proof_sha256: [7; 32],
        };
        Self {
            store,
            lease,
            registration,
            url,
            base_url,
            schema,
        }
    }

    pub fn client(&self) -> postgres::Client {
        postgres::Client::connect(&self.url, postgres::NoTls).unwrap()
    }
    pub fn advance(&mut self, desired: proto::ProxyDesiredState, replace_revision: bool) {
        let target = self.registration.binding.target.as_ref().unwrap();
        let scope = ExactScope {
            workspace_id: target.workspace_id.clone(),
            namespace_id: target.namespace_id.clone(),
        };
        let proxy = ProxyId::new(&target.proxy_id).unwrap();
        let prior = crate::ProxyRevisionId::new(&self.lease.operation.revision_id).unwrap();
        let revision_id = if replace_revision {
            let proxy_state = self.store.get(scope.clone(), proxy.clone()).unwrap();
            let draft = self
                .store
                .update_draft(UpdateProxyDraft {
                    request_id: Uuid::now_v7().to_string(),
                    scope: scope.clone(),
                    proxy_id: proxy.clone(),
                    expected_revision_id: proxy_state.draft_revision_id,
                    actor_id: "operator".into(),
                    spec: ProxySpec::try_from(
                        self.registration.configuration.spec.clone().unwrap(),
                    )
                    .unwrap(),
                })
                .unwrap();
            self.store
                .publish_revision(PublishRevision {
                    request_id: Uuid::now_v7().to_string(),
                    scope: scope.clone(),
                    proxy_id: proxy.clone(),
                    draft_revision_id: draft.draft_revision_id.unwrap(),
                    expected_revision_id: Some(prior.clone()),
                    actor_id: "operator".into(),
                })
                .unwrap()
                .revision_id
        } else {
            prior.clone()
        };
        let request = Uuid::now_v7().to_string();
        let event = crate::proxy::events::managed_event(
            &crate::ProxyLifecycleEvent {
                request_id: request.clone(),
                operation: "deploy".into(),
                scope: scope.clone(),
                proxy_id: proxy.clone(),
                revision_id: Some(revision_id.clone()),
                actor_id: "operator".into(),
                reason_code: "proxy.deploy".into(),
            },
            &Uuid::now_v7().to_string(),
            1_788_500_000_000_000,
        )
        .unwrap();
        self.store
            .submit_proxy_operation(&crate::SubmitProxyOperation {
                scope: scope.clone(),
                proxy_id: proxy.clone(),
                request_id: request,
                expected_revision_id: Some(prior),
                revision_id: revision_id.clone(),
                expected_generation: self.lease.operation.generation,
                desired_state: desired,
                evidence: event,
            })
            .unwrap();
        self.lease = self
            .store
            .lease_proxy_operation(&scope, &proxy, "controller-a", Duration::from_secs(300))
            .unwrap()
            .unwrap();
        let target = self.registration.binding.target.as_mut().unwrap();
        target.revision_id = revision_id.to_string();
        target.generation = self.lease.operation.generation;
        target.fencing_token = self.lease.fencing_token;
        self.registration.binding.process_instance_id = Uuid::now_v7().to_string();
        self.registration.configuration.revision_id = target.revision_id.clone();
        self.registration.configuration.generation = target.generation;
        self.registration.configuration.runtime_manifest_hash =
            crate::proxy::runtime_manifest_hash(&self.registration.configuration).unwrap();
    }
    pub fn rows(&self, table: &str) -> Vec<String> {
        assert!(
            [
                "mcp_proxy_deployments",
                "mcp_proxy_serving_selection",
                "mcp_proxy_grant_decisions"
            ]
            .contains(&table)
        );
        self.client()
            .query(
                &format!("SELECT row_to_json(t)::text FROM {table} t ORDER BY 1"),
                &[],
            )
            .unwrap()
            .into_iter()
            .map(|r| r.get(0))
            .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        assert!(
            self.schema.starts_with("serving_test_")
                && self
                    .schema
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        );
        if let Ok(mut client) = postgres::Client::connect(&self.base_url, postgres::NoTls) {
            let _ = client.batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema));
        }
    }
}
