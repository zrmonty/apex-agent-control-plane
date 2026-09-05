use std::time::Duration;

use apex_control_plane_api::{
    CreateProxy, LeasedProxyOperation, McpProxyRevision, PostgresProxyStore, ProxyError,
    ProxyRevisionId, ProxyStore, PublishRevision, RuntimeOperationSnapshot, SubmitProxyOperation,
    UpdateProxyDraft, proto,
};
use apex_durability::proto::EventEnvelope;
use postgres::{Client, types::ToSql};
use prost::Message;
use uuid::Uuid;

use super::recovery::{Database, another_submission};
#[path = "spec.rs"]
mod spec;

pub const REFUSED: &str = "PROXY_RUNTIME_OPERATION_NOT_CURRENT";
pub const INVALID: &str = "INVALID_RUNTIME_OPERATION_CLAIMS";
pub const UNAVAILABLE: &str = "PROXY_STORE_UNAVAILABLE";

pub struct Fixture {
    // Drop the store's owned connection before dropping its disposable schema.
    pub store: PostgresProxyStore,
    pub database: Database,
    pub input: SubmitProxyOperation,
    pub revision: McpProxyRevision,
    pub operation: proto::ProxyOperation,
    pub lease: Option<LeasedProxyOperation>,
    pub target: proto::RuntimeTarget,
    pub application: String,
}

impl Fixture {
    pub fn new(leased: bool) -> Self {
        Self::desired(leased, proto::ProxyDesiredState::Serving)
    }

    pub fn desired(leased: bool, desired: proto::ProxyDesiredState) -> Self {
        let database = Database::new();
        let application = format!("runtime_snapshot_{}", Uuid::now_v7().simple());
        let store = PostgresProxyStore::connect(&format!(
            "{}&application_name={application}",
            database.url
        ))
        .unwrap();
        let mut input = another_submission();
        // Do not reuse the recovery journal's deliberately incomplete '{}' spec.
        store
            .create(CreateProxy {
                request_id: Uuid::now_v7().to_string(),
                scope: input.scope.clone(),
                proxy_id: input.proxy_id.clone(),
                display_name: "Snapshot fixture".into(),
                slug: input.proxy_id.to_string(),
                description: None,
                owner: None,
            })
            .unwrap();
        let draft = store
            .update_draft(UpdateProxyDraft {
                request_id: Uuid::now_v7().to_string(),
                scope: input.scope.clone(),
                proxy_id: input.proxy_id.clone(),
                expected_revision_id: None,
                actor_id: "operator".into(),
                spec: spec::supported_spec(),
            })
            .unwrap();
        let revision = store
            .publish_revision(PublishRevision {
                request_id: Uuid::now_v7().to_string(),
                scope: input.scope.clone(),
                proxy_id: input.proxy_id.clone(),
                draft_revision_id: draft.draft_revision_id.unwrap(),
                expected_revision_id: None,
                actor_id: "operator".into(),
            })
            .unwrap();
        input.revision_id = revision.revision_id.clone();
        input.expected_revision_id = Some(revision.revision_id.clone());
        input.desired_state = desired;
        let operation = store.submit_proxy_operation(&input).unwrap();
        let lease = leased.then(|| {
            store
                .lease_proxy_operation(
                    &input.scope,
                    &input.proxy_id,
                    "controller-a",
                    Duration::from_secs(30),
                )
                .unwrap()
                .unwrap()
        });
        let target = proto::RuntimeTarget {
            workspace_id: input.scope.workspace_id.clone(),
            namespace_id: input.scope.namespace_id.clone(),
            proxy_id: input.proxy_id.to_string(),
            revision_id: revision.revision_id.to_string(),
            generation: operation.generation,
            fencing_token: lease.as_ref().map_or(1, |lease| lease.fencing_token),
        };
        Self {
            store,
            database,
            input,
            revision,
            operation,
            lease,
            target,
            application,
        }
    }

    pub fn read(&self) -> Result<RuntimeOperationSnapshot, ProxyError> {
        self.store.read_current_runtime_operation(
            &self.target,
            &self.operation.operation_id,
            "controller-a",
        )
    }

    pub fn positive(&self) -> RuntimeOperationSnapshot {
        let before = self.bytes();
        let before_time = database_now(&mut self.client());
        let snapshot = self
            .read()
            .expect("valid published operation with current lease must be readable");
        let after_time = database_now(&mut self.client());
        assert_eq!(snapshot.operation, self.operation);
        assert_eq!(snapshot.revision, self.revision);
        assert_eq!(snapshot.worker_id, "controller-a");
        assert_eq!(snapshot.fencing_token, self.target.fencing_token);
        assert_eq!(
            snapshot.lease_expires_at_unix_us,
            self.lease.as_ref().unwrap().lease_expires_at_micros
        );
        assert!(
            snapshot.checked_at_unix_us >= before_time && snapshot.checked_at_unix_us <= after_time
        );
        assert!(snapshot.checked_at_unix_us < snapshot.lease_expires_at_unix_us);
        assert!(!format!("{snapshot:?}").contains("SNAPSHOT_CANARY"));
        assert_eq!(
            self.bytes(),
            before,
            "successful lookup must not change any durable bytes"
        );
        snapshot
    }

    pub fn client(&self) -> Client {
        let mut client = self.database.client();
        client
            .batch_execute("SET statement_timeout='5s'; SET lock_timeout='2s'")
            .unwrap();
        client
    }

    pub fn bytes(&self) -> Vec<(String, Vec<String>)> {
        let mut client = self.client();
        // Fixed table names only. row_to_json retains BYTEA as exact hex text;
        // includes identity, counters, timestamps, publication and evidence bytes.
        [
            "mcp_proxies",
            "mcp_proxy_revisions",
            "mcp_proxy_operations",
            "mcp_proxy_controller_leases",
            "mcp_proxy_evidence_intents",
            "mcp_proxy_idempotency",
            "mcp_proxy_lifecycle_transitions",
        ]
        .into_iter()
        .map(|table| {
            let rows = client
                .query(
                    &format!("SELECT row_to_json(t)::text AS bytes FROM {table} t ORDER BY bytes"),
                    &[],
                )
                .unwrap()
                .into_iter()
                .map(|row| row.get(0))
                .collect();
            (table.to_owned(), rows)
        })
        .collect()
    }

    pub fn reject(&self, target: &proto::RuntimeTarget, operation: &str, worker: &str, code: &str) {
        let before = self.bytes();
        refused(
            self.store
                .read_current_runtime_operation(target, operation, worker),
            code,
        );
        assert_eq!(
            self.bytes(),
            before,
            "refusal must preserve exact rows, fence and evidence"
        );
    }

    pub fn execute(&self, sql: &str, params: &[&(dyn ToSql + Sync)]) {
        assert_eq!(self.client().execute(sql, params).unwrap(), 1);
    }

    pub fn save_operation(&self, operation: &proto::ProxyOperation) {
        self.execute(
            "UPDATE mcp_proxy_operations SET current_result=$2 WHERE operation_id=$1",
            &[
                &self.operation.operation_id.parse::<Uuid>().unwrap(),
                &operation.encode_to_vec(),
            ],
        );
    }

    pub fn observation(&self) -> EventEnvelope {
        let mut event = self.input.evidence.clone();
        event.event_id = Uuid::now_v7().to_string();
        event.integrity.as_mut().unwrap().event_hash =
            apex_durability::canonical_event_hash(&event).unwrap();
        event
    }

    pub fn expired_at_database_edge(&self) -> u64 {
        let row = self
            .client()
            .query_one(
                "UPDATE mcp_proxy_controller_leases SET expires_at_micros=
             floor(extract(epoch FROM clock_timestamp())*1000000)::bigint
             WHERE proxy_id=$1 RETURNING expires_at_micros",
                &[self.input.proxy_id.as_uuid()],
            )
            .unwrap();
        u64::try_from(row.get::<_, i64>(0)).unwrap()
    }

    pub fn revision_id(&self) -> &ProxyRevisionId {
        &self.revision.revision_id
    }
}

pub fn database_now(client: &mut Client) -> u64 {
    u64::try_from(
        client
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint",
                &[],
            )
            .unwrap()
            .get::<_, i64>(0),
    )
    .unwrap()
}

pub fn refused(result: Result<RuntimeOperationSnapshot, ProxyError>, code: &str) {
    let error = result.expect_err("invalid or stale store claims must not produce a snapshot");
    assert_eq!(error.code(), code);
    assert!(std::error::Error::source(&error).is_none());
    let diagnostic = format!("{error} {error:?}");
    assert!(!diagnostic.contains("SNAPSHOT_CANARY") && !diagnostic.contains("secret://"));
    assert!(diagnostic.len() <= 512);
}
