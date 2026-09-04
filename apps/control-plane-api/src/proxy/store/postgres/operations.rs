use std::time::Duration;

use super::super::operations::{LeasedProxyOperation, SubmitProxyOperation};
use super::{PostgresProxyStore, configuration_error, operation_journal as journal};
use crate::proxy::{ProxyError, ProxyId};
use crate::{ExactScope, proto};
use apex_durability::PostgresClientOps;
use apex_durability::{IngestRequest, proto::EventEnvelope};
use prost::Message;

pub(crate) struct ProxyEvidenceTarget {
    pub(crate) scope: ExactScope,
    pub(crate) proxy_id: ProxyId,
}

impl PostgresProxyStore {
    /// Internal controller inventory, never exposed as an unscoped browser API.
    /// Eight keys per page and sixteen intents per key bound worker allocation.
    pub(crate) fn pending_proxy_evidence_targets(
        &self,
        after: Option<&ProxyEvidenceTarget>,
    ) -> Result<Vec<ProxyEvidenceTarget>, ProxyError> {
        let mut client = self.client.try_lock().map_err(|_| configuration_error())?;
        let rows = if let Some(after) = after {
            client.query(
                "SELECT DISTINCT workspace_id, namespace_id, proxy_id
                 FROM mcp_proxy_evidence_intents WHERE enqueued_at_micros IS NULL
                 AND (workspace_id, namespace_id, proxy_id) > ($1,$2,$3)
                 ORDER BY workspace_id, namespace_id, proxy_id LIMIT 8",
                &[
                    &after.scope.workspace_id,
                    &after.scope.namespace_id,
                    after.proxy_id.as_uuid(),
                ],
            )
        } else {
            client.query(
                "SELECT DISTINCT workspace_id, namespace_id, proxy_id
                 FROM mcp_proxy_evidence_intents WHERE enqueued_at_micros IS NULL
                 ORDER BY workspace_id, namespace_id, proxy_id LIMIT 8",
                &[],
            )
        }
        .map_err(|_| configuration_error())?;
        rows.into_iter()
            .map(|row| {
                let scope = ExactScope {
                    workspace_id: row.get(0),
                    namespace_id: row.get(1),
                };
                super::super::shared::validate_scope(&scope)?;
                Ok(ProxyEvidenceTarget {
                    scope,
                    proxy_id: ProxyId::new(row.get::<_, uuid::Uuid>(2).to_string())?,
                })
            })
            .collect()
    }

    pub fn submit_proxy_operation(
        &self,
        input: &SubmitProxyOperation,
    ) -> Result<proto::ProxyOperation, ProxyError> {
        let mut client = self.client.lock().map_err(|_| configuration_error())?;
        journal::submit_operation(
            &mut *client,
            &journal::SubmitOperation {
                target: journal::Target {
                    scope: &input.scope,
                    proxy_id: &input.proxy_id,
                },
                request_id: &input.request_id,
                expected_revision_id: input.expected_revision_id.as_ref(),
                revision_id: &input.revision_id,
                expected_generation: input.expected_generation,
                desired_state: input.desired_state,
                evidence: &input.evidence,
            },
        )
    }

    pub fn get_proxy_operation(
        &self,
        scope: &ExactScope,
        proxy_id: &ProxyId,
        operation_id: &str,
    ) -> Result<Option<proto::ProxyOperation>, ProxyError> {
        let mut client = self.client.lock().map_err(|_| configuration_error())?;
        journal::get_operation(
            &mut *client,
            journal::Target { scope, proxy_id },
            operation_id,
        )
    }

    pub fn lease_proxy_operation(
        &self,
        scope: &ExactScope,
        proxy_id: &ProxyId,
        worker_id: &str,
        ttl: Duration,
    ) -> Result<Option<LeasedProxyOperation>, ProxyError> {
        let mut client = self.client.lock().map_err(|_| configuration_error())?;
        journal::lease_operation(
            &mut *client,
            journal::Target { scope, proxy_id },
            worker_id,
            ttl,
        )
        .map(|lease| {
            lease.map(|lease| LeasedProxyOperation {
                operation: lease.operation,
                worker_id: lease.worker_id,
                fencing_token: lease.fencing_token,
                lease_expires_at_micros: lease.lease_expires_at_micros,
            })
        })
    }

    pub fn observe_proxy_operation(
        &self,
        scope: &ExactScope,
        proxy_id: &ProxyId,
        lease: &LeasedProxyOperation,
        state: proto::ProxyObservedState,
        error_code: Option<&str>,
        event: &EventEnvelope,
    ) -> Result<proto::ProxyOperation, ProxyError> {
        let mut client = self.client.lock().map_err(|_| configuration_error())?;
        journal::observe_operation(
            &mut *client,
            journal::Target { scope, proxy_id },
            &journal::LeasedOperation {
                operation: lease.operation.clone(),
                worker_id: lease.worker_id.clone(),
                fencing_token: lease.fencing_token,
                lease_expires_at_micros: lease.lease_expires_at_micros,
            },
            state,
            error_code,
            event,
        )
    }

    /// Replay frozen intents through the existing durable outbox. No downstream
    /// network publication occurs here. Retry after an uncertain enqueue uses the
    /// exact original event bytes/ID/hash; the outbox resolves the duplicate.
    /// Call from a bounded blocking worker, not a Tokio runtime worker thread.
    pub fn relay_proxy_evidence(
        &self,
        scope: &ExactScope,
        proxy_id: &ProxyId,
        outbox: &crate::ControlOutboxBackend,
        limit: u32,
    ) -> Result<usize, ProxyError> {
        self.relay_proxy_evidence_cancellable(scope, proxy_id, outbox, limit, || false)
    }

    pub(crate) fn relay_proxy_evidence_cancellable(
        &self,
        scope: &ExactScope,
        proxy_id: &ProxyId,
        outbox: &crate::ControlOutboxBackend,
        limit: u32,
        cancelled: impl Fn() -> bool,
    ) -> Result<usize, ProxyError> {
        let target = journal::Target { scope, proxy_id };
        let intents = {
            let mut client = self.client.try_lock().map_err(|_| configuration_error())?;
            journal::pending_evidence_intents(&mut *client, target, limit)?
        };
        let mut relayed = 0;
        for pending in intents {
            if cancelled() {
                break;
            }
            let envelope = EventEnvelope::decode(pending.intent.envelope.as_slice())
                .map_err(|_| configuration_error())?;
            let request = IngestRequest::from_validated_transport(envelope)
                .map_err(|_| configuration_error())?;
            crate::outbox::try_submit_command(outbox, &request)
                .map_err(|_| ProxyError::event_sink_unavailable())?;
            let mut client = self.client.try_lock().map_err(|_| configuration_error())?;
            if journal::mark_evidence_enqueued(
                &mut *client,
                target,
                &pending.operation_id.to_string(),
                &pending.intent.event_id.to_string(),
                &pending.intent.payload_hash,
            )? {
                relayed += 1;
            }
        }
        Ok(relayed)
    }
}
