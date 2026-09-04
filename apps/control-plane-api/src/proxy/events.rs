use std::sync::Arc;

use apex_durability::{IngestRequest, canonical_event_hash};
use prost_types::value::Kind;
use prost_types::{Struct, Value};

use super::{ProxyError, ProxyEventSink, ProxyLifecycleEvent};
use crate::outbox::{ControlOutboxBackend, submit_command};

const PRODUCER_AGENT_ID: &str = "apex-control-gateway";
const PRODUCER_ACTOR_ID: &str = "apex-control-plane";
const PRODUCER_PROMPT_REVISION: &str = "proxy-lifecycle-v1";
const PRODUCER_MODEL: &str = "n-a";

pub struct DurableProxyEventSink {
    backend: Arc<ControlOutboxBackend>,
}

impl DurableProxyEventSink {
    pub fn new(backend: Arc<ControlOutboxBackend>) -> Self {
        Self { backend }
    }

    fn encode(event: &ProxyLifecycleEvent) -> Result<IngestRequest, ProxyError> {
        validate_event(event)?;
        let timestamp =
            crate::envelope::time::rfc3339_from_uuidv7(&event.request_id).ok_or_else(|| {
                ProxyError::invalid_proxy_spec("Proxy lifecycle IDs must be UUIDv7 values.")
            })?;
        let envelope = apex_durability::proto::EventEnvelope {
            event_id: event.request_id.clone(),
            timestamp,
            r#type: 7, // EventType::WORKFLOW
            agent_id: PRODUCER_AGENT_ID.to_owned(),
            run_id: event.request_id.clone(),
            parent_run_id: None,
            trace_id: event.request_id.clone(),
            scope: Some(apex_durability::proto::Scope {
                workspace_id: event.scope.workspace_id.clone(),
                namespace_id: event.scope.namespace_id.clone(),
                agent_group_ids: vec![],
            }),
            actor: Some(apex_durability::proto::Actor {
                r#type: 3, // ActorType::SYSTEM
                id: PRODUCER_ACTOR_ID.to_owned(),
            }),
            version: Some(apex_durability::proto::Version {
                agent_code: PRODUCER_AGENT_ID.to_owned(),
                prompt: PRODUCER_PROMPT_REVISION.to_owned(),
                model: PRODUCER_MODEL.to_owned(),
            }),
            data: Some(lifecycle_data(event)),
            integrity: Some(apex_durability::proto::Integrity {
                prev_hash: None,
                event_hash: String::new(),
            }),
            schema_version: 1,
        };
        let event_hash = canonical_event_hash(&envelope).map_err(|_| {
            ProxyError::invalid_proxy_spec("Proxy lifecycle event was rejected safely.")
        })?;
        let mut envelope = envelope;
        envelope.integrity = Some(apex_durability::proto::Integrity {
            prev_hash: None,
            event_hash,
        });
        IngestRequest::from_validated_transport(envelope).map_err(|_| {
            ProxyError::invalid_proxy_spec("Proxy lifecycle event was rejected safely.")
        })
    }
}

impl ProxyEventSink for DurableProxyEventSink {
    fn emit(&self, event: ProxyLifecycleEvent) -> Result<(), ProxyError> {
        let request = Self::encode(&event)?;
        submit_command(&self.backend, &request)
            .map(|_| ())
            .map_err(|_| ProxyError::event_sink_unavailable())
    }
}

fn validate_event(event: &ProxyLifecycleEvent) -> Result<(), ProxyError> {
    if !super::validation::is_lowercase_uuidv7(&event.request_id)
        || !super::validation::is_scope_identifier(&event.scope.workspace_id)
        || !super::validation::is_scope_identifier(&event.scope.namespace_id)
        || !super::validation::is_scope_identifier(&event.operation)
        || !super::validation::is_scope_identifier(&event.actor_id)
        || !super::validation::is_scope_identifier(&event.reason_code)
    {
        return Err(ProxyError::invalid_proxy_spec(
            "Proxy lifecycle events require bounded metadata identifiers.",
        ));
    }
    Ok(())
}

fn lifecycle_data(event: &ProxyLifecycleEvent) -> Struct {
    let mut fields = std::collections::BTreeMap::new();
    fields.insert("actor_id".to_owned(), string_value(&event.actor_id));
    fields.insert("operation".to_owned(), string_value(&event.operation));
    fields.insert(
        "proxy_id".to_owned(),
        string_value(&event.proxy_id.to_string()),
    );
    fields.insert("reason_code".to_owned(), string_value(&event.reason_code));
    if let Some(revision_id) = &event.revision_id {
        fields.insert(
            "revision_id".to_owned(),
            string_value(&revision_id.to_string()),
        );
    }
    Struct {
        fields: fields.into_iter().collect(),
    }
}

fn string_value(value: &str) -> Value {
    Value {
        kind: Some(Kind::StringValue(value.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn lifecycle_event_is_encoded_as_redacted_workflow_metadata() {
        let backend = Arc::new(ControlOutboxBackend::new(Box::new(
            apex_durability::InMemoryOutbox::new(8).unwrap(),
        )));
        let sink = DurableProxyEventSink::new(Arc::clone(&backend));

        sink.emit(event()).unwrap();

        let pending = backend.pending_batch(8).unwrap();
        assert_eq!(pending.len(), 1);
        let envelope =
            apex_durability::proto::EventEnvelope::decode(pending[0].envelope.as_slice()).unwrap();
        assert_eq!(envelope.event_id, event().request_id);
        assert_eq!(envelope.r#type, 7); // EventType::WORKFLOW
        assert_eq!(envelope.agent_id, "apex-control-gateway");
        assert_eq!(envelope.run_id, event().request_id);
        assert_eq!(envelope.trace_id, event().request_id);
        assert_eq!(envelope.scope.unwrap().workspace_id, "workspace");
        assert_eq!(envelope.actor.unwrap().r#type, 3); // ActorType::SYSTEM

        let data = envelope.data.unwrap();
        let mut keys = data.fields.keys().cloned().collect::<Vec<_>>();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "actor_id".to_owned(),
                "operation".to_owned(),
                "proxy_id".to_owned(),
                "reason_code".to_owned(),
                "revision_id".to_owned(),
            ]
        );
        assert!(
            !pending[0]
                .envelope
                .windows(b"secret".len())
                .any(|window| window == b"secret")
        );
    }

    #[test]
    fn retrying_the_same_lifecycle_event_is_idempotent() {
        let backend = Arc::new(ControlOutboxBackend::new(Box::new(
            apex_durability::InMemoryOutbox::new(8).unwrap(),
        )));
        let sink = DurableProxyEventSink::new(Arc::clone(&backend));
        let lifecycle = event();

        sink.emit(lifecycle.clone()).unwrap();
        sink.emit(lifecycle).unwrap();

        assert_eq!(backend.pending_count().unwrap(), 1);
    }

    #[test]
    fn malformed_lifecycle_metadata_is_rejected_before_enqueue() {
        let backend = Arc::new(ControlOutboxBackend::new(Box::new(
            apex_durability::InMemoryOutbox::new(8).unwrap(),
        )));
        let sink = DurableProxyEventSink::new(Arc::clone(&backend));
        let mut lifecycle = event();
        lifecycle.reason_code = "bad\nreason".to_owned();

        let error = sink.emit(lifecycle).unwrap_err();

        assert_eq!(error.code(), "INVALID_PROXY_SPEC");
        assert_eq!(backend.pending_count().unwrap(), 0);
    }

    fn event() -> ProxyLifecycleEvent {
        ProxyLifecycleEvent {
            request_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e86".to_owned(),
            operation: "publish".to_owned(),
            scope: crate::ExactScope {
                workspace_id: "workspace".to_owned(),
                namespace_id: "namespace".to_owned(),
            },
            proxy_id: crate::ProxyId::new("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84").unwrap(),
            revision_id: Some(
                crate::ProxyRevisionId::new("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e85").unwrap(),
            ),
            actor_id: "operator".to_owned(),
            reason_code: "operator_requested".to_owned(),
        }
    }
}
