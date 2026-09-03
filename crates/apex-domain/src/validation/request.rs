use std::collections::HashSet;

use prost::Message;

#[cfg(feature = "test-support")]
use super::canonical::canonical_event_hash;
use super::canonical::canonical_event_hash_with_data_json;
use super::control::validate_control_data;
use super::convert::prost_struct_to_json;
use super::identifiers::{
    is_lowercase_sha256, is_lowercase_uuidv7, is_rfc3339_utc, is_scope_identifier,
};
use super::secrets::{contains_secret_like_control_value, contains_secret_like_value};
use crate::{GatewayError, GatewayErrorCode, MAX_ENVELOPE_BYTES, proto};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestRequest {
    pub event_id: String,
    pub workspace_id: String,
    pub namespace_id: String,
    pub scope_key: String,
    pub envelope: Vec<u8>,
}

impl IngestRequest {
    #[cfg(feature = "test-support")]
    pub fn new(
        event_id: impl Into<String>,
        workspace_id: impl Into<String>,
        namespace_id: impl Into<String>,
        envelope: Vec<u8>,
    ) -> Self {
        let event_id = event_id.into();
        let workspace_id = workspace_id.into();
        let namespace_id = namespace_id.into();
        Self {
            event_id,
            workspace_id: workspace_id.clone(),
            namespace_id: namespace_id.clone(),
            scope_key: format!("{workspace_id}/{namespace_id}"),
            envelope,
        }
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    pub fn namespace_id(&self) -> &str {
        &self.namespace_id
    }

    #[cfg(feature = "test-support")]
    pub fn canonical_hash_for_test(
        envelope: &proto::EventEnvelope,
    ) -> Result<String, GatewayError> {
        canonical_event_hash(envelope)
    }

    pub fn scope_key(&self) -> &str {
        &self.scope_key
    }

    /// Validates a decoded transport envelope against every v1 admission rule
    /// (identifiers, timestamp, integrity hash, structure, secret policy, and
    /// the `control` action schema) and returns the canonical outbox-ready
    /// request. This is the single validation gate independent writers (the
    /// OOB control gateway) must go through -- it must never be bypassed.
    pub fn from_validated_transport(
        envelope: proto::EventEnvelope,
    ) -> Result<Self, GatewayError> {
        Self::from_validated_transport_ref(&envelope)
    }

    /// Borrowing twin of [`Self::from_validated_transport`], identical rule
    /// for rule. Exists so callers that must keep the original envelope
    /// alive after a validation failure (to report a redacted security
    /// finding, e.g. `gateway::adapter::AuthenticatedIngestAdapter::
    /// ingest_envelope`) don't need to clone the whole envelope up front
    /// just to retain access to it on the error path. The public, owned
    /// entry point above simply borrows through to this one so there is a
    /// single implementation of the admission rules.
    pub fn from_validated_transport_ref(
        envelope: &proto::EventEnvelope,
    ) -> Result<Self, GatewayError> {
        if envelope.encoded_len() > MAX_ENVELOPE_BYTES {
            return Err(GatewayError::new(GatewayErrorCode::PayloadTooLarge));
        }
        if !is_lowercase_uuidv7(&envelope.event_id) {
            return Err(GatewayError::new(GatewayErrorCode::InvalidEventId));
        }
        if !is_rfc3339_utc(&envelope.timestamp) {
            return Err(GatewayError::new(GatewayErrorCode::InvalidTimestamp));
        }
        let integrity = envelope
            .integrity
            .as_ref()
            .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidIntegrity))?;
        if !is_lowercase_sha256(&integrity.event_hash)
            || integrity
                .prev_hash
                .as_deref()
                .is_some_and(|hash| !is_lowercase_sha256(hash))
        {
            return Err(GatewayError::new(GatewayErrorCode::InvalidIntegrity));
        }
        let scope = envelope
            .scope
            .as_ref()
            .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidStructure))?;
        let unique_agent_groups = scope.agent_group_ids.iter().collect::<HashSet<_>>();
        if envelope.schema_version != 1
            || !matches!(envelope.r#type, 1..=12)
            || !matches!(
                envelope.actor.as_ref().map(|actor| actor.r#type),
                Some(1..=4)
            )
            || envelope.data.is_none()
            || !is_scope_identifier(&envelope.agent_id)
            || !is_scope_identifier(&envelope.run_id)
            || !is_scope_identifier(&envelope.trace_id)
            || envelope
                .parent_run_id
                .as_deref()
                .is_some_and(|id| !is_scope_identifier(id))
            || !is_scope_identifier(&scope.workspace_id)
            || !is_scope_identifier(&scope.namespace_id)
            || scope.agent_group_ids.len() > 128
            || unique_agent_groups.len() != scope.agent_group_ids.len()
            || scope
                .agent_group_ids
                .iter()
                .any(|id| !is_scope_identifier(id))
            || envelope
                .actor
                .as_ref()
                .is_none_or(|actor| !is_scope_identifier(&actor.id))
            || envelope.version.as_ref().is_none_or(|version| {
                !is_scope_identifier(&version.agent_code)
                    || !is_scope_identifier(&version.prompt)
                    || !is_scope_identifier(&version.model)
            })
        {
            return Err(GatewayError::new(GatewayErrorCode::InvalidStructure));
        }
        // `data` was already required present by the structural check above
        // (`envelope.data.is_none()`). Converting it to JSON here -- once --
        // and threading the result through to the canonical hash below
        // avoids re-running the same recursive protobuf-Struct-to-JSON
        // conversion a second time per event for what both the secret scan
        // and the canonical hash need: an identical JSON view of the same
        // `data` value. See `canonical_event_hash_with_data_json`'s doc
        // comment for why reusing it here cannot change the hash.
        let data = envelope
            .data
            .as_ref()
            .ok_or_else(|| GatewayError::new(GatewayErrorCode::InvalidStructure))?;
        let data_json = prost_struct_to_json(data)?;
        let contains_secret = if envelope.r#type == 9 {
            contains_secret_like_control_value(&data_json)
        } else {
            contains_secret_like_value(&data_json)
        };
        if contains_secret {
            return Err(GatewayError::new(GatewayErrorCode::SecretExposure));
        }
        if envelope.r#type == 9 {
            validate_control_data(data)?;
        }
        if canonical_event_hash_with_data_json(envelope, data_json)? != integrity.event_hash {
            return Err(GatewayError::new(GatewayErrorCode::InvalidIntegrity));
        }
        let serialized = envelope.encode_to_vec();
        if serialized.len() > MAX_ENVELOPE_BYTES {
            return Err(GatewayError::new(GatewayErrorCode::PayloadTooLarge));
        }
        Ok(Self {
            event_id: envelope.event_id.clone(),
            workspace_id: scope.workspace_id.clone(),
            namespace_id: scope.namespace_id.clone(),
            scope_key: format!("{}/{}", scope.workspace_id, scope.namespace_id),
            envelope: serialized,
        })
    }
}


