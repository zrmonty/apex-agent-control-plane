use sha2::{Digest, Sha256};

use super::error::FindingError;
use super::types::{FindingStatus, FindingType, SecurityFinding};
use crate::{is_lowercase_uuidv7, is_scope_identifier};

pub(crate) const MAX_FINDINGS: usize = 1_000_000;
pub(crate) const MAX_EVIDENCE_REFS: usize = 32;

pub(crate) fn validate_finding(f: &SecurityFinding) -> Result<(), FindingError> {
    validate_scope(&f.workspace_id, &f.namespace_id)?;
    if !is_lowercase_uuidv7(&f.finding_id)
        || !valid_detector(&f.detector)
        || f.evidence_refs.len() > MAX_EVIDENCE_REFS
        || !valid_hash(&f.fingerprint)
        || f.fingerprint
            != fingerprint_for(
                f.finding_type,
                &f.workspace_id,
                &f.namespace_id,
                &f.detector,
                &f.evidence_key(),
            )
    {
        return Err(FindingError::invalid_field());
    }
    f.evidence_refs.iter().try_for_each(|e| {
        if is_lowercase_uuidv7(&e.event_id)
            && valid_field_path(&e.field_path)
            && valid_hash(&e.value_hash)
        {
            Ok(())
        } else {
            Err(FindingError::invalid_field())
        }
    })
}

pub(crate) fn fingerprint_for(
    finding_type: FindingType,
    workspace_id: &str,
    namespace_id: &str,
    detector: &str,
    evidence_key: &str,
) -> String {
    format!(
        "{:x}",
        Sha256::digest(
            format!("{finding_type:?}:{workspace_id}:{namespace_id}:{detector}:{evidence_key}")
                .as_bytes()
        )
    )
}

pub(crate) fn valid_detector(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

pub(crate) fn logically_equal(left: &SecurityFinding, right: &SecurityFinding) -> bool {
    left.finding_type == right.finding_type
        && left.severity == right.severity
        && left.confidence == right.confidence
        && left.workspace_id == right.workspace_id
        && left.namespace_id == right.namespace_id
        && left.detector == right.detector
        && left.evidence_refs == right.evidence_refs
        && left.policy_decision == right.policy_decision
        && left.fingerprint == right.fingerprint
}

pub(crate) fn validate_scope(workspace: &str, namespace: &str) -> Result<(), FindingError> {
    if is_scope_identifier(workspace) && is_scope_identifier(namespace) {
        Ok(())
    } else {
        Err(FindingError::invalid_field())
    }
}

pub(crate) fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub(crate) fn valid_field_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.contains("..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
}

pub(crate) fn allowed_transition(from: FindingStatus, to: FindingStatus) -> bool {
    matches!(
        (from, to),
        (
            FindingStatus::Open,
            FindingStatus::Acknowledged
                | FindingStatus::Contained
                | FindingStatus::Resolved
                | FindingStatus::FalsePositive
        ) | (
            FindingStatus::Acknowledged,
            FindingStatus::Contained | FindingStatus::Resolved | FindingStatus::FalsePositive
        ) | (FindingStatus::Contained, FindingStatus::Resolved)
    )
}
