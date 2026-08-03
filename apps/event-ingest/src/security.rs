use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{is_lowercase_uuidv7, is_scope_identifier};

const MAX_FINDINGS: usize = 1_000_000;
const MAX_EVIDENCE_REFS: usize = 32;
static FINDING_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static FINDING_SEED: OnceLock<u64> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingType {
    TelemetryIntegrity,
    AgentTemplateNoncompliant,
    ScopeIdentityDenied,
    UntrustedControlBoundary,
    SecretExposure,
    ToolPolicyDenied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingConfidence {
    Deterministic,
    Corroborated,
    Heuristic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingStatus {
    Open,
    Acknowledged,
    Contained,
    Resolved,
    FalsePositive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    Allow,
    Deny,
    RequireApproval,
    Contain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainmentAction {
    Pause,
    Quarantine,
    DisableTool,
}

/// Bounded, redacted signals accepted by the deterministic detector boundary.
/// No variant carries prompts, completions, credentials, or raw tool output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecuritySignal {
    TelemetryIntegrity,
    ScopeIdentityDenied,
    UntrustedControlBoundary,
    SecretExposure,
    ToolPolicyDenied,
    AgentTemplateNoncompliant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionInput {
    pub signal: SecuritySignal,
    pub workspace_id: String,
    pub namespace_id: String,
    pub event_id: String,
    pub field_path: String,
    pub value_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub event_id: String,
    pub field_path: String,
    pub value_hash: String,
}

impl EvidenceRef {
    pub fn new(event_id: &str, field_path: &str, value_hash: &str) -> Result<Self, FindingError> {
        if !is_lowercase_uuidv7(event_id)
            || !valid_field_path(field_path)
            || !valid_hash(value_hash)
        {
            return Err(FindingError::invalid_field());
        }
        Ok(Self {
            event_id: event_id.to_owned(),
            field_path: field_path.to_owned(),
            value_hash: value_hash.to_owned(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub finding_id: String,
    pub finding_type: FindingType,
    pub severity: FindingSeverity,
    pub confidence: FindingConfidence,
    pub workspace_id: String,
    pub namespace_id: String,
    pub detector: String,
    pub evidence_refs: Vec<EvidenceRef>,
    pub policy_decision: PolicyDecision,
    pub fingerprint: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingInput {
    pub finding_type: FindingType,
    pub severity: FindingSeverity,
    pub confidence: FindingConfidence,
    pub workspace_id: String,
    pub namespace_id: String,
    pub detector: String,
    pub evidence_refs: Vec<EvidenceRef>,
    pub policy_decision: PolicyDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingStatusUpdate {
    pub finding_id: String,
    pub from: FindingStatus,
    pub to: FindingStatus,
    pub action: Option<ContainmentAction>,
    pub actor_scope: String,
    pub at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingErrorCode {
    InvalidField,
    Capacity,
    DuplicateId,
    FingerprintConflict,
    NotFound,
    ScopeDenied,
    InvalidTransition,
}

impl FindingErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidField => "INVALID_SECURITY_FINDING_FIELD",
            Self::Capacity => "SECURITY_FINDING_CAPACITY",
            Self::DuplicateId => "SECURITY_FINDING_ID_CONFLICT",
            Self::FingerprintConflict => "SECURITY_FINDING_FINGERPRINT_CONFLICT",
            Self::NotFound => "SECURITY_FINDING_NOT_FOUND",
            Self::ScopeDenied => "SECURITY_FINDING_SCOPE_DENIED",
            Self::InvalidTransition => "SECURITY_FINDING_INVALID_TRANSITION",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingError {
    pub code: FindingErrorCode,
    pub summary: &'static str,
    pub cause: &'static str,
    pub retryable: bool,
    pub next_steps: &'static [&'static str],
}

impl FindingError {
    fn invalid_field() -> Self {
        Self {
            code: FindingErrorCode::InvalidField,
            summary: "The security finding contains an invalid field.",
            cause: "A scope, UUID, hash, detector, evidence path, or bounded collection failed the finding contract.",
            retryable: false,
            next_steps: &[
                "Validate identifiers and SHA-256 evidence hashes before creating the finding.",
            ],
        }
    }
    fn capacity() -> Self {
        Self {
            code: FindingErrorCode::Capacity,
            summary: "The security finding store is at capacity.",
            cause: "The append-only finding boundary refuses new records rather than evicting security evidence.",
            retryable: true,
            next_steps: &[
                "Increase durable finding capacity or archive findings through the approved retention workflow.",
            ],
        }
    }
    fn duplicate_id() -> Self {
        Self {
            code: FindingErrorCode::DuplicateId,
            summary: "The finding ID is already bound to different evidence.",
            cause: "Immutable finding IDs cannot be reused for a changed record.",
            retryable: false,
            next_steps: &[
                "Use the original record for replay or generate a new UUIDv7 finding ID.",
            ],
        }
    }
    fn fingerprint_conflict() -> Self {
        Self {
            code: FindingErrorCode::FingerprintConflict,
            summary: "The finding fingerprint is already bound to different evidence or policy.",
            cause: "A deterministic security signal cannot be silently downgraded or replaced by a changed record.",
            retryable: false,
            next_steps: &[
                "Replay the original finding or create a new detector fingerprint for a materially different signal.",
            ],
        }
    }
    fn not_found() -> Self {
        Self {
            code: FindingErrorCode::NotFound,
            summary: "The requested security finding was not found.",
            cause: "The supplied finding ID is not present in this scoped store.",
            retryable: false,
            next_steps: &["Verify the finding ID and authenticated scope before retrying."],
        }
    }
    fn scope_denied() -> Self {
        Self {
            code: FindingErrorCode::ScopeDenied,
            summary: "The security finding is outside the caller's scope.",
            cause: "Finding reads and status changes require an exact workspace/namespace scope match.",
            retryable: false,
            next_steps: &[
                "Use an authorized scope or request the required security.finding permission.",
            ],
        }
    }
    fn invalid_transition() -> Self {
        Self {
            code: FindingErrorCode::InvalidTransition,
            summary: "The security finding status transition is not allowed.",
            cause: "Terminal findings cannot be reopened and containment actions are allowlisted and reversible.",
            retryable: false,
            next_steps: &[
                "Read the current status and submit an allowed transition with an authorized actor scope.",
            ],
        }
    }
}

impl fmt::Display for FindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} Cause: {} Next: {}",
            self.code.as_str(),
            self.summary,
            self.cause,
            self.next_steps[0]
        )
    }
}
impl std::error::Error for FindingError {}

#[derive(Debug, Clone)]
pub struct FindingStore {
    capacity: usize,
    findings: Vec<SecurityFinding>,
    updates: Vec<FindingStatusUpdate>,
    by_id: HashMap<String, usize>,
    by_scope_fingerprint: HashMap<(String, String, String), String>,
}

impl FindingStore {
    pub fn new(capacity: usize) -> Result<Self, FindingError> {
        if capacity == 0 || capacity > MAX_FINDINGS {
            return Err(FindingError::capacity());
        }
        Ok(Self {
            capacity,
            findings: Vec::new(),
            updates: Vec::new(),
            by_id: HashMap::new(),
            by_scope_fingerprint: HashMap::new(),
        })
    }

    pub fn append(&mut self, finding: SecurityFinding) -> Result<bool, FindingError> {
        validate_finding(&finding)?;
        if let Some(index) = self.by_id.get(&finding.finding_id).copied() {
            if self.findings[index] == finding {
                return Ok(false);
            }
            return Err(FindingError::duplicate_id());
        }
        let key = (
            finding.workspace_id.clone(),
            finding.namespace_id.clone(),
            finding.fingerprint.clone(),
        );
        if let Some(existing_id) = self.by_scope_fingerprint.get(&key) {
            let existing = self
                .by_id
                .get(existing_id)
                .and_then(|index| self.findings.get(*index))
                .ok_or_else(FindingError::fingerprint_conflict)?;
            if logically_equal(existing, &finding) {
                return Ok(false);
            }
            return Err(FindingError::fingerprint_conflict());
        }
        if self.findings.len() >= self.capacity {
            return Err(FindingError::capacity());
        }
        self.by_scope_fingerprint
            .insert(key, finding.finding_id.clone());
        self.by_id
            .insert(finding.finding_id.clone(), self.findings.len());
        self.findings.push(finding);
        Ok(true)
    }

    pub fn list_scope(
        &self,
        workspace_id: &str,
        namespace_id: &str,
    ) -> Result<Vec<&SecurityFinding>, FindingError> {
        validate_scope(workspace_id, namespace_id)?;
        Ok(self
            .findings
            .iter()
            .filter(|f| f.workspace_id == workspace_id && f.namespace_id == namespace_id)
            .collect())
    }

    pub fn transition(
        &mut self,
        finding_id: &str,
        expected: FindingStatus,
        to: FindingStatus,
        actor_scope: &str,
        action: Option<ContainmentAction>,
    ) -> Result<(), FindingError> {
        let index = self
            .by_id
            .get(finding_id)
            .copied()
            .ok_or_else(FindingError::not_found)?;
        let finding = &self.findings[index];
        validate_scope(&finding.workspace_id, &finding.namespace_id)?;
        if actor_scope != format!("{}/{}", finding.workspace_id, finding.namespace_id) {
            return Err(FindingError::scope_denied());
        }
        let current = self.current_status(finding_id);
        if current != expected || !allowed_transition(current, to) {
            return Err(FindingError::invalid_transition());
        }
        if to == FindingStatus::Contained && action.is_none() {
            return Err(FindingError::invalid_transition());
        }
        self.updates.push(FindingStatusUpdate {
            finding_id: finding_id.to_owned(),
            from: current,
            to,
            action,
            actor_scope: actor_scope.to_owned(),
            at_ms: now_ms(),
        });
        Ok(())
    }

    pub fn current_status(&self, finding_id: &str) -> FindingStatus {
        self.updates
            .iter()
            .rev()
            .find(|u| u.finding_id == finding_id)
            .map_or(FindingStatus::Open, |u| u.to)
    }

    pub fn findings(&self) -> &[SecurityFinding] {
        &self.findings
    }
    pub fn updates(&self) -> &[FindingStatusUpdate] {
        &self.updates
    }
}

pub fn new_finding(input: FindingInput) -> Result<SecurityFinding, FindingError> {
    validate_scope(&input.workspace_id, &input.namespace_id)?;
    if !valid_detector(&input.detector) || input.evidence_refs.len() > MAX_EVIDENCE_REFS {
        return Err(FindingError::invalid_field());
    }
    let evidence_key = input
        .evidence_refs
        .iter()
        .map(|e| format!("{}:{}:{}", e.event_id, e.field_path, e.value_hash))
        .collect::<Vec<_>>()
        .join("|");
    let fingerprint = fingerprint_for(
        input.finding_type,
        &input.workspace_id,
        &input.namespace_id,
        &input.detector,
        &evidence_key,
    );
    let finding = SecurityFinding {
        finding_id: uuid7(),
        finding_type: input.finding_type,
        severity: input.severity,
        confidence: input.confidence,
        workspace_id: input.workspace_id,
        namespace_id: input.namespace_id,
        detector: input.detector,
        evidence_refs: input.evidence_refs,
        policy_decision: input.policy_decision,
        fingerprint,
        created_at_ms: now_ms(),
    };
    validate_finding(&finding)?;
    Ok(finding)
}

/// Convert one trusted, redacted boundary signal into an immutable finding.
/// The store remains the authoritative deduplication and scope boundary.
pub fn detect_and_record(
    store: &mut FindingStore,
    input: DetectionInput,
) -> Result<bool, FindingError> {
    let (finding_type, severity, policy_decision, detector) = match input.signal {
        SecuritySignal::TelemetryIntegrity => (
            FindingType::TelemetryIntegrity,
            FindingSeverity::High,
            PolicyDecision::Deny,
            "telemetry.integrity.v1",
        ),
        SecuritySignal::ScopeIdentityDenied => (
            FindingType::ScopeIdentityDenied,
            FindingSeverity::High,
            PolicyDecision::Deny,
            "identity.scope-denied.v1",
        ),
        SecuritySignal::UntrustedControlBoundary => (
            FindingType::UntrustedControlBoundary,
            FindingSeverity::High,
            PolicyDecision::Deny,
            "control.untrusted-boundary.v1",
        ),
        SecuritySignal::SecretExposure => (
            FindingType::SecretExposure,
            FindingSeverity::Critical,
            PolicyDecision::Deny,
            "data.secret-exposure.v1",
        ),
        SecuritySignal::ToolPolicyDenied => (
            FindingType::ToolPolicyDenied,
            FindingSeverity::High,
            PolicyDecision::Deny,
            "tool.policy-denied.v1",
        ),
        SecuritySignal::AgentTemplateNoncompliant => (
            FindingType::AgentTemplateNoncompliant,
            FindingSeverity::High,
            PolicyDecision::RequireApproval,
            "agent.template-noncompliant.v1",
        ),
    };
    let evidence = EvidenceRef::new(&input.event_id, &input.field_path, &input.value_hash)?;
    store.append(new_finding(FindingInput {
        finding_type,
        severity,
        confidence: FindingConfidence::Deterministic,
        workspace_id: input.workspace_id,
        namespace_id: input.namespace_id,
        detector: detector.to_owned(),
        evidence_refs: vec![evidence],
        policy_decision,
    })?)
}

fn validate_finding(f: &SecurityFinding) -> Result<(), FindingError> {
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

impl SecurityFinding {
    fn evidence_key(&self) -> String {
        self.evidence_refs
            .iter()
            .map(|e| format!("{}:{}:{}", e.event_id, e.field_path, e.value_hash))
            .collect::<Vec<_>>()
            .join("|")
    }
}

fn fingerprint_for(
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

fn valid_detector(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

fn logically_equal(left: &SecurityFinding, right: &SecurityFinding) -> bool {
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

fn validate_scope(workspace: &str, namespace: &str) -> Result<(), FindingError> {
    if is_scope_identifier(workspace) && is_scope_identifier(namespace) {
        Ok(())
    } else {
        Err(FindingError::invalid_field())
    }
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn valid_field_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.contains("..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
}
fn allowed_transition(from: FindingStatus, to: FindingStatus) -> bool {
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
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn uuid7() -> String {
    let time = now_ms();
    let seq = FINDING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let seed = *FINDING_SEED.get_or_init(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos() as u64)
    });
    let entropy = seed.wrapping_add(seq.rotate_left(17));
    format!(
        "{:08x}-{:04x}-7{:03x}-8{:03x}-{:012x}",
        time >> 16,
        time & 0xffff,
        entropy & 0xfff,
        (entropy >> 12) & 0xfff,
        entropy & 0xffffffffffff
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    const EVENT: &str = "018f5c91-2d88-7c00-8000-000000000001";
    const HASH: &str = "2ceaac5b752083018db384977ec25ad50a4dda3bf748ea359c2c1ef9e53e7058";

    fn finding(detector: &str) -> SecurityFinding {
        new_finding(FindingInput {
            finding_type: FindingType::SecretExposure,
            severity: FindingSeverity::Critical,
            confidence: FindingConfidence::Deterministic,
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            detector: detector.to_owned(),
            evidence_refs: vec![EvidenceRef::new(EVENT, "data.secret_hash", HASH).unwrap()],
            policy_decision: PolicyDecision::Deny,
        })
        .unwrap()
    }

    #[test]
    fn creates_redacted_finding_and_scopes_reads() {
        let mut store = FindingStore::new(2).unwrap();
        assert!(store.append(finding("secret-detector")).unwrap());
        assert_eq!(store.list_scope("acme", "prod").unwrap().len(), 1);
        assert!(store.list_scope("other", "prod").unwrap().is_empty());
    }
    #[test]
    fn deduplicates_same_fingerprint_without_overwriting() {
        let mut store = FindingStore::new(2).unwrap();
        let first = finding("same");
        let mut second = first.clone();
        second.finding_id = uuid7();
        assert!(store.append(first).unwrap());
        assert!(!store.append(second).unwrap());
        assert_eq!(store.findings().len(), 1);
    }
    #[test]
    fn rejects_changed_duplicate_id() {
        let mut store = FindingStore::new(2).unwrap();
        let first = finding("one");
        let mut second = first.clone();
        second.severity = FindingSeverity::High;
        assert!(store.append(first).unwrap());
        assert_eq!(
            store.append(second).unwrap_err().code,
            FindingErrorCode::DuplicateId
        );
    }

    #[test]
    fn rejects_fingerprint_downgrade_and_public_record_bypass() {
        let mut store = FindingStore::new(2).unwrap();
        let first = finding("same-signal");
        let mut changed = first.clone();
        changed.finding_id = uuid7();
        changed.severity = FindingSeverity::Low;
        assert!(store.append(first).unwrap());
        assert_eq!(
            store.append(changed).unwrap_err().code,
            FindingErrorCode::FingerprintConflict
        );

        let mut unsafe_record = finding("safe");
        unsafe_record.finding_id = uuid7();
        unsafe_record.detector = "unsafe detector".to_owned();
        assert_eq!(
            store.append(unsafe_record).unwrap_err().code,
            FindingErrorCode::InvalidField
        );

        let mut forged_fingerprint = finding("forged");
        forged_fingerprint.finding_id = uuid7();
        forged_fingerprint.fingerprint = "a".repeat(64);
        assert_eq!(
            store.append(forged_fingerprint).unwrap_err().code,
            FindingErrorCode::InvalidField
        );
    }
    #[test]
    fn transitions_are_append_only_and_scope_checked() {
        let mut store = FindingStore::new(2).unwrap();
        let f = finding("transition");
        let id = f.finding_id.clone();
        store.append(f).unwrap();
        store
            .transition(
                &id,
                FindingStatus::Open,
                FindingStatus::Contained,
                "acme/prod",
                Some(ContainmentAction::Pause),
            )
            .unwrap();
        assert_eq!(store.current_status(&id), FindingStatus::Contained);
        assert_eq!(store.findings()[0].finding_id, id);
        assert_eq!(store.updates().len(), 1);
        assert_eq!(
            store
                .transition(
                    &id,
                    FindingStatus::Contained,
                    FindingStatus::Open,
                    "acme/prod",
                    None
                )
                .unwrap_err()
                .code,
            FindingErrorCode::InvalidTransition
        );
    }
    #[test]
    fn rejects_unsafe_evidence_and_scope() {
        assert!(EvidenceRef::new(EVENT, "data..raw", HASH).is_err());
        assert!(EvidenceRef::new(EVENT, "data.raw", &HASH.to_ascii_uppercase()).is_err());
        assert!(
            new_finding(FindingInput {
                finding_type: FindingType::ToolPolicyDenied,
                severity: FindingSeverity::High,
                confidence: FindingConfidence::Deterministic,
                workspace_id: "../acme".to_owned(),
                namespace_id: "prod".to_owned(),
                detector: "detector".to_owned(),
                evidence_refs: vec![],
                policy_decision: PolicyDecision::Deny,
            })
            .is_err()
        );
    }
    #[test]
    fn capacity_and_not_found_errors_are_actionable() {
        assert_eq!(
            FindingStore::new(0).unwrap_err().code,
            FindingErrorCode::Capacity
        );
        let mut store = FindingStore::new(1).unwrap();
        store.append(finding("capacity")).unwrap();
        assert_eq!(
            store.append(finding("other")).unwrap_err().code,
            FindingErrorCode::Capacity
        );
        assert_eq!(
            store
                .transition(
                    EVENT,
                    FindingStatus::Open,
                    FindingStatus::Acknowledged,
                    "acme/prod",
                    None
                )
                .unwrap_err()
                .code,
            FindingErrorCode::NotFound
        );
    }

    #[test]
    fn validates_bounded_detector_and_evidence_collections() {
        let base = || FindingInput {
            finding_type: FindingType::TelemetryIntegrity,
            severity: FindingSeverity::High,
            confidence: FindingConfidence::Corroborated,
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            detector: "detector".to_owned(),
            evidence_refs: vec![],
            policy_decision: PolicyDecision::RequireApproval,
        };
        let mut input = base();
        input.detector = "bad detector".to_owned();
        assert_eq!(
            new_finding(input).unwrap_err().code,
            FindingErrorCode::InvalidField
        );
        let mut input = base();
        input.evidence_refs = (0..=MAX_EVIDENCE_REFS)
            .map(|_| EvidenceRef::new(EVENT, "data.hash", HASH).unwrap())
            .collect();
        assert_eq!(
            new_finding(input).unwrap_err().code,
            FindingErrorCode::InvalidField
        );
        assert!(FindingStore::new(MAX_FINDINGS + 1).is_err());
        assert!(
            FindingError::invalid_field()
                .to_string()
                .contains("INVALID_SECURITY_FINDING_FIELD")
        );
    }

    #[test]
    fn enforces_scope_and_allowlisted_status_transitions() {
        let mut store = FindingStore::new(8).unwrap();
        let record = finding("status");
        let id = record.finding_id.clone();
        store.append(record).unwrap();
        assert_eq!(
            store.list_scope("bad scope", "prod").unwrap_err().code,
            FindingErrorCode::InvalidField
        );
        assert_eq!(
            store
                .transition(
                    &id,
                    FindingStatus::Open,
                    FindingStatus::Acknowledged,
                    "other/prod",
                    None
                )
                .unwrap_err()
                .code,
            FindingErrorCode::ScopeDenied
        );
        assert_eq!(
            store
                .transition(
                    &id,
                    FindingStatus::Open,
                    FindingStatus::Contained,
                    "acme/prod",
                    None
                )
                .unwrap_err()
                .code,
            FindingErrorCode::InvalidTransition
        );
        store
            .transition(
                &id,
                FindingStatus::Open,
                FindingStatus::Acknowledged,
                "acme/prod",
                None,
            )
            .unwrap();
        store
            .transition(
                &id,
                FindingStatus::Acknowledged,
                FindingStatus::Contained,
                "acme/prod",
                Some(ContainmentAction::Quarantine),
            )
            .unwrap();
        store
            .transition(
                &id,
                FindingStatus::Contained,
                FindingStatus::Resolved,
                "acme/prod",
                Some(ContainmentAction::DisableTool),
            )
            .unwrap();
        assert_eq!(store.current_status(&id), FindingStatus::Resolved);
    }

    #[test]
    fn rejects_invalid_finding_records_and_evidence_paths() {
        assert!(EvidenceRef::new(EVENT, "", HASH).is_err());
        assert!(EvidenceRef::new(EVENT, &"x".repeat(257), HASH).is_err());
        assert!(EvidenceRef::new(EVENT, "data raw", HASH).is_err());
        let mut record = finding("record");
        record.finding_id = "not-a-uuid".to_owned();
        let mut store = FindingStore::new(1).unwrap();
        assert_eq!(
            store.append(record).unwrap_err().code,
            FindingErrorCode::InvalidField
        );
    }

    #[test]
    fn deterministic_detector_maps_each_signal_to_redacted_findings() {
        let signals = [
            SecuritySignal::TelemetryIntegrity,
            SecuritySignal::ScopeIdentityDenied,
            SecuritySignal::UntrustedControlBoundary,
            SecuritySignal::SecretExposure,
            SecuritySignal::ToolPolicyDenied,
            SecuritySignal::AgentTemplateNoncompliant,
        ];
        let mut store = FindingStore::new(8).unwrap();
        for (index, signal) in signals.into_iter().enumerate() {
            assert!(
                detect_and_record(
                    &mut store,
                    DetectionInput {
                        signal,
                        workspace_id: "acme".to_owned(),
                        namespace_id: "prod".to_owned(),
                        event_id: EVENT.to_owned(),
                        field_path: format!("data.signal_{index}"),
                        value_hash: HASH.to_owned(),
                    },
                )
                .unwrap()
            );
        }
        assert_eq!(store.findings().len(), signals.len());
        assert_eq!(store.findings()[3].severity, FindingSeverity::Critical);
        assert_eq!(
            store.findings()[5].policy_decision,
            PolicyDecision::RequireApproval
        );
        assert!(
            !detect_and_record(
                &mut store,
                DetectionInput {
                    signal: SecuritySignal::SecretExposure,
                    workspace_id: "acme".to_owned(),
                    namespace_id: "prod".to_owned(),
                    event_id: EVENT.to_owned(),
                    field_path: "data.signal_3".to_owned(),
                    value_hash: HASH.to_owned(),
                },
            )
            .unwrap()
        );
    }

    #[test]
    fn detector_rejects_untrusted_or_cross_scope_inputs_before_storage() {
        let mut store = FindingStore::new(2).unwrap();
        let mut input = DetectionInput {
            signal: SecuritySignal::SecretExposure,
            workspace_id: "acme".to_owned(),
            namespace_id: "prod".to_owned(),
            event_id: EVENT.to_owned(),
            field_path: "data.secret".to_owned(),
            value_hash: HASH.to_owned(),
        };
        input.value_hash = HASH.to_ascii_uppercase();
        assert_eq!(
            detect_and_record(&mut store, input.clone())
                .unwrap_err()
                .code,
            FindingErrorCode::InvalidField
        );
        input.value_hash = HASH.to_owned();
        input.workspace_id = "../acme".to_owned();
        assert_eq!(
            detect_and_record(&mut store, input).unwrap_err().code,
            FindingErrorCode::InvalidField
        );
        assert!(store.findings().is_empty());
    }

    #[test]
    fn generated_finding_ids_are_uuidv7_and_unique_for_a_burst() {
        let first = uuid7();
        let second = uuid7();
        assert!(is_lowercase_uuidv7(&first));
        assert!(is_lowercase_uuidv7(&second));
        assert_ne!(first, second);
    }
}
