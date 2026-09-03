use std::{collections::HashMap, fmt};

use super::error::FindingError;
use super::ids::now_ms;
use super::types::{ContainmentAction, FindingStatus, FindingStatusUpdate, SecurityFinding};
use super::validate::{
    MAX_FINDINGS, MAX_STATUS_UPDATES_PER_FINDING, allowed_transition, logically_equal,
    valid_actor_scope, validate_finding, validate_scope,
};
use crate::Caller;

#[derive(Clone)]
pub struct FindingStore {
    scope_capacity: usize,
    global_capacity: usize,
    max_updates: usize,
    findings: Vec<SecurityFinding>,
    updates: Vec<FindingStatusUpdate>,
    by_id: HashMap<String, usize>,
    by_scope_fingerprint: HashMap<(String, String, String), String>,
    scope_counts: HashMap<(String, String), usize>,
}

// Findings and status history are tenant data. Never include either collection
// in derived debug output, because diagnostics may cross an application
// boundary even when the scoped read APIs are correctly authorized.
impl fmt::Debug for FindingStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FindingStore")
            .field("scope_capacity", &self.scope_capacity)
            .field("global_capacity", &self.global_capacity)
            .field("max_updates", &self.max_updates)
            .field("finding_count", &self.findings.len())
            .field("update_count", &self.updates.len())
            .finish()
    }
}

impl FindingStore {
    /// Creates a store with an independent per-scope quota and the maximum
    /// bounded global hard cap.
    pub fn new(scope_capacity: usize) -> Result<Self, FindingError> {
        Self::with_quotas(scope_capacity, MAX_FINDINGS)
    }

    /// Creates a store with explicit per-scope and global quotas. The global
    /// cap prevents an attacker from bypassing tenant quotas by creating many
    /// scopes, while the scope cap prevents one tenant from starving others.
    pub fn with_quotas(
        scope_capacity: usize,
        global_capacity: usize,
    ) -> Result<Self, FindingError> {
        if scope_capacity == 0
            || global_capacity == 0
            || scope_capacity > global_capacity
            || global_capacity > MAX_FINDINGS
        {
            return Err(FindingError::capacity());
        }
        Ok(Self {
            scope_capacity,
            global_capacity,
            max_updates: global_capacity.saturating_mul(MAX_STATUS_UPDATES_PER_FINDING),
            findings: Vec::new(),
            updates: Vec::new(),
            by_id: HashMap::new(),
            by_scope_fingerprint: HashMap::new(),
            scope_counts: HashMap::new(),
        })
    }

    /// Internal persistence seam. Public callers must use `detect_and_record`
    /// so finding classification cannot be supplied by an untrusted writer.
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
        if self.findings.len() >= self.global_capacity {
            return Err(FindingError::capacity());
        }
        let scope = (finding.workspace_id.clone(), finding.namespace_id.clone());
        if self.scope_counts.get(&scope).copied().unwrap_or(0) >= self.scope_capacity {
            return Err(FindingError::capacity());
        }
        self.by_scope_fingerprint
            .insert(key, finding.finding_id.clone());
        self.by_id
            .insert(finding.finding_id.clone(), self.findings.len());
        self.scope_counts
            .entry(scope)
            .and_modify(|count| *count += 1)
            .or_insert(1);
        self.findings.push(finding);
        Ok(true)
    }

    pub fn transition(
        &mut self,
        finding_id: &str,
        expected: FindingStatus,
        to: FindingStatus,
        caller: &Caller,
        actor_scope: &str,
        action: Option<ContainmentAction>,
    ) -> Result<(), FindingError> {
        if !valid_actor_scope(actor_scope) {
            return Err(FindingError::scope_denied());
        }
        let actor_subject = caller
            .subject()
            .filter(|subject| !subject.is_empty())
            .ok_or_else(FindingError::scope_denied)?;
        if !caller.allows_scope(actor_scope) {
            return Err(FindingError::scope_denied());
        }
        self.transition_internal(finding_id, expected, to, actor_scope, actor_subject, action)
    }

    /// Replays an already-authenticated journal record during startup. New
    /// callers must use `transition`, which requires a verified Caller.
    pub fn transition_replayed(
        &mut self,
        finding_id: &str,
        expected: FindingStatus,
        to: FindingStatus,
        actor_scope: &str,
        actor_subject: &str,
        action: Option<ContainmentAction>,
    ) -> Result<(), FindingError> {
        if actor_subject.is_empty() || !valid_actor_scope(actor_scope) {
            return Err(FindingError::scope_denied());
        }
        self.transition_internal(finding_id, expected, to, actor_scope, actor_subject, action)
    }

    fn transition_internal(
        &mut self,
        finding_id: &str,
        expected: FindingStatus,
        to: FindingStatus,
        actor_scope: &str,
        actor_subject: &str,
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
        let current = self.current_status(finding_id)?;
        if current != expected || !allowed_transition(current, to) {
            return Err(FindingError::invalid_transition());
        }
        if matches!(to, FindingStatus::Contained | FindingStatus::Resolved) && action.is_none() {
            return Err(FindingError::invalid_transition());
        }
        if self.updates.len() >= self.max_updates {
            return Err(FindingError::capacity());
        }
        self.updates.push(FindingStatusUpdate {
            finding_id: finding_id.to_owned(),
            from: current,
            to,
            action,
            actor_scope: actor_scope.to_owned(),
            actor_subject: actor_subject.to_owned(),
            at_ms: now_ms()?,
        });
        Ok(())
    }

    pub fn current_status(&self, finding_id: &str) -> Result<FindingStatus, FindingError> {
        if !self.by_id.contains_key(finding_id) {
            return Err(FindingError::not_found());
        }
        Ok(self
            .updates
            .iter()
            .rev()
            .find(|u| u.finding_id == finding_id)
            .map_or(FindingStatus::Open, |u| u.to))
    }

    /// Returns findings for exactly one caller-authorized scope. The backing
    /// collection is never exported, even to diagnostic callers.
    pub fn findings_for_scope(
        &self,
        caller: &Caller,
        workspace_id: &str,
        namespace_id: &str,
    ) -> Result<Vec<&SecurityFinding>, FindingError> {
        validate_scope(workspace_id, namespace_id)?;
        let scope = format!("{workspace_id}/{namespace_id}");
        if !caller.allows_scope(&scope) {
            return Err(FindingError::scope_denied());
        }
        Ok(self
            .findings
            .iter()
            .filter(|finding| {
                finding.workspace_id == workspace_id && finding.namespace_id == namespace_id
            })
            .collect())
    }

    pub fn updates_for_scope(
        &self,
        caller: &Caller,
        workspace_id: &str,
        namespace_id: &str,
    ) -> Result<Vec<&FindingStatusUpdate>, FindingError> {
        validate_scope(workspace_id, namespace_id)?;
        let scope = format!("{workspace_id}/{namespace_id}");
        if !caller.allows_scope(&scope) {
            return Err(FindingError::scope_denied());
        }
        Ok(self
            .updates
            .iter()
            .filter(|update| {
                self.by_id
                    .get(&update.finding_id)
                    .and_then(|index| self.findings.get(*index))
                    .is_some_and(|finding| {
                        finding.workspace_id == workspace_id && finding.namespace_id == namespace_id
                    })
            })
            .collect())
    }

    pub fn updates(&self) -> &[FindingStatusUpdate] {
        &self.updates
    }
}

