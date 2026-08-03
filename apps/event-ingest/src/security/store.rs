use std::collections::HashMap;

use super::error::FindingError;
use super::ids::now_ms;
use super::types::{ContainmentAction, FindingStatus, FindingStatusUpdate, SecurityFinding};
use super::validate::{
    MAX_FINDINGS, allowed_transition, logically_equal, validate_finding, validate_scope,
};

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

    /// Returns findings for exactly one authorized scope. Future API layers
    /// must use this method rather than exporting the unfiltered in-process
    /// slice, which intentionally remains only a local inspection seam.
    pub fn findings_for_scope(
        &self,
        workspace_id: &str,
        namespace_id: &str,
    ) -> Result<Vec<&SecurityFinding>, FindingError> {
        validate_scope(workspace_id, namespace_id)?;
        Ok(self
            .findings
            .iter()
            .filter(|finding| {
                finding.workspace_id == workspace_id && finding.namespace_id == namespace_id
            })
            .collect())
    }

    pub fn updates(&self) -> &[FindingStatusUpdate] {
        &self.updates
    }
}
