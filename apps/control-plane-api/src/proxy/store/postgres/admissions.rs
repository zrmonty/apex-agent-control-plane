//! Private reservation data seam; authentication and Apex evaluation belong to main.
#![allow(dead_code)] // Consumed by main's separately reviewed bounded service owner.
use super::PostgresProxyStore;
use super::operation_journal as journal;
use super::serving::transaction::{BindingKey, CheckedTransaction};
use crate::{ProxyError, proto};
use uuid::Uuid;
mod cleanup;
mod guard;
mod reserve;

#[derive(Clone)]
pub(crate) struct ManagedCallReservation {
    pub binding: proto::ManagedDeploymentBinding,
    pub call_id: Uuid,
    pub semantic_sha256: [u8; 32],
    pub policy_id: String,
    pub policy_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagedCallAdmission {
    pub admission_id: Uuid,
    pub call_id: Uuid,
    pub epoch: u64,
    pub policy_revision: u64,
    pub expires_at_unix_us: u64,
    pub valid_for_us: u64,
}

fn refused() -> ProxyError {
    ProxyError::new(
        "MANAGED_ADMISSION_REFUSED",
        "Managed call reservation refused.",
    )
}

impl PostgresProxyStore {
    /// Read-only business eligibility; main still authenticates and evaluates policy.
    pub(crate) fn read_admittable_deployment_checked(
        &self,
        binding: &proto::ManagedDeploymentBinding,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<super::serving::DeploymentRecord, ProxyError> {
        self.with_deployment(binding, None, check, |tx, key| {
            guard::admittable(tx, key, binding)?;
            super::serving::record::read(tx, key, binding)
        })
    }

    pub(crate) fn reserve_managed_call_checked(
        &self,
        input: &ManagedCallReservation,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<ManagedCallAdmission, ProxyError> {
        check()?;
        journal::request_uuid(&input.call_id.to_string())?;
        if input.policy_revision == 0 || !journal::bounded_identifier(&input.policy_id) {
            return Err(refused());
        }
        self.with_deployment(&input.binding, None, check, |tx, key| {
            reserve::reserve(tx, key, input)
        })
    }

    /// Call only after main authenticates exact physical cleanup completion.
    pub(crate) fn complete_managed_call_checked(
        &self,
        binding: &proto::ManagedDeploymentBinding,
        admission_id: Uuid,
        call_id: Uuid,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<(), ProxyError> {
        check()?;
        journal::request_uuid(&call_id.to_string())?;
        journal::request_uuid(&admission_id.to_string())?;
        self.with_deployment(binding, None, check, |tx, key| {
            cleanup::complete(tx, key, binding, admission_id, call_id)
        })
    }

    /// No caller-supplied termination boolean: consume existing exact registry fact.
    pub(crate) fn release_terminated_admissions_checked(
        &self,
        binding: &proto::ManagedDeploymentBinding,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<u64, ProxyError> {
        self.with_deployment(binding, None, check, |tx, key| {
            cleanup::terminated(tx, key, binding)
        })
    }
}

#[cfg(test)]
mod tests;
