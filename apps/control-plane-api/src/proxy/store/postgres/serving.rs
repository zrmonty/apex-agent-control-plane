//! Private durable metadata seam. This does not authenticate or enable serving.
#![allow(dead_code)] // Main's bounded authenticated service owner is a later slice.

use super::operation_journal as journal;
use super::{PostgresProxyStore, configuration_error};
use crate::{LeasedProxyOperation, ProxyError, proto};
use apex_durability::{PostgresClientOps, PostgresTransaction};
use prost::Message;
use uuid::Uuid;

mod attested;
pub(super) mod record;
mod registration;
pub(super) mod renewal;
pub(super) mod transaction;
mod transitions;
use transaction::{BindingKey, CheckedTransaction, positive, refused};

#[derive(Clone)]
pub(crate) struct DeploymentRegistration {
    pub binding: proto::ManagedDeploymentBinding,
    pub configuration: proto::RuntimeConfiguration,
    pub authority_profile_ref: String,
    pub authority_profile_version: String,
    pub proof_sha256: [u8; 32],
}

/// Metadata from main's authenticated probe, not a constructed authority token.
pub(crate) struct CandidateReadiness {
    pub report: proto::ReadinessReport,
    pub admitting: bool,
    pub active_calls: u64,
}

/// Point-in-time metadata for main's verifier/projection; not route permission.
pub(crate) struct DeploymentRecord {
    pub registration: DeploymentRegistration,
    pub epoch: u64,
    pub mode: proto::ManagedGrantMode,
    pub selected_instance: Option<Uuid>,
    pub highest_sequence: u64,
    pub applied: Option<AppliedDecision>,
    pub active_calls: u64,
    pub terminated: bool,
}

pub(crate) struct AppliedDecision {
    pub decision_id: Uuid,
    pub epoch: u64,
    pub mode: proto::ManagedGrantMode,
    pub sequence: u64,
    pub valid_until_unix_us: u64,
    pub admitting: bool,
}

impl PostgresProxyStore {
    /// Read-only candidate policy preflight; never grants call or route authority.
    pub(crate) fn read_eligible_deployment_checked(
        &self,
        binding: &proto::ManagedDeploymentBinding,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<DeploymentRecord, ProxyError> {
        self.with_deployment(binding, None, check, |tx, key| {
            let record = record::read(tx, key, binding)?;
            if record.terminated
                || !matches!(
                    record.mode,
                    proto::ManagedGrantMode::Prepare | proto::ManagedGrantMode::Serve
                )
                || (record.mode == proto::ManagedGrantMode::Serve
                    && record.selected_instance != Some(key.instance))
            {
                return Err(refused());
            }
            renewal::eligible(tx, key, binding, record.mode as i32)?;
            Ok(record)
        })
    }

    pub(crate) fn read_deployment_checked(
        &self,
        binding: &proto::ManagedDeploymentBinding,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<DeploymentRecord, ProxyError> {
        self.with_deployment(binding, None, check, |tx, key| {
            record::read(tx, key, binding)
        })
    }

    pub(crate) fn renew_deployment_checked(
        &self,
        input: &proto::ManagedDeploymentRenewal,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<proto::ManagedDeploymentGrant, ProxyError> {
        let binding = input.binding.as_ref().ok_or_else(refused)?;
        positive(input.renewal_sequence)?;
        if input.nonce.len() != 32 || input.encoded_len() > 8192 {
            return Err(refused());
        }
        self.with_deployment(binding, None, check, |tx, key| {
            renewal::renew(tx, key, input)
        })
    }

    /// Main supplies an authenticated fresh probe. This type contains only data.
    pub(crate) fn record_candidate_readiness_checked(
        &self,
        lease: &LeasedProxyOperation,
        binding: &proto::ManagedDeploymentBinding,
        report: &CandidateReadiness,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<Uuid, ProxyError> {
        self.with_deployment(binding, Some(lease), check, |tx, key| {
            transitions::readiness(tx, key, lease, binding, report)
        })
    }

    pub(crate) fn select_candidate_checked(
        &self,
        lease: &LeasedProxyOperation,
        binding: &proto::ManagedDeploymentBinding,
        readiness: Uuid,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<u64, ProxyError> {
        self.with_deployment(binding, Some(lease), check, |tx, key| {
            transitions::select(tx, key, lease, binding, readiness)
        })
    }

    pub(crate) fn withdraw_deployment_checked(
        &self,
        lease: &LeasedProxyOperation,
        binding: &proto::ManagedDeploymentBinding,
        reason: Withdrawal,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<u64, ProxyError> {
        self.with_deployment(binding, Some(lease), check, |tx, key| {
            transitions::withdraw(tx, key, lease, binding, reason)
        })
    }

    /// Main independently verifies termination of this exact immutable instance.
    pub(crate) fn record_deployment_termination_checked(
        &self,
        lease: &LeasedProxyOperation,
        binding: &proto::ManagedDeploymentBinding,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<(), ProxyError> {
        self.with_deployment(binding, Some(lease), check, |tx, key| {
            transitions::terminate(tx, key, binding)
        })
    }

    pub(super) fn with_deployment<R, F: Fn() -> Result<(), ProxyError>>(
        &self,
        binding: &proto::ManagedDeploymentBinding,
        lease: Option<&LeasedProxyOperation>,
        check: &F,
        action: impl FnOnce(&mut CheckedTransaction<'_, '_, F>, &BindingKey) -> Result<R, ProxyError>,
    ) -> Result<R, ProxyError> {
        let key = BindingKey::new(binding)?;
        let mut client = self.client.try_lock_checked(check)?;
        check()?;
        let mut tx = CheckedTransaction::new(
            client.transaction().map_err(|_| configuration_error())?,
            &key,
            check,
        )?;
        if let Some(lease) = lease {
            tx.lease(lease)?;
        }
        let result = action(&mut tx, &key)?;
        tx.finish(lease)?;
        drop(client);
        check()?;
        Ok(result)
    }

    pub(crate) fn register_deployment_checked(
        &self,
        lease: &LeasedProxyOperation,
        input: &DeploymentRegistration,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<(), ProxyError> {
        let key = BindingKey::new(&input.binding)?;
        let mut client = self.client.try_lock_checked(check)?;
        check()?;
        let tx = client.transaction().map_err(|_| configuration_error())?;
        let mut tx = CheckedTransaction::new(tx, &key, check)?;
        tx.lease(lease)?;
        registration::register(&mut tx, &key, lease, input)?;
        tx.finish(Some(lease))?;
        drop(client);
        check()
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Withdrawal {
    Replacement,
    Pause,
    Retire,
}

#[cfg(test)]
mod tests;
