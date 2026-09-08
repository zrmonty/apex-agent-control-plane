//! Private durable metadata seam. Selection still needs a later applied SERVE.
#![allow(dead_code)] // Lifecycle/projection consumers are outside this bounded slice.

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

/// Metadata from the controller's authenticated probe, not an authority token.
pub(crate) struct CandidateReadiness {
    /// Original local health deadline, never renewed by a database handoff.
    pub expires: std::time::Instant,
    pub report: proto::ReadinessReport,
    pub admitting: bool,
    pub active_calls: u64,
}

impl CandidateReadiness {
    fn remaining_us(&self, now: std::time::Instant) -> Result<i64, ProxyError> {
        let remaining = self
            .expires
            .checked_duration_since(now)
            .ok_or_else(refused)?;
        i64::try_from(remaining.as_micros().min(5_000_000))
            .ok()
            .filter(|us| *us > 0)
            .ok_or_else(refused)
    }
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
    /// Fenced, policy-checked preflight for the controller's original launch.
    /// A selected or closed instance needs no candidate health consumption.
    pub(crate) fn read_health_candidate_checked(
        &self,
        lease: &LeasedProxyOperation,
        binding: &proto::ManagedDeploymentBinding,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<Option<DeploymentRecord>, ProxyError> {
        self.with_deployment(binding, Some(lease), check, |tx, key| {
            let record = record::read(tx, key, binding)?;
            if record.terminated
                || record.mode != proto::ManagedGrantMode::Prepare
                || record.selected_instance.is_some()
            {
                return Ok(None);
            }
            let row = transitions::candidate(tx, key, lease, binding)?;
            let until = transitions::applied_prepare_expiry(tx, key, &row)?;
            tx.require_valid_until(until);
            Ok(Some(record))
        })
    }

    /// Consumes one original authenticated observation, retaining its local
    /// lifetime through both transactions. Selection is not applied SERVE.
    pub(crate) fn select_healthy_candidate_checked(
        &self,
        lease: &LeasedProxyOperation,
        binding: &proto::ManagedDeploymentBinding,
        observation: crate::proxy::runtime_client::health::HealthObservation,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<(), ProxyError> {
        // Anchor before consumption: time spent handing off cannot extend life.
        let anchor = std::time::Instant::now();
        let (report, remaining) = observation.into_remaining()?;
        let expires = anchor.checked_add(remaining).ok_or_else(refused)?;
        let fresh = || {
            check()?;
            if std::time::Instant::now() >= expires {
                return Err(refused());
            }
            Ok(())
        };
        let Some(current) = self.read_health_candidate_checked(lease, binding, &fresh)? else {
            return Ok(());
        };
        let observation = CandidateReadiness {
            report,
            expires,
            admitting: current.applied.as_ref().ok_or_else(refused)?.admitting,
            active_calls: current.active_calls,
        };
        let readiness =
            self.record_candidate_readiness_checked(lease, binding, &observation, &fresh)?;
        self.select_candidate_checked(lease, binding, readiness, &fresh)?;
        Ok(())
    }

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

    /// The controller supplies a fresh authenticated probe and its local expiry.
    pub(crate) fn record_candidate_readiness_checked(
        &self,
        lease: &LeasedProxyOperation,
        binding: &proto::ManagedDeploymentBinding,
        report: &CandidateReadiness,
        check: &impl Fn() -> Result<(), ProxyError>,
    ) -> Result<Uuid, ProxyError> {
        self.record_candidate_readiness_at_checked(
            lease,
            binding,
            report,
            check,
            &std::time::Instant::now,
        )
    }

    fn record_candidate_readiness_at_checked(
        &self,
        lease: &LeasedProxyOperation,
        binding: &proto::ManagedDeploymentBinding,
        report: &CandidateReadiness,
        check: &impl Fn() -> Result<(), ProxyError>,
        now: &impl Fn() -> std::time::Instant,
    ) -> Result<Uuid, ProxyError> {
        let fresh = || {
            check()?;
            report.remaining_us(now()).map(|_| ())
        };
        self.with_deployment(binding, Some(lease), &fresh, |tx, key| {
            transitions::readiness(tx, key, lease, binding, report, now)
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
