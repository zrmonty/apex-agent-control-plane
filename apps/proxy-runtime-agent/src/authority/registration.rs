//! Pinned durable identity callback. A receipt never permits runtime effects.
use super::{
    AuthorityClientConfig, AuthorityClientError as Error, AuthorityOperation, MAX_BUDGET,
    RuntimeAuthorityClient, configuration, peer_error, remote_error, snapshot,
};
use crate::proto;
use apex_auth::{PeerIdentity, RuntimePeerPolicy, RuntimePeerRole};
use prost::Message;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    future::Future,
    time::{Duration, Instant},
};
use tonic::Request;

pub(super) const REQUEST_LIMIT: usize = 24_576;
pub(super) const REPLY_LIMIT: usize = 16_384;

impl RuntimeAuthorityClient {
    /// Register immutable launch metadata over the existing pinned Agent channel.
    /// The owner must supply the installed sealed attestation and current policy.
    /// A returned receipt is neither readiness nor a grant to perform effects.
    ///
    /// # Errors
    /// Refuses invalid input, non-Controller TLS, exhausted bounds, remote refusal
    /// and any receipt or current-operation mismatch. Errors retain no response.
    pub async fn register<T>(
        &self,
        incoming: &Request<T>,
        current_policy: &RuntimePeerPolicy,
        operation: AuthorityOperation<'_>,
        attestation: &proto::RuntimeLaunchAttestation,
        budget: Duration,
    ) -> Result<proto::RuntimeDeploymentRegistrationReceipt, Error> {
        let started = Instant::now();
        let budget = budget.min(MAX_BUDGET);
        remaining(started, budget)?;
        validate_input(attestation, &self.config, &operation)?;
        let authorize = || {
            current_policy
                .authorize(
                    incoming,
                    RuntimePeerRole::Controller,
                    &self.config.installation_id,
                    &operation.target.workspace_id,
                    &operation.target.namespace_id,
                )
                .map_err(peer_error)
        };
        let authenticated = authorize()?;
        let peer = PeerIdentity::from_request(incoming).ok_or(Error::Unauthenticated)?;
        // The same semaphore covers check, resolve and registration through the
        // final handoff; no queued acquire, background retry or spawned owner.
        let _slot = self.slots.try_acquire().map_err(|_| Error::Overloaded)?;
        let body = proto::RegisterRuntimeDeploymentRequest {
            authority: Some(proto::CheckRuntimeAuthorityRequest {
                schema_version: 1,
                target: Some(operation.target.clone()),
                operation_id: operation.operation_id.into(),
                command_id: operation.command_id.into(),
                action: proto::RuntimeAuthorityAction::CheckCurrentOperation.into(),
                installation_id: self.config.installation_id.clone(),
                observed_controller_certificate_sha256: peer.certificate_sha256.to_vec(),
            }),
            attestation: Some(attestation.clone()),
        };
        if body.encoded_len() > REQUEST_LIMIT {
            return Err(Error::InvalidInput);
        }
        let mut request = Request::new(body);
        request.set_timeout(remaining(started, budget)?);
        let reply = await_reply(started, budget, async {
            self.registration_client
                .clone()
                .register_deployment(request)
                .await
                .map_err(remote_error)
                .map(tonic::Response::into_inner)
        })
        .await?;
        // Reauthorize the actual same inbound request, never a synthesized peer.
        let handoff = authorize()?;
        if handoff.identity_id() != authenticated.identity_id()
            || handoff.policy_version() != authenticated.policy_version()
        {
            return Err(Error::Denied);
        }
        validate_receipt(
            &reply,
            attestation,
            &self.config,
            &operation,
            handoff.identity_id(),
            handoff.policy_version(),
            started.elapsed(),
        )?;
        remaining(started, budget)?;
        snapshot::validate_elapsed(
            reply.authority.as_ref().ok_or(Error::InvalidSnapshot)?,
            started.elapsed(),
        )?;
        remaining(started, budget)?;
        Ok(reply)
    }
}

fn remaining(started: Instant, budget: Duration) -> Result<Duration, Error> {
    budget
        .checked_sub(started.elapsed())
        .filter(|left| !left.is_zero())
        .ok_or(Error::Deadline)
}

async fn await_reply(
    started: Instant,
    budget: Duration,
    future: impl Future<Output = Result<proto::RuntimeDeploymentRegistrationReceipt, Error>>,
) -> Result<proto::RuntimeDeploymentRegistrationReceipt, Error> {
    remaining(started, budget)?;
    let result =
        tokio::time::timeout_at(tokio::time::Instant::from_std(started + budget), future).await;
    // timeout_at alone misses synchronous work in the final ready poll.
    remaining(started, budget)?;
    result.map_err(|_| Error::Deadline)?
}

fn validate_input(
    attestation: &proto::RuntimeLaunchAttestation,
    config: &AuthorityClientConfig,
    operation: &AuthorityOperation<'_>,
) -> Result<(), Error> {
    configuration::validate_operation(operation)?;
    if attestation.encoded_len() > REQUEST_LIMIT {
        return Err(Error::InvalidInput);
    }
    let launch = attestation.launch.as_ref().ok_or(Error::InvalidInput)?;
    let original = launch.target.as_ref().ok_or(Error::InvalidInput)?;
    let health = launch.health.as_ref().ok_or(Error::InvalidInput)?;
    let current = operation.target;
    if attestation.schema_version != 1
        || attestation.installation_id != config.installation_id
        || !crate::shapes::hex_hash(&attestation.instance_proof_sha256)
        || !crate::shapes::hex_hash(&attestation.staged_manifest_sha256)
        || !crate::shapes::image_id(&attestation.image_id)
        || launch.schema_version != 1
        || crate::check_runtime_target(original).is_err()
        || !configuration::sql_positive(original.fencing_token)
        || original.fencing_token > current.fencing_token
        || original.workspace_id != current.workspace_id
        || original.namespace_id != current.namespace_id
        || original.proxy_id != current.proxy_id
        || original.revision_id != current.revision_id
        || original.generation != current.generation
        || launch.config_hash != operation.config_hash
        || !crate::shapes::uuid_v7(&launch.process_instance_id)
        || !crate::shapes::hex_hash(&launch.launch_context_hash)
        || !crate::shapes::hex_hash(&launch.runtime_manifest_hash)
        || !crate::shapes::image_ref(&launch.image_ref)
        || !identifier(&launch.authority_profile_ref)
        || !identifier(&launch.authority_profile_version)
        || health.port != 8081
        || launch.materials.len() != 13
    {
        return Err(Error::InvalidInput);
    }
    let mut roles = BTreeSet::new();
    let mut references = BTreeSet::new();
    for material in &launch.materials {
        if !(1..=13).contains(&material.role)
            || !roles.insert(material.role)
            || !references.insert(&material.reference)
            || !reference(&material.reference)
            || !identifier(&material.version)
            || (material.role == proto::RuntimeMaterialRole::HealthToken as i32
                && health.credential_ref != material.reference)
        {
            return Err(Error::InvalidInput);
        }
    }
    Ok(())
}

fn identifier(value: &str) -> bool {
    value.len() <= 128 && crate::shapes::scope(value)
}
fn reference(value: &str) -> bool {
    value.len() <= 256
        && value.strip_prefix("secret://").is_some_and(|tail| {
            tail.as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
                && tail
                    .split('/')
                    .all(|part| part != "." && crate::shapes::scope(part))
        })
}

fn validate_receipt(
    reply: &proto::RuntimeDeploymentRegistrationReceipt,
    attestation: &proto::RuntimeLaunchAttestation,
    config: &AuthorityClientConfig,
    operation: &AuthorityOperation<'_>,
    controller: &str,
    policy_version: &str,
    elapsed: Duration,
) -> Result<(), Error> {
    validate_input(attestation, config, operation)?;
    if reply.encoded_len() > REPLY_LIMIT {
        return Err(Error::InvalidSnapshot);
    }
    let launch = attestation.launch.as_ref().ok_or(Error::InvalidInput)?;
    let binding = reply.binding.as_ref().ok_or(Error::InvalidSnapshot)?;
    if binding.installation_id != attestation.installation_id || binding.target != launch.target
        || binding.process_instance_id != launch.process_instance_id || binding.config_hash != launch.config_hash
        || binding.launch_context_hash != launch.launch_context_hash
        // Input's encoded length was bounded BEFORE allocating protobuf bytes.
        || reply.attestation_sha256 != format!("{:x}", Sha256::digest(attestation.encode_to_vec()))
    {
        return Err(Error::MismatchedSnapshot);
    }
    snapshot::validate(
        reply.authority.as_ref().ok_or(Error::InvalidSnapshot)?,
        config,
        operation,
        controller,
        policy_version,
        elapsed,
    )
}

#[cfg(test)]
mod tests;
