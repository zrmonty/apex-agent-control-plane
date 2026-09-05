//! Supported Docker identity/state input only, never raw engine diagnostics.
//!
//! Bounds: 65,536 UTF-8 input bytes, nesting depth 32, 64 labels total, label
//! keys 1..=128 bytes and values <=512 bytes. Unknown fields are ignored without
//! retaining Config.Env, mounts or host paths. Duplicate required fields/labels
//! refuse. Extraction IDs are 1..=128 bytes; only the ownership check requires
//! exact lower64hex container IDs and sha256:lower64hex image IDs.
//!
//! Fixed ownership labels (all required) are io.apex.runtime.installation-id,
//! workspace-id, namespace-id, proxy-id, revision-id, generation, fencing-token,
//! config-hash, runtime-manifest-hash, launch-context-hash and process-instance-id,
//! each under that same io.apex.runtime. prefix. Labels are comparisons, not
//! credentials. A future authenticated durable owner must supply the expectation.

use crate::{RuntimeError, check_runtime_target, inspect_decode, proto::RuntimeTarget, shapes};
use std::fmt;

/// Unverified data supplied to a pure comparison, not an authority credential.
/// There is intentionally no constructor from RPCs, Docker labels or defaults.
#[derive(Clone, PartialEq)]
pub struct RuntimeOwnershipInput {
    /// Canonical UUIDv7 of the separately authenticated durable installation.
    pub installation_id: String,
    /// Expected lower64hex engine container identifier.
    pub container_id: String,
    /// Expected sha256:lower64hex engine image identifier.
    pub image_id: String,
    /// Exact apex-runtime-<process-instance-UUIDv7>, without a leading slash.
    pub name: String,
    /// Unverified relation inputs; even a large fence is not lease authority.
    pub target: RuntimeTarget,
    /// Shaped published-config hash; equality does not establish integrity.
    pub config_hash: String,
    /// Shaped runtime-manifest hash, semantically separate from config_hash.
    pub runtime_manifest_hash: String,
    /// Shaped launch-context hash; this slice does not construct a launch.
    pub launch_context_hash: String,
    /// Canonical UUIDv7 process instance, distinct from container/image IDs.
    pub process_instance_id: String,
}

impl fmt::Debug for RuntimeOwnershipInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuntimeOwnershipInput { [unverified, redacted] }")
    }
}

/// Immutable snapshot of unverified comparison inputs; NOT a trusted brand.
/// Authenticated durable provenance and current lease must be checked elsewhere
/// before a future caller may act. Matching this snapshot cannot establish them.
#[derive(Clone)]
pub struct ExpectedRuntimeOwnership {
    identity: RuntimeOwnershipInput,
}

impl ExpectedRuntimeOwnership {
    /// Move raw inputs into a private immutable snapshot, without granting trust.
    /// `check_owned_inspect` must validate these fields before comparing inspect.
    pub fn from_unverified(identity: RuntimeOwnershipInput) -> Self {
        Self { identity }
    }
}

impl fmt::Debug for ExpectedRuntimeOwnership {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExpectedRuntimeOwnership { [unverified, redacted] }")
    }
}

/// Engine lifecycle only. Running is not application readiness or admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineState {
    /// Created, not started.
    Created,
    /// Engine reports running; no readiness inference is permitted.
    Running,
    /// Engine reports restarting.
    Restarting,
    /// Engine reports paused.
    Paused,
    /// Engine reports exited.
    Exited,
    /// Engine reports dead.
    Dead,
    /// Engine reports removing.
    Removing,
}

/// Only validated immutable identity and engine state; no serving-authority API.
pub struct InspectedRuntime {
    identity: RuntimeOwnershipInput,
    state: EngineState,
}

impl InspectedRuntime {
    /// Validated identity equality, not proof of the expectation's provenance.
    pub fn identity(&self) -> &RuntimeOwnershipInput {
        &self.identity
    }

    /// Engine state only, never ready/admitting/provisioned.
    pub fn state(&self) -> EngineState {
        self.state
    }
}

impl fmt::Debug for InspectedRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InspectedRuntime")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Extract only Id from exactly one inspect array element. Toy `sha256:abc` is
/// extractable but is NOT a production container ID or safe runtime handle.
///
/// # Errors
/// Refuses malformed, oversized, empty/multiple or duplicate-critical input.
pub fn parse_inspect_id(input: &str) -> Result<String, RuntimeError> {
    inspect_decode::extract_id(input)
}

/// Compare one supported projection object or one-element normal inspect array
/// with the supplied immutable expectation. A single Docker Name leading slash
/// is permitted; returned name is the expectation's exact unprefixed name.
///
/// # Errors
/// Refuses invalid expected data before decoding, malformed/bounded input,
/// mismatched identity/labels and unsupported engine states. No raw cause escapes.
pub fn check_owned_inspect(
    input: &str,
    expected: &ExpectedRuntimeOwnership,
) -> Result<InspectedRuntime, RuntimeError> {
    let identity = &expected.identity;
    check_expectation(identity)?;
    let observed = inspect_decode::projection(input)?;
    let name = observed
        .name
        .0
        .strip_prefix('/')
        .unwrap_or(&observed.name.0);
    if !shapes::hex_hash(&observed.id.0)
        || !shapes::image_id(&observed.image.0)
        || shapes::instance_name(name).is_none()
    {
        return Err(RuntimeError::InvalidInspect);
    }
    // Exact equality to already-shaped expected values enforces label shape,
    // including canonical u64 decimal text, without parsing through a float.
    let generation = identity.target.generation.to_string();
    let fence = identity.target.fencing_token.to_string();
    if observed.id.0 != identity.container_id
        || observed.image.0 != identity.image_id
        || name != identity.name
        || !observed.config.0.labels.matches(&[
            &identity.installation_id,
            &identity.target.workspace_id,
            &identity.target.namespace_id,
            &identity.target.proxy_id,
            &identity.target.revision_id,
            &generation,
            &fence,
            &identity.config_hash,
            &identity.runtime_manifest_hash,
            &identity.launch_context_hash,
            &identity.process_instance_id,
        ])
    {
        return Err(RuntimeError::OwnershipMismatch);
    }
    let state = match observed.state.0.status.0.as_str() {
        "created" => EngineState::Created,
        "running" => EngineState::Running,
        "restarting" => EngineState::Restarting,
        "paused" => EngineState::Paused,
        "exited" => EngineState::Exited,
        "dead" => EngineState::Dead,
        "removing" => EngineState::Removing,
        _ => return Err(RuntimeError::UnsupportedState),
    };
    Ok(InspectedRuntime {
        identity: identity.clone(),
        state,
    })
}

fn check_expectation(value: &RuntimeOwnershipInput) -> Result<(), RuntimeError> {
    if check_runtime_target(&value.target).is_ok()
        && shapes::uuid_v7(&value.installation_id)
        && shapes::uuid_v7(&value.process_instance_id)
        && shapes::hex_hash(&value.container_id)
        && shapes::image_id(&value.image_id)
        && shapes::instance_name(&value.name) == Some(value.process_instance_id.as_str())
        && shapes::hex_hash(&value.config_hash)
        && shapes::hex_hash(&value.runtime_manifest_hash)
        && shapes::hex_hash(&value.launch_context_hash)
    {
        Ok(())
    } else {
        Err(RuntimeError::InvalidExpectedOwnership)
    }
}
