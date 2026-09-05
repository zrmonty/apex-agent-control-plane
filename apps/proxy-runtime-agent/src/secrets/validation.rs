//! Pure bounded checks, completed for the entire request before any source read.

use super::{ScopedMaterial, StagingError};
use crate::{
    check_runtime_target,
    proto::{RuntimeMaterialRole as Role, RuntimeTarget},
    shapes,
};

pub(super) fn request(
    target: &RuntimeTarget,
    instance_id: &str,
    revision: &[u8],
    launch: &[u8],
    materials: &[ScopedMaterial],
) -> Result<(), StagingError> {
    check_runtime_target(target).map_err(|_| StagingError::InvalidTarget)?;
    if i64::try_from(target.generation).is_err() || i64::try_from(target.fencing_token).is_err() {
        return Err(StagingError::InvalidTarget);
    }
    if !shapes::uuid_v7(instance_id)
        || !(1..=262_144).contains(&revision.len())
        || !(1..=16_384).contains(&launch.len())
        || !(1..=13).contains(&materials.len())
    {
        return Err(StagingError::InvalidInput);
    }
    // Deployment scope is independent of reference spelling, which grants no
    // authority. Check every entry before resolving even the first source file.
    for material in materials {
        if material.workspace_id != target.workspace_id
            || material.namespace_id != target.namespace_id
            || material.proxy_id != target.proxy_id
        {
            return Err(StagingError::ScopeMismatch);
        }
    }
    let mut health = false;
    for (index, material) in materials.iter().enumerate() {
        filename(material.role)?;
        if !source_name(&material.source_name)
            || !reference(&material.reference)
            || material.version.len() > 128
            || !shapes::scope(&material.version)
            || materials[..index].iter().any(|previous| {
                previous.role == material.role || previous.reference == material.reference
            })
        {
            return Err(StagingError::InvalidInput);
        }
        health |= material.role == Role::HealthToken;
    }
    if !health {
        return Err(StagingError::InvalidInput);
    }
    Ok(())
}

fn source_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn reference(value: &str) -> bool {
    if value.len() > 256 {
        return false;
    }
    if let Some(parts) = value.strip_prefix("secret://") {
        parts
            .split('/')
            .all(|part| part != "." && shapes::scope(part))
    } else {
        shapes::scope(value)
    }
}

pub(super) fn filename(role: Role) -> Result<&'static str, StagingError> {
    Ok(match role {
        Role::Unspecified => return Err(StagingError::InvalidInput),
        Role::HealthToken => "health-token",
        Role::GovernanceCa => "governance-ca",
        Role::GovernanceCert => "governance-cert",
        Role::GovernanceKey => "governance-key",
        Role::GovernanceToken => "governance-token",
        Role::EvidenceCa => "evidence-ca",
        Role::EvidenceCert => "evidence-cert",
        Role::EvidenceKey => "evidence-key",
        Role::EvidenceToken => "evidence-token",
        Role::InboundJwks => "inbound-jwks",
        Role::WorkloadCa => "workload-ca",
        Role::WorkloadCert => "workload-cert",
        Role::WorkloadKey => "workload-key",
    })
}

pub(super) fn health_token(bytes: &[u8]) -> bool {
    bytes.len() == 43
        && bytes.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        // A 32-byte token leaves two unused bits in the final base64 sextet.
        // Only these characters encode a sextet whose low two bits are zero.
        && matches!(bytes[42], b'A' | b'E' | b'I' | b'M' | b'Q' | b'U' | b'Y'
            | b'c' | b'g' | b'k' | b'o' | b's' | b'w' | b'0' | b'4' | b'8')
}
