//! Synchronous confined staging boundary for a later bounded blocking owner.
//!
//! A staged runtime describes files only, never a current-operation or launch permit.
//! The caller selects a canonical UUIDv7 before constructing launch bytes and
//! must verify publication, manifest/launch binding and the current operation.
//! Revision and launch bytes are bounded opaque inputs at this IO boundary.
//!
//! Production filesystem effects are Linux-only. Host root/service operators
//! must protect both directory hierarchies throughout their lifetime. Failure
//! may leave an owned quarantined staging directory; this API must never clean
//! externally supplied paths. Dropping a staged value must not delete live mounts.
//! The deployment owner must preserve the returned pathname until mount/use;
//! descriptor confinement alone cannot stop a trusted operator renaming it later.
#![forbid(unsafe_code)]

use crate::proto;
use std::{
    fmt,
    path::{Path, PathBuf},
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod roots;
#[cfg(target_os = "linux")]
mod validation;

/// Deployment-owned material metadata, resolved only in its exact target scope.
#[derive(Clone)]
pub struct ScopedMaterial {
    pub workspace_id: String,
    pub namespace_id: String,
    pub proxy_id: String,
    pub reference: String,
    pub version: String,
    pub role: proto::RuntimeMaterialRole,
    pub source_name: String,
}

impl fmt::Debug for ScopedMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopedMaterial { .. }")
    }
}

/// Static refusal codes: no input formatting, secret bytes or source errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StagingError {
    Unsupported,
    InvalidRoot,
    InvalidTarget,
    InvalidInput,
    ScopeMismatch,
    InvalidSource,
    AlreadyExists,
    Io,
}

impl fmt::Display for StagingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "staging platform unsupported",
            Self::InvalidRoot => "invalid staging root",
            Self::InvalidTarget => "invalid staging target",
            Self::InvalidInput => "invalid staging input",
            Self::ScopeMismatch => "staging scope mismatch",
            Self::InvalidSource => "invalid staging source",
            Self::AlreadyExists => "staging instance already exists",
            Self::Io => "staging IO refused",
        })
    }
}

impl std::error::Error for StagingError {}

/// Holds trusted state/source roots; cannot be publicly constructed.
pub struct StagingOwner {
    #[cfg(target_os = "linux")]
    inner: linux::Owner,
    #[cfg(not(target_os = "linux"))]
    _private: (),
}

impl fmt::Debug for StagingOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StagingOwner { .. }")
    }
}

impl StagingOwner {
    /// Open existing absolute trusted roots without following symlinks.
    ///
    /// # Errors
    /// Refuses unsupported platforms/UIDs, unsafe roots, or overlapping roots.
    pub fn open(state_root: &Path, source_root: &Path) -> Result<Self, StagingError> {
        #[cfg(target_os = "linux")]
        {
            linux::Owner::open(state_root, source_root).map(|inner| Self { inner })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (state_root, source_root);
            Err(StagingError::Unsupported)
        }
    }

    /// Stage opaque owner bytes and exact-scoped material at the caller's UUIDv7.
    /// The caller must bind this same instance ID into trusted launch bytes.
    /// Never call this synchronous boundary on a Tokio worker.
    ///
    /// # Errors
    /// Refuses invalid metadata/material, source IO violations, existing instance
    /// paths, or failed writes/sealing. An IO failure may leave a quarantined
    /// owned directory. No cleanup of supplied paths is attempted.
    pub fn stage(
        &self,
        target: &proto::RuntimeTarget,
        instance_id: &str,
        revision_json: &[u8],
        launch_json: &[u8],
        materials: &[ScopedMaterial],
    ) -> Result<StagedRuntime, StagingError> {
        #[cfg(target_os = "linux")]
        {
            self.inner
                .stage(target, instance_id, revision_json, launch_json, materials)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (target, instance_id, revision_json, launch_json, materials);
            Err(StagingError::Unsupported)
        }
    }
}

/// Trusted staging location, not an execution permit. No deletion on drop.
pub struct StagedRuntime {
    directory: PathBuf,
    instance_id: String,
}

impl StagedRuntime {
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }
}

impl fmt::Debug for StagedRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StagedRuntime { .. }")
    }
}
