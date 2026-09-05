//! Private paired generation/freshness state, not TLS or wall-time authority.
//! Local generation/content checks never prove global rollback or delivery.

use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use apex_auth::RuntimePeerPolicy;
use sha2::{Digest, Sha256};

use super::{RuntimeAuthorityError, enrollment::Enrollment};

pub(super) struct PolicyState {
    active: Option<CurrentPair>,
    last_peer: Option<VersionContent>,
    last_enrollment: Option<VersionContent>,
    serial: u64,
}

struct CurrentPair {
    selected: Arc<SelectedPolicy>,
    read_started: Instant,
}

struct VersionContent {
    version: String,
    digest: [u8; 32],
}

pub(super) struct SelectedPolicy {
    pub generation: u64,
    pub peer: RuntimePeerPolicy,
    pub enrollment: Enrollment,
}

impl PolicyState {
    pub(super) fn new() -> Self {
        Self {
            active: None,
            last_peer: None,
            last_enrollment: None,
            serial: 0,
        }
    }

    pub(super) fn publish(
        &mut self,
        peer_bytes: &[u8],
        enrollment_bytes: &[u8],
        read_started: Instant,
        now: Instant,
    ) -> Result<(), RuntimeAuthorityError> {
        let result = self.publish_checked(peer_bytes, enrollment_bytes, read_started, now);
        if result.is_err() {
            self.disable();
        }
        result
    }

    fn publish_checked(
        &mut self,
        peer_bytes: &[u8],
        enrollment_bytes: &[u8],
        read_started: Instant,
        now: Instant,
    ) -> Result<(), RuntimeAuthorityError> {
        fresh(read_started, now)?;
        let peer = RuntimePeerPolicy::parse_json(peer_bytes)
            .map_err(|_| RuntimeAuthorityError::Unavailable)?;
        let enrollment = Enrollment::parse_json(enrollment_bytes)?;
        if enrollment.peer_policy_version() != peer.version() {
            return Err(RuntimeAuthorityError::Unavailable);
        }
        let peer_content = VersionContent::new(peer.version(), peer_bytes);
        let enrollment_content = VersionContent::new(enrollment.version(), enrollment_bytes);
        peer_content.check_immutable(self.last_peer.as_ref())?;
        enrollment_content.check_immutable(self.last_enrollment.as_ref())?;
        if let Some(active) = &mut self.active {
            if read_started < active.read_started {
                return Err(RuntimeAuthorityError::Unavailable);
            }
            if self
                .last_peer
                .as_ref()
                .is_some_and(|last| last.same(&peer_content))
                && self
                    .last_enrollment
                    .as_ref()
                    .is_some_and(|last| last.same(&enrollment_content))
            {
                // Identical rereads refresh age, never replace the in-flight pair.
                active.read_started = read_started;
                return Ok(());
            }
        }
        let generation = self
            .serial
            .checked_add(1)
            .ok_or(RuntimeAuthorityError::Unavailable)?;
        self.active = Some(CurrentPair {
            selected: Arc::new(SelectedPolicy {
                generation,
                peer,
                enrollment,
            }),
            read_started,
        });
        self.serial = generation;
        self.last_peer = Some(peer_content);
        self.last_enrollment = Some(enrollment_content);
        Ok(())
    }

    pub(super) fn current(
        &self,
        now: Instant,
    ) -> Result<Arc<SelectedPolicy>, RuntimeAuthorityError> {
        let current = self
            .active
            .as_ref()
            .ok_or(RuntimeAuthorityError::Unavailable)?;
        fresh(current.read_started, now)?;
        Ok(Arc::clone(&current.selected))
    }

    pub(super) fn recheck(
        &self,
        selected: &SelectedPolicy,
        now: Instant,
    ) -> Result<(), RuntimeAuthorityError> {
        let current = self
            .active
            .as_ref()
            .ok_or(RuntimeAuthorityError::PolicyChanged)?;
        if current.selected.generation != selected.generation {
            return Err(RuntimeAuthorityError::PolicyChanged);
        }
        fresh(current.read_started, now)
    }

    pub(super) fn disable(&mut self) {
        // Retain only the last accepted version/content for EACH document.
        // Recovery gets a new generation even when those bytes are identical.
        self.active = None;
    }
}

impl VersionContent {
    fn new(version: &str, bytes: &[u8]) -> Self {
        Self {
            version: version.to_owned(),
            digest: Sha256::digest(bytes).into(),
        }
    }

    fn same(&self, other: &Self) -> bool {
        self.version == other.version && self.digest == other.digest
    }

    fn check_immutable(&self, previous: Option<&Self>) -> Result<(), RuntimeAuthorityError> {
        if previous.is_some_and(|old| self.version == old.version && self.digest != old.digest) {
            return Err(RuntimeAuthorityError::Unavailable);
        }
        Ok(())
    }
}

fn fresh(read_started: Instant, now: Instant) -> Result<(), RuntimeAuthorityError> {
    if now
        .checked_duration_since(read_started)
        .is_none_or(|age| age >= Duration::from_secs(2))
    {
        return Err(RuntimeAuthorityError::Unavailable);
    }
    Ok(())
}

impl fmt::Debug for SelectedPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SelectedPolicy { [redacted] }")
    }
}
