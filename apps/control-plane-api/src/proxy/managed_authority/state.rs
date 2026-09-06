//! One refresh publication, with original read-start age and explicit revocation.
use super::{Refused, profile::Profile};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub(super) struct Selection {
    pub profile: Arc<Profile>,
    serial: u64,
}
pub(super) struct State {
    active: Option<(Arc<Selection>, Instant)>,
    last: Option<(String, [u8; 32])>,
    serial: u64,
}
impl State {
    pub(super) fn new() -> Self {
        Self {
            active: None,
            last: None,
            serial: 0,
        }
    }
    pub(super) fn publish(
        &mut self,
        bytes: &[u8],
        started: Instant,
        now: Instant,
    ) -> Result<(), Refused> {
        let result = self.publish_checked(bytes, started, now);
        if result.is_err() {
            self.disable();
        }
        result
    }
    fn publish_checked(
        &mut self,
        bytes: &[u8],
        started: Instant,
        now: Instant,
    ) -> Result<(), Refused> {
        fresh(started, now)?;
        let profile = Profile::parse(bytes)?;
        let content: [u8; 32] = Sha256::digest(bytes).into();
        if self
            .last
            .as_ref()
            .is_some_and(|(version, previous)| version == &profile.version && previous != &content)
        {
            return Err(Refused);
        }
        if let Some((_, previous_start)) = &mut self.active {
            if started < *previous_start {
                return Err(Refused);
            }
            if self.last.as_ref().is_some_and(|(version, previous)| {
                version == &profile.version && previous == &content
            }) {
                *previous_start = started;
                return Ok(());
            }
        }
        let serial = self.serial.checked_add(1).ok_or(Refused)?;
        self.last = Some((profile.version.clone(), content));
        self.active = Some((
            Arc::new(Selection {
                profile: Arc::new(profile),
                serial,
            }),
            started,
        ));
        self.serial = serial;
        Ok(())
    }
    pub(super) fn disable(&mut self) {
        self.active = None;
    }
    pub(super) fn current(&self, now: Instant) -> Result<Arc<Selection>, Refused> {
        let (selected, started) = self.active.as_ref().ok_or(Refused)?;
        fresh(*started, now)?;
        Ok(Arc::clone(selected))
    }
    pub(super) fn recheck(&self, selected: &Selection, now: Instant) -> Result<(), Refused> {
        if self.current(now)?.serial != selected.serial {
            return Err(Refused);
        }
        Ok(())
    }
}
fn fresh(started: Instant, now: Instant) -> Result<(), Refused> {
    if now
        .checked_duration_since(started)
        .is_none_or(|age| age >= Duration::from_secs(5))
    {
        return Err(Refused);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn document(version: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"schema_version":1,"version":version,
            "valid_from_unix_us":"1","expires_at_unix_us":"9223372036854775807","profiles":[]}))
        .unwrap()
    }
    #[test]
    fn invalid_refresh_revokes_previously_borrowed_state_without_last_good_fallback() {
        let mut state = State::new();
        let now = Instant::now();
        state.publish(&document("v1"), now, now).unwrap();
        let old = state.current(now).unwrap();
        assert!(state.publish(b"invalid", now, now).is_err());
        assert!(state.current(now).is_err());
        assert!(state.recheck(&old, now).is_err());
        state.publish(&document("v1"), now, now).unwrap();
        assert!(state.current(now).is_ok());
        assert!(state.recheck(&old, now).is_err());
    }
    #[test]
    fn freshness_starts_before_read_and_same_bytes_do_not_replace_inflight_selection() {
        let mut state = State::new();
        let now = Instant::now();
        state.publish(&document("v1"), now, now).unwrap();
        let old = state.current(now).unwrap();
        assert!(state.current(now + Duration::from_secs(5)).is_err());
        state
            .publish(
                &document("v1"),
                now + Duration::from_secs(1),
                now + Duration::from_secs(1),
            )
            .unwrap();
        state.recheck(&old, now + Duration::from_secs(5)).unwrap();
        assert!(
            state
                .publish(&document("v1"), now, now + Duration::from_secs(5))
                .is_err()
        );
        assert!(state.recheck(&old, now).is_err());
        assert!(
            state
                .publish(&document("v1"), now + Duration::from_secs(1), now)
                .is_err()
        );
    }
    #[test]
    fn changed_version_replaces_snapshot_but_same_version_changed_bytes_poison() {
        let mut state = State::new();
        let now = Instant::now();
        state.publish(&document("v1"), now, now).unwrap();
        let old = state.current(now).unwrap();
        let mut changed = document("v1");
        changed.push(b' ');
        assert!(state.publish(&changed, now, now).is_err());
        assert!(state.recheck(&old, now).is_err());
        state.publish(&document("v2"), now, now).unwrap();
        assert_eq!(state.current(now).unwrap().profile.version, "v2");
    }
}
