//! Physical proxy ownership: health may coexist with read-only network inspection.
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

pub(super) enum Kind {
    Reconcile,
    Network,
    Health,
}
pub(super) struct Guard {
    active: Arc<Mutex<BTreeSet<String>>>,
    key: String,
}
impl Guard {
    pub(super) fn acquire(
        active: &Arc<Mutex<BTreeSet<String>>>,
        key: String,
        kind: Kind,
    ) -> Result<Self, &'static str> {
        let mut state = active.lock().map_err(|_| "RUNTIME_WORKER_UNAVAILABLE")?;
        // Ordinary ownership is shared by reconciliation and network reads.
        // Health starts only between those operations, but a later NETWORK read
        // must remain possible while the fixed health process calls the gateway.
        let health_key = format!("health:{key}");
        if state.contains(&key)
            || (matches!(kind, Kind::Reconcile | Kind::Health) && state.contains(&health_key))
            || (matches!(kind, Kind::Health)
                && state.iter().filter(|k| k.starts_with("health:")).count() >= 2)
        {
            return Err("RUNTIME_PROXY_BUSY");
        }
        let key = if matches!(kind, Kind::Health) {
            health_key
        } else {
            key
        };
        state.insert(key.clone());
        Ok(Self {
            active: Arc::clone(active),
            key,
        })
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active.lock() {
            active.remove(&self.key);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn health_allows_network_but_excludes_mutation_and_duplicate_probe_until_owner_drops() {
        let active = Arc::default();
        let health = Guard::acquire(&active, "proxy-a".into(), Kind::Health).unwrap();
        assert!(Guard::acquire(&active, "proxy-a".into(), Kind::Health).is_err());
        assert!(Guard::acquire(&active, "proxy-a".into(), Kind::Reconcile).is_err());
        let network = Guard::acquire(&active, "proxy-a".into(), Kind::Network).unwrap();
        drop(health);
        assert!(Guard::acquire(&active, "proxy-a".into(), Kind::Reconcile).is_err());
        drop(network);
        let exclusive = Guard::acquire(&active, "proxy-a".into(), Kind::Reconcile).unwrap();
        assert!(Guard::acquire(&active, "proxy-a".into(), Kind::Network).is_err());
        assert!(Guard::acquire(&active, "proxy-a".into(), Kind::Health).is_err());
        drop(exclusive);
        assert!(active.lock().unwrap().is_empty());
    }
    #[test]
    fn two_health_owners_leave_six_physical_workers_for_network_and_other_proxies() {
        let active = Arc::default();
        let a = Guard::acquire(&active, "a".into(), Kind::Health).unwrap();
        let b = Guard::acquire(&active, "b".into(), Kind::Health).unwrap();
        assert!(Guard::acquire(&active, "c".into(), Kind::Health).is_err());
        let n = Guard::acquire(&active, "a".into(), Kind::Network).unwrap();
        let r = Guard::acquire(&active, "other".into(), Kind::Reconcile).unwrap();
        drop(a);
        let c = Guard::acquire(&active, "c".into(), Kind::Health).unwrap();
        drop((b, n, r, c));
        assert!(active.lock().unwrap().is_empty());
    }
}
