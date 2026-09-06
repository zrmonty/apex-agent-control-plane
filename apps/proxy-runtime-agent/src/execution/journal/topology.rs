//! Separate protected effect history; no legacy checksum or phase changes.
use super::Journal;
use crate::execution::network_owner::{
    ERROR,
    topology::{Document, Phase},
};
use std::collections::{BTreeMap, BTreeSet};
mod disk;
#[cfg(test)]
mod tests;
#[derive(Default)]
pub(super) struct State {
    seen: BTreeSet<String>,
    poisoned: bool,
}
impl Journal {
    #[cfg(test)]
    pub(in crate::execution) fn fixture_lost_network_observation(
        &self,
        installation: &str,
        target: &crate::proto::RuntimeTarget,
    ) {
        let r = self.load(installation, target).unwrap().unwrap();
        let mut all = self.topology_history(installation).unwrap();
        let d = all.get_mut(&r.instance).unwrap();
        assert!(d.phase == Phase::Observed);
        d.phase = Phase::CreateIntent;
        d.observation = None;
        disk::save(
            &self.root,
            &format!("network-topology-{}.json", r.instance),
            d,
        )
        .unwrap();
    }
    pub(in crate::execution) fn topology_history(
        &self,
        installation: &str,
    ) -> Result<BTreeMap<String, Document>, &'static str> {
        // Serialize the index snapshot with the sidecar scan, in the writer's
        // topology -> network lock order. Otherwise a valid new sidecar can be
        // joined against an older index and falsely poison this owner.
        let mut state = self.topology_lock.lock().map_err(|_| ERROR)?;
        // A caller scope conflict is not corruption. The global reader retains
        // its own poison on uncertain storage before this scope check returns.
        let entries = self.network_entries(installation)?;
        #[cfg(test)]
        tests::concurrency::after_entries();
        if state.poisoned {
            return Err(ERROR);
        }
        let result = self.read_topologies(installation, &entries, &mut state);
        if result.is_err() {
            state.poisoned = true;
        }
        result
    }
    fn read_topologies(
        &self,
        installation: &str,
        entries: &[(String, crate::execution::network::Binding)],
        state: &mut State,
    ) -> Result<BTreeMap<String, Document>, &'static str> {
        self.root.check()?;
        let mut documents = BTreeMap::new();
        let mut count = 0;
        for entry in rustix::fs::Dir::read_from(&self.root.fd).map_err(|_| ERROR)? {
            let entry = entry.map_err(|_| ERROR)?;
            count += 1;
            if count > 4096 {
                return Err(ERROR);
            }
            let name = entry.file_name().to_str().map_err(|_| ERROR)?;
            if !name.starts_with("network-topology-") {
                continue;
            }
            let id = name
                .strip_prefix("network-topology-")
                .and_then(|s| s.strip_suffix(".json"))
                .ok_or(ERROR)?;
            if !crate::shapes::uuid_v7(id) || documents.len() >= 128 {
                return Err(ERROR);
            }
            let binding = &entries
                .iter()
                .find(|(instance, _)| instance == id)
                .ok_or(ERROR)?
                .1;
            let d = disk::load(&self.root, name)?.ok_or(ERROR)?;
            let t = &d.topology.0;
            if t.instance != id || t.installation != installation || &t.binding.0 != binding {
                return Err(ERROR);
            }
            let r = self
                .load(installation, t.original.0.target.as_ref().ok_or(ERROR)?)?
                .ok_or(ERROR)?;
            let i = [&r.installed, &r.predecessor]
                .into_iter()
                .flatten()
                .find(|i| i.instance == id)
                .ok_or(ERROR)?;
            t.validate(i)?;
            if i.network.as_ref() != Some(binding) {
                return Err(ERROR);
            }
            documents.insert(id.into(), d);
        }
        if state.seen.iter().any(|id| !documents.contains_key(id)) {
            return Err(ERROR);
        }
        state.seen.extend(documents.keys().cloned());
        self.root.check()?;
        Ok(documents)
    }
    pub(in crate::execution) fn prepare_topology(&self, d: &Document) -> Result<(), &'static str> {
        if d.phase != Phase::Prepared {
            return Err(ERROR);
        }
        self.write_topology(d, None)
    }
    pub(in crate::execution) fn transition_topology(
        &self,
        previous: &Document,
        next: &Document,
    ) -> Result<(), &'static str> {
        if previous.topology_hash != next.topology_hash
            || !matches!(
                (previous.phase, next.phase),
                (Phase::Prepared, Phase::CreateIntent)
                    | (Phase::CreateIntent, Phase::Prepared)
                    | (Phase::CreateIntent, Phase::Observed)
            )
        {
            return Err(ERROR);
        }
        self.write_topology(next, Some(previous))
    }
    fn write_topology(
        &self,
        d: &Document,
        previous: Option<&Document>,
    ) -> Result<(), &'static str> {
        let mut state = self.topology_lock.lock().map_err(|_| ERROR)?;
        if state.poisoned {
            return Err(ERROR);
        }
        let result = (|| {
            let entries = self.network_entries(&d.topology.0.installation)?;
            let all = self.read_topologies(&d.topology.0.installation, &entries, &mut state)?;
            let old = all.get(&d.topology.0.instance);
            if old.map(crate::execution::network::hash).transpose()?
                != previous.map(crate::execution::network::hash).transpose()?
            {
                return Err(ERROR);
            }
            let t = &d.topology.0;
            let entries = self.network_entries(&t.installation)?;
            if !entries
                .iter()
                .any(|(id, b)| id == &t.instance && b == &t.binding.0)
            {
                return Err(ERROR);
            }
            let r = self
                .load(&t.installation, t.original.0.target.as_ref().ok_or(ERROR)?)?
                .ok_or(ERROR)?;
            let i = [&r.installed, &r.predecessor]
                .into_iter()
                .flatten()
                .find(|i| i.instance == t.instance)
                .ok_or(ERROR)?;
            t.validate(i)?;
            disk::save(
                &self.root,
                &format!("network-topology-{}.json", t.instance),
                d,
            )?;
            state.seen.insert(t.instance.clone());
            Ok(())
        })();
        if result.is_err() {
            state.poisoned = true;
        }
        result
    }
}
