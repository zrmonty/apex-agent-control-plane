use super::Journal;
use crate::{
    execution::{
        metadata::strict::Object,
        network::{Binding, hash, owner_hash},
        record::Installed,
    },
    network_catalog::NetworkCatalog,
    shapes,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
mod disk;
const ERROR: &str = "RUNTIME_NETWORK_RESERVATION_REFUSED";
#[derive(Default)]
pub(super) struct State {
    loaded: bool,
    poisoned: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u32,
    installation: String,
    layout_hash: String,
    capacity: u16,
    entries: Vec<Object<Entry>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    instance: String,
    owner_hash: String,
    slot: u16,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    document: Object<Document>,
    digest: String,
}
impl State {
    fn load(&mut self, root: &crate::config::Directory) -> Result<Option<Document>, &'static str> {
        if self.poisoned {
            return Err(ERROR);
        }
        match disk::load(root) {
            Ok(Some(d)) => {
                self.loaded = true;
                Ok(Some(d))
            }
            Ok(None) if !self.loaded => Ok(None),
            _ => {
                self.poisoned = true;
                Err(ERROR)
            }
        }
    }
}
impl Journal {
    pub(in crate::execution) fn network_entries(
        &self,
        installation: &str,
    ) -> Result<Vec<(String, Binding)>, &'static str> {
        let mut state = self.network_lock.lock().map_err(|_| ERROR)?;
        let Some(d) = state.load(&self.root)? else {
            return Ok(vec![]);
        };
        if d.installation != installation {
            return Err(ERROR);
        }
        d.entries
            .iter()
            .map(|Object(e)| {
                Ok((
                    e.instance.clone(),
                    Binding::new(
                        installation,
                        &e.instance,
                        e.slot,
                        d.layout_hash.clone(),
                        e.owner_hash.clone(),
                    )?,
                ))
            })
            .collect()
    }
    // Read-only, catalog-independent fence. A global commit can precede the
    // per-proxy attachment; disabling the opt-in must not erase that history.
    pub(in crate::execution) fn network_reserved(
        &self,
        installation: &str,
        installed: &Installed,
    ) -> Result<bool, &'static str> {
        self.topology_history(installation)?;
        let mut state = self.network_lock.lock().map_err(|_| ERROR)?;
        let document = state.load(&self.root)?;
        let Some(d) = document else {
            return if installed.network.is_none() {
                Ok(false)
            } else {
                Err(ERROR)
            };
        };
        if d.installation != installation {
            return Err(ERROR);
        }
        let entry = d
            .entries
            .iter()
            .find(|Object(e)| e.instance == installed.instance);
        let Some(Object(e)) = entry else {
            return if installed.network.is_none() {
                Ok(false)
            } else {
                Err(ERROR)
            };
        };
        if e.owner_hash != owner_hash(installed)? {
            return Err(ERROR);
        }
        let binding = Binding::new(
            installation,
            &installed.instance,
            e.slot,
            d.layout_hash,
            e.owner_hash.clone(),
        )?;
        if installed.network.as_ref().is_some_and(|b| b != &binding) {
            return Err(ERROR);
        }
        Ok(true)
    }
    pub(in crate::execution) fn reserve_network(
        &self,
        catalog: &NetworkCatalog,
        installation: &str,
        installed: &Installed,
    ) -> Result<Binding, &'static str> {
        if installation != catalog.installation_id() {
            return Err(ERROR);
        }
        let owner_hash = owner_hash(installed)?;
        let outer = catalog.outer();
        let layout_hash = hash(&(
            catalog.installation_id(),
            catalog.internal_pool(),
            catalog.capacity(),
            outer.network_id(),
            outer.subnet(),
            outer.gateway(),
            outer.edge_address(),
        ))?;
        let mut state = self.network_lock.lock().map_err(|_| ERROR)?;
        let mut document = match state.load(&self.root)? {
            Some(d) => d,
            None => Document {
                schema_version: 1,
                installation: installation.into(),
                layout_hash: layout_hash.clone(),
                capacity: catalog.capacity(),
                entries: vec![],
            },
        };
        if document.installation != installation
            || document.layout_hash != layout_hash
            || document.capacity != catalog.capacity()
        {
            return Err(ERROR);
        }
        if let Some(Object(entry)) = document
            .entries
            .iter()
            .find(|Object(e)| e.instance == installed.instance)
        {
            if entry.owner_hash != owner_hash {
                return Err(ERROR);
            }
            return Binding::new(
                installation,
                &installed.instance,
                entry.slot,
                layout_hash,
                owner_hash,
            );
        }
        let slot = (0..document.capacity)
            .find(|n| document.entries.iter().all(|Object(e)| e.slot != *n))
            .ok_or(ERROR)?;
        let result = Binding::new(
            installation,
            &installed.instance,
            slot,
            layout_hash,
            owner_hash.clone(),
        )?;
        document.entries.push(Object(Entry {
            instance: installed.instance.clone(),
            owner_hash,
            slot,
        }));
        document
            .entries
            .sort_by(|a, b| a.0.instance.cmp(&b.0.instance));
        if disk::save(&self.root, &document).is_err() {
            state.poisoned = true;
            return Err(ERROR);
        }
        state.loaded = true;
        Ok(result)
    }
}
fn validate(d: &Document) -> Result<(), &'static str> {
    if d.schema_version != 1
        || !shapes::uuid_v7(&d.installation)
        || !shapes::hex_hash(&d.layout_hash)
        || !(1..=128).contains(&d.capacity)
        || d.entries.len() > usize::from(d.capacity)
    {
        return Err(ERROR);
    }
    let mut ids = BTreeSet::new();
    let mut slots = BTreeSet::new();
    for Object(e) in &d.entries {
        if !shapes::uuid_v7(&e.instance)
            || !shapes::hex_hash(&e.owner_hash)
            || e.slot >= d.capacity
            || !ids.insert(&e.instance)
            || !slots.insert(e.slot)
        {
            return Err(ERROR);
        }
    }
    if !d
        .entries
        .windows(2)
        .all(|p| p[0].0.instance < p[1].0.instance)
    {
        return Err(ERROR);
    }
    Ok(())
}
#[cfg(test)]
mod tests;
