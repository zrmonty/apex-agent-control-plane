//! Docker network inspect omits stopped configurations. Join the bounded container inventory too.
use super::*;
use crate::execution::{
    journal::Journal,
    network_owner::topology::{Document, Topology},
};
use std::collections::BTreeSet;
impl Engine {
    pub(in crate::execution) fn pair_memberships(
        &self,
        journal: &Journal,
        t: &Topology,
        history: &BTreeMap<String, Document>,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<String, &'static str> {
        self.pair_inventory(journal, t, history, deadline, cancel)
            .map(|(_, outer)| outer)
    }
    pub(in crate::execution) fn pair_inventory(
        &self,
        journal: &Journal,
        t: &Topology,
        history: &BTreeMap<String, Document>,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<(super::super::network::Inventory, String), &'static str> {
        let networks = self.network_inventory(deadline, cancel)?;
        let outer = networks.outer_candidate(t)?;
        let mut owners = BTreeMap::new();
        for (instance, d) in history {
            let r = journal
                .load(
                    &t.installation,
                    d.topology.0.original.0.target.as_ref().ok_or(ERROR)?,
                )?
                .ok_or(ERROR)?;
            let i = [r.installed, r.predecessor]
                .into_iter()
                .flatten()
                .find(|i| &i.instance == instance)
                .ok_or(ERROR)?;
            owners.insert(instance.clone(), i);
        }
        let bytes = self.run(
            vec![
                "container".into(),
                "ls".into(),
                "--all".into(),
                "--quiet".into(),
                "--no-trunc".into(),
            ],
            deadline,
            cancel,
        )?;
        let mut ids = BTreeSet::new();
        for id in std::str::from_utf8(&bytes)
            .map_err(|_| ERROR)?
            .split_whitespace()
        {
            if !shapes::hex_hash(id) || ids.len() >= 1024 || !ids.insert(id.to_owned()) {
                return Err(ERROR);
            }
        }
        let catalog = t.catalog()?;
        let reserved: BTreeSet<_> = (0..catalog.capacity())
            .map(|slot| {
                catalog
                    .candidate_addresses(slot)
                    .map(|a| a.guard_outer.to_string())
            })
            .collect::<Result<_, _>>()?;
        let mut found = BTreeSet::new();
        let mut running = Vec::new();
        for (id, bytes) in self.inspect_many(
            super::super::network_inspection_batch::Kind::Container,
            ids,
            deadline,
            cancel,
        )? {
            let parsed = super::super::inspect::Json::parse(&bytes)?;
            let v = &parsed.0.as_array().filter(|a| a.len() == 1).ok_or(ERROR)?[0];
            if v["Id"] != id {
                return Err(ERROR);
            }
            let name = v["Name"]
                .as_str()
                .and_then(|s| s.strip_prefix('/'))
                .ok_or(ERROR)?;
            let mut matched = false;
            for i in owners.values() {
                for role in [Role::Gateway, Role::Guard] {
                    let p = i.paired_containers.as_ref();
                    if name != role.name(i) && p.is_none_or(|p| role.id(p) != id) {
                        continue;
                    }
                    let p = p.ok_or(ERROR)?;
                    if p.phase == Phase::Prepared
                        || (role == Role::Guard
                            && matches!(p.phase, Phase::GatewayIntent | Phase::GatewayObserved))
                    {
                        return Err(ERROR);
                    }
                    let connected = role == Role::Guard
                        && match p.phase {
                            Phase::Verified => true,
                            Phase::ConnectIntent => v["NetworkSettings"]["Networks"]
                                .as_object()
                                .is_some_and(|n| n.len() == 2),
                            _ => false,
                        };
                    inspect::check(
                        &bytes,
                        &t.installation,
                        i,
                        role,
                        &self.paths.staging_root.join(role.name(i)),
                        &outer,
                        connected,
                    )?;
                    if v["State"]["Running"] == true {
                        running.push(v.clone());
                    }
                    if !found.insert((i.instance.clone(), role == Role::Guard)) {
                        return Err(ERROR);
                    }
                    matched = true;
                }
            }
            if matched {
                continue;
            }
            let configured = v["NetworkSettings"]["Networks"].as_object().ok_or(ERROR)?;
            let mode = v["HostConfig"]["NetworkMode"].as_str().ok_or(ERROR)?;
            if configured.contains_key(&t.name()) || mode == t.name() {
                return Err(ERROR);
            }
            for d in history.values() {
                if configured.contains_key(&d.topology.0.name())
                    || mode == d.topology.0.name()
                    || d.observation.as_deref() == Some(mode)
                    || configured.values().any(|e| {
                        e["NetworkID"].as_str().is_some_and(|id| {
                            !id.is_empty() && d.observation.as_deref() == Some(id)
                        })
                    })
                {
                    return Err(ERROR);
                }
            }
            if let Some(e) = configured.get(&outer)
                && [
                    e["IPAMConfig"]["IPv4Address"].as_str(),
                    e["IPAddress"].as_str(),
                ]
                .into_iter()
                .flatten()
                .any(|a| reserved.contains(a))
            {
                return Err(ERROR);
            }
        }
        for i in owners.values() {
            if let Some(p) = &i.paired_containers {
                for role in [Role::Gateway, Role::Guard] {
                    if !role.id(p).is_empty()
                        && !found.contains(&(i.instance.clone(), role == Role::Guard))
                    {
                        return Err(ERROR);
                    }
                }
            }
        }
        let verified = networks.without_running(&running)?;
        verified.validate(t, history)?;
        if verified.outer_name(t)? != outer {
            return Err(ERROR);
        }
        Ok((verified, outer))
    }
}
