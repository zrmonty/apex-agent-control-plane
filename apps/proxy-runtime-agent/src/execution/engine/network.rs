//! Fixed Docker network operations; every candidate requires independent inspect.
use super::*;
use crate::execution::network_owner::{
    self,
    topology::{Document, Phase, Topology},
};
use std::collections::{BTreeMap, BTreeSet};
mod inspect;
mod range;
use inspect::Inspected;
pub(in crate::execution) struct Inventory {
    networks: Vec<Inspected>,
}
mod paired;
impl Inventory {
    pub(in crate::execution) fn outer_name(&self, t: &Topology) -> Result<String, &'static str> {
        let c = t.catalog()?;
        let n = self
            .networks
            .iter()
            .find(|n| n.id == c.outer().network_id())
            .ok_or(ERROR)?;
        n.outer(t)?;
        if self
            .networks
            .iter()
            .filter(|other| other.name == n.name)
            .count()
            != 1
        {
            return Err(ERROR);
        }
        Ok(n.name.clone())
    }
    pub fn validate(
        &self,
        t: &Topology,
        history: &BTreeMap<String, Document>,
    ) -> Result<Option<String>, &'static str> {
        let c = t.catalog()?;
        self.networks
            .iter()
            .find(|n| n.id == c.outer().network_id())
            .ok_or(ERROR)?
            .outer(t)?;
        let pools = [
            range::Range::parse(c.internal_pool(), true)?,
            range::Range::parse(c.outer().subnet(), true)?,
        ];
        let mut own = None;
        let mut claimed = BTreeSet::new();
        for n in &self.networks {
            if n.id == c.outer().network_id() {
                continue;
            }
            let matches: Vec<_> = history
                .values()
                .filter(|d| n.internal(&d.topology.0).is_ok())
                .collect();
            if matches.len() > 1 {
                return Err(ERROR);
            }
            if let Some(d) = matches.first() {
                if d.phase == Phase::Prepared
                    || d.observation.as_ref().is_some_and(|id| id != &n.id)
                    || !claimed.insert(&d.topology.0.instance)
                {
                    return Err(ERROR);
                }
                if d.topology.0.instance == t.instance {
                    own = Some(n.id.clone());
                }
            } else if n.name == t.name()
                || n.ranges
                    .iter()
                    .any(|r| pools.iter().any(|p| p.overlaps(*r)))
            {
                return Err(ERROR);
            }
        }
        for d in history.values() {
            if d.phase == Phase::Observed && !claimed.contains(&d.topology.0.instance) {
                return Err(ERROR);
            }
            if d.phase == Phase::CreateIntent && d.topology.0.instance != t.instance {
                return Err(ERROR);
            }
        }
        Ok(own)
    }
    pub fn unchanged(&self, other: &Self, new: Option<&str>) -> bool {
        self.networks
            .iter()
            .filter(|n| Some(n.id.as_str()) != new)
            .eq(other.networks.iter().filter(|n| Some(n.id.as_str()) != new))
    }
}
impl Engine {
    pub(in crate::execution) fn network_inventory(
        &self,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Inventory, &'static str> {
        let list = self.run(
            vec![
                "network".into(),
                "ls".into(),
                "--quiet".into(),
                "--no-trunc".into(),
            ],
            deadline,
            cancel,
        )?;
        let mut ids: BTreeSet<String> = BTreeSet::new();
        for id in std::str::from_utf8(&list)
            .map_err(|_| ERROR)?
            .split_whitespace()
        {
            if !shapes::hex_hash(id) || ids.len() >= 1024 || !ids.insert(id.into()) {
                return Err(ERROR);
            }
        }
        if ids.is_empty() {
            return Err(ERROR);
        }
        let mut networks = vec![];
        for (id, bytes) in self.inspect_many(
            network_inspection_batch::Kind::Network,
            ids,
            deadline,
            cancel,
        )? {
            let n = Inspected::parse(&bytes)?;
            if n.id != id {
                return Err(ERROR);
            }
            networks.push(n);
        }
        Ok(Inventory { networks })
    }
    pub(in crate::execution) fn create_internal(
        &self,
        t: &Topology,
        gate: &mut network_owner::DispatchGate<'_>,
    ) -> Result<String, &'static str> {
        self.check()?;
        #[cfg(test)]
        crate::execution::testing::at(
            crate::execution::testing::Point::Preflight,
            Some(gate.deadline()?),
        )?;
        let mut args: Vec<OsString> = vec![
            format!("--host=unix://{}", self.paths.docker_socket.display()).into(),
            format!("--config={}", self.paths.docker_config_root.display()).into(),
        ];
        args.extend(
            [
                "network",
                "create",
                "--driver=bridge",
                "--scope=local",
                "--internal",
                "--ipv4=true",
                "--ipv6=false",
                "--attachable=false",
                "--ipam-driver=default",
            ]
            .map(OsString::from),
        );
        args.extend(
            [
                format!("--subnet={}", t.internal_subnet),
                format!("--gateway={}", t.ipam_gateway),
                "--opt=com.docker.network.bridge.gateway_mode_ipv4=isolated".into(),
            ]
            .map(OsString::from),
        );
        args.extend(
            t.labels()?
                .into_iter()
                .map(|(k, v)| OsString::from(format!("--label={k}={v}"))),
        );
        args.push(t.name().into());
        let executable = PathBuf::from(format!("/proc/self/fd/{}", self.executable.as_raw_fd()));
        let bytes = command::run_guarded(
            CommandInput {
                executable: &executable,
                arguments: &args,
                directory: &self.paths.docker_config_root,
                home: None,
                budget: Duration::from_secs(30),
                cancelled: gate.cancelled(),
            },
            gate,
        )?;
        let id = std::str::from_utf8(&bytes).map_err(|_| ERROR)?.trim();
        #[cfg(test)]
        crate::execution::testing::at(
            crate::execution::testing::Point::NetworkCommandReturned,
            None,
        )?;
        if !shapes::hex_hash(id) {
            return Err(ERROR);
        }
        Ok(id.into())
    }
}
