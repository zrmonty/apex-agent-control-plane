//! Bounded key-free durable inputs; these are never current authority.
use super::ERROR;
use crate::{
    execution::{
        metadata::strict::Object,
        network::{Binding, hash},
        record::Installed,
    },
    network_catalog::NetworkCatalog,
    proto, shapes,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::execution) struct Topology {
    pub schema_version: u32,
    pub installation: String,
    pub instance: String,
    pub original: Object<proto::RuntimeReconcileRequest>,
    pub binding: Object<Binding>,
    pub launch_json: String,
    // Reparsed through the unchanged strict NetworkCatalog grammar on every load.
    pub selected_catalog_json: String,
    pub source_digest: String,
    pub internal_subnet: String,
    pub ipam_gateway: String,
    pub gateway_workload_address: String,
    pub guard_internal_address: String,
    pub guard_outer_address: String,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::execution) enum Phase {
    Prepared,
    CreateIntent,
    Observed,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::execution) struct Document {
    pub topology: Object<Topology>,
    pub topology_hash: String,
    pub phase: Phase,
    // Full observed ID. The immutable topology is its exact expected inspect spec.
    pub observation: Option<String>,
}
impl Topology {
    pub fn new(
        c: &NetworkCatalog,
        installation: &str,
        i: &Installed,
        source: String,
        now: u64,
    ) -> Result<Self, &'static str> {
        super::super::network::prepare(c, installation, i, now)?;
        let b = i.network.as_ref().ok_or(ERROR)?;
        let v: serde_json::Value = serde_json::from_str(&i.authority_json).map_err(|_| ERROR)?;
        let p = &v["profile"];
        let selected = c.select(
            installation,
            p["host_policy_version"].as_str().ok_or(ERROR)?,
            p["managed"]["network_policy"]["reference"]
                .as_str()
                .ok_or(ERROR)?,
            p["managed"]["network_policy"]["version"]
                .as_str()
                .ok_or(ERROR)?,
            now,
        )?;
        let a = c.candidate_addresses(b.slot)?;
        Ok(Self {
            schema_version: 1,
            installation: installation.into(),
            instance: i.instance.clone(),
            original: Object(i.original.clone()),
            binding: Object(b.clone()),
            launch_json: i.launch_json.clone(),
            selected_catalog_json: c.selected_snapshot(selected)?,
            source_digest: source,
            ipam_gateway: std::net::Ipv4Addr::from(u32::from(a.gateway) - 1).to_string(),
            internal_subnet: a.internal_subnet,
            gateway_workload_address: a.gateway.to_string(),
            guard_internal_address: a.guard_internal.to_string(),
            guard_outer_address: a.guard_outer.to_string(),
        })
    }
    pub fn digest(&self) -> Result<String, &'static str> {
        hash(&("apex.runtime.network-topology.v1", self))
    }
    pub fn catalog(&self) -> Result<NetworkCatalog, &'static str> {
        NetworkCatalog::parse(self.selected_catalog_json.as_bytes())
    }
    pub fn name(&self) -> String {
        format!("apex-net-{}", self.instance)
    }
    pub fn labels(&self) -> Result<BTreeMap<String, String>, &'static str> {
        let l: proto::RuntimeLaunchContext =
            serde_json::from_str(&self.launch_json).map_err(|_| ERROR)?;
        let mut labels: BTreeMap<_, _> =
            crate::execution::engine::inspect::labels(&self.installation, &l)?
                .into_iter()
                .map(|(k, v)| (format!("io.apex.runtime.{k}"), v))
                .collect();
        for (k, v) in [
            ("network-role", "internal".into()),
            ("network-profile", "isolated-bridge-v1".into()),
            ("network-binding-hash", self.binding.0.binding_hash.clone()),
            ("network-topology-hash", self.digest()?),
        ] {
            labels.insert(format!("io.apex.runtime.{k}"), v);
        }
        Ok(labels)
    }
    pub fn matches_current(&self, fresh: &Self) -> Result<bool, &'static str> {
        let mut a = serde_json::to_value(self).map_err(|_| ERROR)?;
        let mut b = serde_json::to_value(fresh).map_err(|_| ERROR)?;
        for v in [&mut a, &mut b] {
            v.as_object_mut().ok_or(ERROR)?.remove("source_digest");
            let mut c: serde_json::Value =
                serde_json::from_str(v["selected_catalog_json"].as_str().ok_or(ERROR)?)
                    .map_err(|_| ERROR)?;
            c.as_object_mut().ok_or(ERROR)?.remove("valid_from_unix_us");
            c.as_object_mut().ok_or(ERROR)?.remove("expires_at_unix_us");
            v["selected_catalog_json"] = c;
        }
        Ok(a == b)
    }
    pub fn validate(&self, i: &Installed) -> Result<(), &'static str> {
        self.binding.0.validate(&self.installation, i)?;
        if self.schema_version != 1
            || self.instance != i.instance
            || self.original.0 != i.original
            || self.launch_json != i.launch_json
            || !shapes::hex_hash(&self.source_digest)
        {
            return Err(ERROR);
        }
        let c = self.catalog()?;
        let o = c.outer();
        if self.binding.0.layout_hash
            != hash(&(
                c.installation_id(),
                c.internal_pool(),
                c.capacity(),
                o.network_id(),
                o.subnet(),
                o.gateway(),
                o.edge_address(),
            ))?
        {
            return Err(ERROR);
        }
        let a = c.candidate_addresses(self.binding.0.slot)?;
        if c.installation_id() != self.installation
            || self.internal_subnet != a.internal_subnet
            || self.gateway_workload_address != a.gateway.to_string()
            || self.guard_internal_address != a.guard_internal.to_string()
            || self.guard_outer_address != a.guard_outer.to_string()
            || self.ipam_gateway != std::net::Ipv4Addr::from(u32::from(a.gateway) - 1).to_string()
        {
            return Err(ERROR);
        }
        // Validate the historical selector against ORIGINAL authority material,
        // at its recorded interval start, never treating old policy as current.
        let value: serde_json::Value =
            serde_json::from_str(&self.selected_catalog_json).map_err(|_| ERROR)?;
        let from = value["valid_from_unix_us"].as_u64().ok_or(ERROR)?;
        let expected = Self::new(&c, &self.installation, i, self.source_digest.clone(), from)?;
        if expected.digest()? != self.digest()? {
            return Err(ERROR);
        }
        Ok(())
    }
}
impl Document {
    pub fn prepared(t: Topology) -> Result<Self, &'static str> {
        Ok(Self {
            topology_hash: t.digest()?,
            topology: Object(t),
            phase: Phase::Prepared,
            observation: None,
        })
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.topology_hash != self.topology.0.digest()?
            || match self.phase {
                Phase::Observed => self
                    .observation
                    .as_ref()
                    .is_none_or(|s| !shapes::hex_hash(s)),
                _ => self.observation.is_some(),
            }
        {
            return Err(ERROR);
        }
        Ok(())
    }
}
