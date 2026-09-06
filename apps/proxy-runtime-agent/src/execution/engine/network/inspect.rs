use super::{ERROR, range::Range};
use crate::execution::network_owner::topology::Topology;
use serde_json::{Value, json};
use std::collections::BTreeSet;
#[cfg(test)]
mod tests;
#[derive(PartialEq)]
pub(in crate::execution) struct Inspected {
    pub id: String,
    pub name: String,
    pub(super) value: Value,
    pub(super) ranges: Vec<Range>,
    pub(super) addresses: Vec<Range>,
}
fn object_empty(v: &Value) -> bool {
    v.is_null() || v.as_object().is_some_and(|m| m.is_empty())
}
fn optional_text(v: &Value) -> bool {
    v.is_null() || v.as_str() == Some("")
}
impl Inspected {
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        let parsed = crate::execution::engine::inspect::json::Json::bounded(bytes, 262_144)?;
        let v = &parsed.0;
        let mut v = v.as_array().filter(|a| a.len() == 1).ok_or(ERROR)?[0].clone();
        let id = v["Id"]
            .as_str()
            .filter(|s| crate::shapes::hex_hash(s))
            .ok_or(ERROR)?
            .to_owned();
        let name = v["Name"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 128)
            .ok_or(ERROR)?
            .to_owned();
        if v["Scope"] != "local"
            || !matches!(v["Driver"].as_str(), Some("bridge" | "host" | "null"))
            || v["IPAM"]["Driver"] != "default"
            || !object_empty(&v["IPAM"]["Options"])
        {
            return Err(ERROR);
        }
        let mut ranges = vec![];
        let mut addresses = vec![];
        let configs = v["IPAM"]["Config"]
            .as_array()
            .cloned()
            .or_else(|| v["IPAM"]["Config"].is_null().then(Vec::new))
            .ok_or(ERROR)?;
        if configs.len() > 32 || (configs.is_empty() && v["Driver"] == "bridge") {
            return Err(ERROR);
        }
        for c in configs {
            if c.as_object().ok_or(ERROR)?.keys().any(|k| {
                !matches!(
                    k.as_str(),
                    "Subnet" | "Gateway" | "IPRange" | "AuxiliaryAddresses"
                )
            }) {
                return Err(ERROR);
            }
            let range = Range::parse(c["Subnet"].as_str().ok_or(ERROR)?, true)?;
            if ranges.iter().any(|r: &Range| r.overlaps(range)) {
                return Err(ERROR);
            }
            ranges.push(range);
            if !optional_text(&c["IPRange"]) {
                let ip_range = Range::parse(c["IPRange"].as_str().ok_or(ERROR)?, true)?;
                if !range.contains(ip_range) {
                    return Err(ERROR);
                }
            }
            if !optional_text(&c["Gateway"]) {
                let ip = Range::address(c["Gateway"].as_str().ok_or(ERROR)?)?;
                if !range.contains(ip) {
                    return Err(ERROR);
                }
                addresses.push(ip);
            }
            if !object_empty(&c["AuxiliaryAddresses"]) {
                let aux = c["AuxiliaryAddresses"]
                    .as_object()
                    .filter(|m| m.len() <= 256)
                    .ok_or(ERROR)?;
                for ip in aux.values() {
                    let ip = Range::address(ip.as_str().ok_or(ERROR)?)?;
                    if !range.contains(ip) {
                        return Err(ERROR);
                    }
                    addresses.push(ip);
                }
            }
        }
        let endpoints = v["Containers"]
            .as_object()
            .filter(|m| m.len() <= 1024)
            .ok_or(ERROR)?;
        let mut seen = BTreeSet::new();
        for (id, e) in endpoints {
            if !crate::shapes::hex_hash(id) {
                return Err(ERROR);
            }
            for field in ["IPv4Address", "IPv6Address"] {
                let text = e[field].as_str().ok_or(ERROR)?;
                if text.is_empty() {
                    continue;
                }
                let ip = Range::parse(text, false)?;
                if !ranges.iter().any(|r| r.contains(ip)) || !seen.insert((ip.v6, ip.first)) {
                    return Err(ERROR);
                }
                addresses.push(ip);
            }
        }
        let mut allocated = BTreeSet::new();
        if addresses.iter().any(|a| !allocated.insert((a.v6, a.first))) {
            return Err(ERROR);
        }
        if !object_empty(&v["Peers"]) || !object_empty(&v["Services"]) {
            return Err(ERROR);
        }
        let m = v.as_object_mut().ok_or(ERROR)?;
        m.remove("Created");
        m.remove("Status");
        Ok(Self {
            id,
            name,
            value: v,
            ranges,
            addresses,
        })
    }
    fn profile(&self, internal: bool, subnet: &str, gateway: &str) -> Result<(), &'static str> {
        let v = &self.value;
        let c = &v["IPAM"]["Config"];
        if v["Driver"] != "bridge"
            || v["Internal"] != internal
            || v["EnableIPv4"] != true
            || v["EnableIPv6"] != false
            || v["Attachable"] != false
            || v["Ingress"] != false
            || v["ConfigOnly"] != false
            || v["ConfigFrom"] != json!({"Network":""})
            || c.as_array().is_none_or(|a| a.len() != 1)
            || c[0]["Subnet"] != subnet
            || c[0]["Gateway"] != gateway
            || !optional_text(&c[0]["IPRange"])
            || !object_empty(&c[0]["AuxiliaryAddresses"])
        {
            return Err(ERROR);
        }
        let options = if internal {
            json!({"com.docker.network.bridge.gateway_mode_ipv4":"isolated"})
        } else {
            json!({})
        };
        if v["Options"] != options {
            return Err(ERROR);
        }
        Ok(())
    }
    pub fn internal(&self, t: &Topology) -> Result<(), &'static str> {
        self.profile(true, &t.internal_subnet, &t.ipam_gateway)?;
        if self.name != t.name()
            || self.value["Labels"] != serde_json::to_value(t.labels()?).map_err(|_| ERROR)?
            || self.value["Containers"] != json!({})
        {
            return Err(ERROR);
        }
        Ok(())
    }
    pub fn outer(&self, t: &Topology) -> Result<(), &'static str> {
        let c = t.catalog()?;
        let o = c.outer();
        if self.id != o.network_id() {
            return Err(ERROR);
        }
        self.profile(false, o.subnet(), o.gateway())?;
        for slot in 0..c.capacity() {
            let a = Range::address(&c.candidate_addresses(slot)?.guard_outer.to_string())?;
            if self.addresses.iter().any(|r| r.overlaps(a)) {
                return Err(ERROR);
            }
        }
        Ok(())
    }
}
