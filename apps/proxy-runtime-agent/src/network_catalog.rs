//! Protected network policy data; never a network allocation or effect permit.
use crate::{image_catalog::ImageCatalog, shapes};
use serde::Deserialize;
use std::{collections::BTreeSet, net::Ipv4Addr};
mod address;
mod shape;
use address::Cidr;
use shape::Object;
const ERROR: &str = "RUNTIME_NETWORK_CATALOG_INVALID";

/// Fully validated data. Construction does not authenticate its source.
pub struct NetworkCatalog {
    document: Document,
    internal: Cidr,
    outer: Cidr,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u32,
    version: String,
    installation_id: String,
    host_policy_version: String,
    valid_from_unix_us: u64,
    expires_at_unix_us: u64,
    capacity: u16,
    internal_pool: String,
    outer: Object<Outer>,
    profiles: Vec<Object<Profile>>,
}
/// Read-only selection of a protected, pre-existing outer fabric.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outer {
    network_id: String,
    subnet: String,
    gateway: String,
    edge_address: String,
}
/// Exact profile metadata, not permission to pull or start its guard image.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    reference: String,
    version: String,
    guard_image_catalog_id: String,
    guard_image_ref: String,
    grants: Vec<Object<Grant>>,
}
/// A protected upper bound; published policy and actual DNS answers must narrow it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    purpose: String,
    host: String,
    port: u16,
    cidrs: Vec<String>,
}
/// Deterministic candidates only. Durable allocation must reserve a slot first.
#[derive(Debug, PartialEq, Eq)]
pub struct CandidateAddresses {
    pub internal_subnet: String,
    pub gateway: Ipv4Addr,
    pub guard_internal: Ipv4Addr,
    pub guard_outer: Ipv4Addr,
}
impl NetworkCatalog {
    /// Parse original strict JSON with bounded fields and unambiguous IPv4 ranges.
    /// # Errors
    /// Refuses malformed or unsupported policy. Errors contain no input data.
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if !(1..=262_144).contains(&bytes.len()) {
            return Err(ERROR);
        }
        let Object(d): Object<Document> = serde_json::from_slice(bytes).map_err(|_| ERROR)?;
        let internal = Cidr::parse(&d.internal_pool)?;
        let outer = Cidr::parse(&d.outer.0.subnet)?;
        if d.schema_version != 1
            || !shape::version(&d.version)
            || !shapes::uuid_v7(&d.installation_id)
            || !shape::version(&d.host_policy_version)
            || d.valid_from_unix_us == 0
            || d.valid_from_unix_us >= d.expires_at_unix_us
            || d.expires_at_unix_us > i64::MAX as u64
            || !(1..=128).contains(&d.capacity)
            || !(22..=29).contains(&internal.prefix)
            || !internal.private()
            || u32::from(d.capacity) > internal.size() / 8
            || outer.prefix != 24
            || !outer.private()
            || outer.overlaps(internal)
            || !shapes::hex_hash(&d.outer.0.network_id)
            || d.outer.0.gateway == d.outer.0.edge_address
            || !(1..=32).contains(&d.profiles.len())
        {
            return Err(ERROR);
        }
        for ip in [&d.outer.0.gateway, &d.outer.0.edge_address] {
            let ip = address::ip(ip)?;
            if !(outer.base + 1..=outer.base + 15).contains(&u32::from(ip)) {
                return Err(ERROR);
            }
        }
        let mut selectors = BTreeSet::new();
        for Object(p) in &d.profiles {
            if !shape::version(&p.reference)
                || !shape::version(&p.version)
                || !shape::image_id(&p.guard_image_catalog_id)
                || !shapes::image_ref(&p.guard_image_ref)
                || !selectors.insert((&p.reference, &p.version))
                || !(1..=64).contains(&p.grants.len())
            {
                return Err(ERROR);
            }
            let mut grants = BTreeSet::new();
            let mut purposes = BTreeSet::new();
            for Object(g) in &p.grants {
                if !matches!(g.purpose.as_str(), "governance" | "evidence" | "upstream")
                    || !shape::host(&g.host)
                    || g.port == 0
                    || !(1..=32).contains(&g.cidrs.len())
                    || !grants.insert((&g.purpose, &g.host, g.port))
                {
                    return Err(ERROR);
                }
                purposes.insert(g.purpose.as_str());
                let mut cidrs = BTreeSet::new();
                for text in &g.cidrs {
                    let cidr = Cidr::parse(text)?;
                    if !cidrs.insert(text)
                        || cidr.overlaps(internal)
                        || cidr.overlaps(outer)
                        || cidr.reserved()
                    {
                        return Err(ERROR);
                    }
                }
            }
            if !purposes.contains("governance") || !purposes.contains("evidence") {
                return Err(ERROR);
            }
        }
        Ok(Self {
            document: d,
            internal,
            outer,
        })
    }
    /// # Errors
    /// Refuses time outside the exact half-open validity interval.
    pub fn current(&self, now_unix_us: u64) -> Result<(), &'static str> {
        if now_unix_us < self.document.valid_from_unix_us
            || now_unix_us >= self.document.expires_at_unix_us
        {
            return Err(ERROR);
        }
        Ok(())
    }
    /// Join all guard selectors to protected image policy; does not verify signatures.
    /// # Errors
    /// Refuses any unmatched ID or digest, including unselected profiles.
    pub fn join_images(&self, images: &ImageCatalog) -> Result<(), &'static str> {
        for Object(p) in &self.document.profiles {
            images
                .select(&p.guard_image_catalog_id, &p.guard_image_ref)
                .map_err(|_| ERROR)?;
        }
        Ok(())
    }
    /// # Errors
    /// Refuses expired policy or any installation/host/reference/version mismatch.
    pub fn select(
        &self,
        installation: &str,
        host_policy: &str,
        reference: &str,
        version: &str,
        now_unix_us: u64,
    ) -> Result<&Profile, &'static str> {
        self.current(now_unix_us)?;
        if self.document.installation_id != installation
            || self.document.host_policy_version != host_policy
        {
            return Err(ERROR);
        }
        self.document
            .profiles
            .iter()
            .map(|Object(p)| p)
            .find(|p| p.reference == reference && p.version == version)
            .ok_or(ERROR)
    }
    pub fn installation_id(&self) -> &str {
        &self.document.installation_id
    }
    pub fn host_policy_version(&self) -> &str {
        &self.document.host_policy_version
    }
    pub fn capacity(&self) -> u16 {
        self.document.capacity
    }
    /// Key-free selected policy snapshot; data only, never an effect permit.
    #[cfg(target_os = "linux")]
    pub(crate) fn selected_snapshot(&self, p: &Profile) -> Result<String, &'static str> {
        let d = &self.document;
        serde_json::to_string(&serde_json::json!({
            "schema_version":d.schema_version,"version":d.version,
            "installation_id":d.installation_id,"host_policy_version":d.host_policy_version,
            "valid_from_unix_us":d.valid_from_unix_us,"expires_at_unix_us":d.expires_at_unix_us,
            "capacity":d.capacity,"internal_pool":d.internal_pool,
            "outer":{"network_id":d.outer.0.network_id,"subnet":d.outer.0.subnet,
                "gateway":d.outer.0.gateway,"edge_address":d.outer.0.edge_address},
            "profiles":[{"reference":p.reference,"version":p.version,
                "guard_image_catalog_id":p.guard_image_catalog_id,"guard_image_ref":p.guard_image_ref,
                "grants":p.grants().map(|g|serde_json::json!({"purpose":g.purpose,"host":g.host,
                    "port":g.port,"cidrs":g.cidrs})).collect::<Vec<_>>()}]
        })).map_err(|_| ERROR)
    }
    pub fn internal_pool(&self) -> &str {
        &self.document.internal_pool
    }
    pub fn outer(&self) -> &Outer {
        &self.document.outer.0
    }
    /// This pure calculation neither reserves a slot nor authorizes network effects.
    /// # Errors
    /// Refuses a slot outside protected capacity.
    pub fn candidate_addresses(&self, slot: u16) -> Result<CandidateAddresses, &'static str> {
        if slot >= self.capacity() {
            return Err(ERROR);
        }
        let base = self.internal.base + u32::from(slot) * 8;
        Ok(CandidateAddresses {
            internal_subnet: format!("{}/29", Ipv4Addr::from(base)),
            gateway: (base + 2).into(),
            guard_internal: (base + 3).into(),
            guard_outer: (self.outer.base + 16 + u32::from(slot)).into(),
        })
    }
}
impl Outer {
    pub fn network_id(&self) -> &str {
        &self.network_id
    }
    pub fn subnet(&self) -> &str {
        &self.subnet
    }
    pub fn gateway(&self) -> &str {
        &self.gateway
    }
    pub fn edge_address(&self) -> &str {
        &self.edge_address
    }
}
impl Profile {
    pub fn reference(&self) -> &str {
        &self.reference
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn guard_image_catalog_id(&self) -> &str {
        &self.guard_image_catalog_id
    }
    pub fn guard_image_ref(&self) -> &str {
        &self.guard_image_ref
    }
    pub fn grants(&self) -> impl Iterator<Item = &Grant> {
        self.grants.iter().map(|Object(g)| g)
    }
}
impl Grant {
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn cidrs(&self) -> &[String] {
        &self.cidrs
    }
}
#[cfg(test)]
pub(crate) mod tests;
