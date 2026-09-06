//! Durable network identity is metadata, never an engine or admission permit.
#[cfg(target_os = "linux")]
use super::record::Installed;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
const ERROR: &str = "RUNTIME_NETWORK_RESERVATION_REFUSED";
#[cfg(target_os = "linux")]
mod prepare;
#[cfg(target_os = "linux")]
pub(super) use prepare::prepare;
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub schema_version: u32,
    pub slot: u16,
    pub layout_hash: String,
    pub owner_hash: String,
    pub binding_hash: String,
}
#[cfg(target_os = "linux")]
impl Binding {
    pub(super) fn new(
        installation: &str,
        instance: &str,
        slot: u16,
        layout_hash: String,
        owner_hash: String,
    ) -> Result<Self, &'static str> {
        if !crate::shapes::uuid_v7(installation)
            || !crate::shapes::uuid_v7(instance)
            || slot >= 128
            || !crate::shapes::hex_hash(&layout_hash)
            || !crate::shapes::hex_hash(&owner_hash)
        {
            return Err(ERROR);
        }
        let binding_hash = hash(&(&installation, &instance, slot, &layout_hash, &owner_hash))?;
        Ok(Self {
            schema_version: 1,
            slot,
            layout_hash,
            owner_hash,
            binding_hash,
        })
    }
    pub(super) fn validate(&self, installation: &str, i: &Installed) -> Result<(), &'static str> {
        if self.schema_version != 1
            || self.owner_hash != owner_hash(i)?
            || *self
                != Self::new(
                    installation,
                    &i.instance,
                    self.slot,
                    self.layout_hash.clone(),
                    self.owner_hash.clone(),
                )?
        {
            return Err(ERROR);
        }
        Ok(())
    }
}
#[cfg(target_os = "linux")]
pub(super) fn hash(v: &impl Serialize) -> Result<String, &'static str> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(v).map_err(|_| ERROR)?)
    ))
}
#[cfg(target_os = "linux")]
pub(super) fn owner_hash(i: &Installed) -> Result<String, &'static str> {
    if !crate::shapes::uuid_v7(&i.instance) {
        return Err(ERROR);
    }
    hash(&(
        &i.original,
        &i.instance,
        &i.launch_json,
        &i.configuration_json,
        &i.authority_json,
        &i.tools_json,
        &i.publication_hash,
    ))
}
pub(super) fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Binding>, D::Error> {
    struct V;
    impl<'de> serde::de::Visitor<'de> for V {
        type Value = Binding;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("network binding object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, m: A) -> Result<Binding, A::Error> {
            Binding::deserialize(serde::de::value::MapAccessDeserializer::new(m))
        }
    }
    d.deserialize_map(V).map(Some)
}
