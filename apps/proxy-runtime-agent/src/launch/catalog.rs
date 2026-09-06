//! Object-only, duplicate-preserving decode of protected deployment metadata.

use super::{LaunchError, validation};
use crate::proto::RuntimeMaterialRole;
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};
use std::{fmt, marker::PhantomData};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Document {
    pub schema_version: u32,
    pub version: String,
    pub valid_from_unix_us: u64,
    pub expires_at_unix_us: u64,
    pub profiles: Vec<Object<Profile>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    pub installation_id: String,
    pub workspace_id: String,
    pub namespace_id: String,
    pub proxy_id: String,
    pub revision_id: String,
    pub host_policy_version: String,
    pub deployment_bindings_version: String,
    pub config_hash: String,
    pub authority_profile_ref: String,
    pub authority_profile_version: String,
    pub image_catalog_id: String,
    pub materials: Vec<Object<Material>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Material {
    pub role: NamedRole,
    pub reference: String,
    pub version: String,
    pub source_name: String,
}

// Generated enum serde also accepts integers; this catalog requires names only.
pub(super) struct NamedRole(pub RuntimeMaterialRole);
impl<'de> Deserialize<'de> for NamedRole {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        RuntimeMaterialRole::from_str_name(&name)
            .filter(|role| *role != RuntimeMaterialRole::Unspecified)
            .map(Self)
            .ok_or_else(|| serde::de::Error::custom("invalid material role"))
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<Document, LaunchError> {
    if !(1..=262_144).contains(&bytes.len()) {
        return Err(LaunchError::InvalidCatalog);
    }
    let Object(document): Object<Document> =
        serde_json::from_slice(bytes).map_err(|_| LaunchError::InvalidCatalog)?;
    validation::document(&document)?;
    Ok(document)
}

// Derived structs otherwise accept positional arrays. Each metadata record must
// be an object; derive retains decoded duplicate/unknown/missing field refusal.
pub(super) struct Object<T>(pub T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
            type Value = Object<T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("object")
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                T::deserialize(MapAccessDeserializer::new(map)).map(Object)
            }
        }
        deserializer.deserialize_map(ObjectVisitor(PhantomData))
    }
}
