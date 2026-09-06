use super::ERROR;
use crate::{
    execution::{
        guard_stage::{self, Data},
        metadata::strict::Object,
        network_owner::topology::Document,
        record::Installed,
    },
    image_catalog::{ImageCatalog, SelectedImage},
    secrets::{GuardIdentity, GuardRoot},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub(in crate::execution) enum Phase {
    Intent,
    Sealed,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::execution) struct GuardStage {
    pub schema_version: u32,
    #[serde(deserialize_with = "phase")]
    pub phase: Phase,
    pub config_json: String,
    pub files: BTreeMap<String, String>,
    pub manifest: String,
    pub environment: BTreeMap<String, String>,
    pub image_catalog_id: String,
    pub image_ref: String,
    pub certificate_identity: String,
    pub certificate_oidc_issuer: String,
    #[serde(deserialize_with = "topology")]
    pub topology: Object<Document>,
    // Mandatory in durable records, absent only on freshly produced comparison data.
    #[serde(
        default,
        deserialize_with = "root",
        skip_serializing_if = "Option::is_none"
    )]
    pub root_identity: Option<Object<GuardRoot>>,
    #[serde(
        default,
        deserialize_with = "identity",
        skip_serializing_if = "Option::is_none"
    )]
    pub sealed_identity: Option<Object<GuardIdentity>>,
}
pub(in crate::execution) fn present<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<GuardStage>, D::Error> {
    Object::<GuardStage>::deserialize(d).map(|v| Some(v.0))
}
fn phase<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Phase, D::Error> {
    match String::deserialize(d)?.as_str() {
        "Intent" => Ok(Phase::Intent),
        "Sealed" => Ok(Phase::Sealed),
        _ => Err(serde::de::Error::custom(ERROR)),
    }
}
// Confine stricter phase representation to the new guard record; existing network
// journal decoding remains unchanged. Object wrappers retain duplicate rejection.
fn topology<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Object<Document>, D::Error> {
    use crate::execution::network_owner::topology::{Phase as NetworkPhase, Topology};
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GuardDocument {
        topology: Object<Topology>,
        topology_hash: String,
        phase: String,
        observation: Option<String>,
    }
    let Object(raw) = Object::<GuardDocument>::deserialize(d)?;
    if raw.phase != "Observed" {
        return Err(serde::de::Error::custom(ERROR));
    }
    Ok(Object(Document {
        topology: raw.topology,
        topology_hash: raw.topology_hash,
        phase: NetworkPhase::Observed,
        observation: raw.observation,
    }))
}
fn identity<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Object<GuardIdentity>>, D::Error> {
    Object::<GuardIdentity>::deserialize(d).map(Some)
}
fn root<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Object<GuardRoot>>, D::Error> {
    Object::<GuardRoot>::deserialize(d).map(Some)
}
impl GuardStage {
    pub(in crate::execution) fn freeze(
        data: Data,
        image: SelectedImage<'_>,
        topology: &Document,
    ) -> Result<Self, &'static str> {
        if data.image_catalog_id != image.catalog_id || data.image_ref != image.image_ref {
            return Err(ERROR);
        }
        Ok(Self {
            schema_version: 1,
            phase: Phase::Intent,
            config_json: String::from_utf8(data.bytes).map_err(|_| ERROR)?,
            files: data.files,
            manifest: data.manifest,
            environment: data.environment,
            image_catalog_id: data.image_catalog_id,
            image_ref: data.image_ref,
            certificate_identity: image.certificate_identity.into(),
            certificate_oidc_issuer: image.certificate_oidc_issuer.into(),
            topology: Object(topology.clone()),
            root_identity: None,
            sealed_identity: None,
        })
    }
    pub(in crate::execution) fn matches(&self, fresh: &Self) -> Result<(), &'static str> {
        let mut frozen = self.clone();
        frozen.phase = Phase::Intent;
        frozen.sealed_identity = None;
        frozen.root_identity = None;
        if serde_json::to_vec(&frozen).map_err(|_| ERROR)?
            != serde_json::to_vec(fresh).map_err(|_| ERROR)?
        {
            return Err(ERROR);
        }
        Ok(())
    }
    pub(in crate::execution) fn validate(
        &self,
        installation: &str,
        i: &Installed,
    ) -> Result<(), &'static str> {
        if self.schema_version != 1
            || self.config_json.is_empty()
            || self.config_json.len() > 262_144
            || self.files.len() != 1
            || self.environment.len() != 9
            || self.image_catalog_id.len() > 64
            || self.image_ref.len() > 512
            || self.certificate_identity.len() > 2048
            || self.certificate_oidc_issuer.len() > 2048
            || self.topology.0.topology.0.selected_catalog_json.len() > 262_144
            || self.topology.0.topology.0.launch_json.len() > 16_384
            || self.topology.0.topology.0.installation != installation
            || self.topology.0.phase != crate::execution::network_owner::topology::Phase::Observed
            || i.network.as_ref() != Some(&self.topology.0.topology.0.binding.0)
            || i.phase != crate::execution::record::Phase::Intent
            || !i.files.is_empty()
            || !i.image_id.is_empty()
            || !i.container_id.is_empty()
            || (self.phase == Phase::Sealed) != self.sealed_identity.is_some()
        {
            return Err(ERROR);
        }
        if let Some(identity) = &self.sealed_identity {
            identity.0.validate().map_err(|_| ERROR)?;
            if self
                .root_identity
                .as_ref()
                .is_none_or(|root| !identity.0.matches_root(&root.0))
            {
                return Err(ERROR);
            }
        }
        if let Some(root) = &self.root_identity {
            root.0.validate().map_err(|_| ERROR)?;
        }
        self.topology.0.validate()?;
        self.topology.0.topology.0.validate(i)?;
        let images = ImageCatalog::parse(&serde_json::to_vec(&serde_json::json!({
            "schema_version":1,"images":[{"id":self.image_catalog_id,"image_ref":self.image_ref,
            "signing":{"certificate_identity":self.certificate_identity,"certificate_oidc_issuer":self.certificate_oidc_issuer}}]
        })).map_err(|_| ERROR)?).map_err(|_| ERROR)?;
        let image = images
            .select(&self.image_catalog_id, &self.image_ref)
            .map_err(|_| ERROR)?;
        let data = guard_stage::reproduce(i, &self.topology.0, image, &self.config_json)?;
        if data.bytes != self.config_json.as_bytes()
            || data.files != self.files
            || data.manifest != self.manifest
            || data.environment != self.environment
        {
            return Err(ERROR);
        }
        Ok(())
    }
}
