use super::ERROR;
use crate::{
    execution::{guard_staging, metadata::strict::Object, network, record::Installed},
    image_catalog::SelectedImage,
    secrets::{GatewayIdentity, GuardRoot},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub(in crate::execution) enum Phase {
    ProofIntent,
    StageIntent,
    SealIntent,
    Sealed,
}
fn phase<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Phase, D::Error> {
    match String::deserialize(d)?.as_str() {
        "ProofIntent" => Ok(Phase::ProofIntent),
        "StageIntent" => Ok(Phase::StageIntent),
        "SealIntent" => Ok(Phase::SealIntent),
        "Sealed" => Ok(Phase::Sealed),
        _ => Err(serde::de::Error::custom(ERROR)),
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::execution) struct GatewayStage {
    pub schema_version: u32,
    #[serde(deserialize_with = "phase")]
    pub phase: Phase,
    pub binding_hash: String,
    pub source_metadata_hash: String,
    pub image_catalog_id: String,
    pub image_ref: String,
    pub certificate_identity: String,
    pub certificate_oidc_issuer: String,
    pub root: Object<GuardRoot>,
    pub files: BTreeMap<String, String>,
    pub source_identity: Option<String>,
    #[serde(
        default,
        deserialize_with = "identity",
        skip_serializing_if = "Option::is_none"
    )]
    pub identity: Option<Object<GatewayIdentity>>,
}
pub(in crate::execution) fn present<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<GatewayStage>, D::Error> {
    Object::<GatewayStage>::deserialize(d).map(|v| Some(v.0))
}
fn identity<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Object<GatewayIdentity>>, D::Error> {
    Object::<GatewayIdentity>::deserialize(d).map(Some)
}
impl GatewayStage {
    pub(in crate::execution) fn new(
        installation: &str,
        i: &Installed,
        image: SelectedImage<'_>,
        source_metadata_hash: String,
        root: GuardRoot,
    ) -> Result<Self, &'static str> {
        let mut result = Self {
            schema_version: 1,
            phase: Phase::ProofIntent,
            binding_hash: String::new(),
            source_metadata_hash,
            image_catalog_id: image.catalog_id.into(),
            image_ref: image.image_ref.into(),
            certificate_identity: image.certificate_identity.into(),
            certificate_oidc_issuer: image.certificate_oidc_issuer.into(),
            root: Object(root),
            files: BTreeMap::new(),
            source_identity: None,
            identity: None,
        };
        result.binding_hash = result.binding(installation, i)?;
        result.validate(installation, i)?;
        Ok(result)
    }
    fn binding(&self, installation: &str, i: &Installed) -> Result<String, &'static str> {
        network::hash(&(
            installation,
            network::owner_hash(i)?,
            &i.guard_stage,
            &self.root,
            &self.source_metadata_hash,
            &self.image_catalog_id,
            &self.image_ref,
            &self.certificate_identity,
            &self.certificate_oidc_issuer,
        ))
    }
    pub(in crate::execution) fn matches(&self, fresh: &Self) -> Result<(), &'static str> {
        if self.binding_hash != fresh.binding_hash {
            return Err(ERROR);
        }
        Ok(())
    }
    pub(in crate::execution) fn validate(
        &self,
        installation: &str,
        i: &Installed,
    ) -> Result<(), &'static str> {
        let guard = i.guard_stage.as_ref().ok_or(ERROR)?;
        guard.validate(installation, i)?;
        let launch: crate::proto::RuntimeLaunchContext =
            serde_json::from_str(&i.launch_json).map_err(|_| ERROR)?;
        if self.schema_version != 1
            || guard.phase != guard_staging::Phase::Sealed
            || guard
                .root_identity
                .as_ref()
                .is_none_or(|r| r.0 != self.root.0)
            || i.instance_proof_version != Some(1)
            || !crate::shapes::hex_hash(&self.source_metadata_hash)
            || self.binding_hash != self.binding(installation, i)?
            || self.image_ref != launch.image_ref
            || self.image_catalog_id.is_empty()
            || self.image_catalog_id.len() > 64
            || self.image_ref.len() > 512
            || self.certificate_identity.is_empty()
            || self.certificate_identity.len() > 2048
            || self.certificate_oidc_issuer.is_empty()
            || self.certificate_oidc_issuer.len() > 2048
        {
            return Err(ERROR);
        }
        self.root.0.validate().map_err(|_| ERROR)?;
        match self.phase {
            Phase::ProofIntent
                if !self.files.is_empty()
                    || self.identity.is_some()
                    || self.source_identity.is_some() =>
            {
                return Err(ERROR);
            }
            Phase::StageIntent if self.identity.is_some() => return Err(ERROR),
            Phase::SealIntent | Phase::Sealed if self.identity.is_none() => return Err(ERROR),
            _ => {}
        }
        if self.phase != Phase::ProofIntent {
            if self
                .source_identity
                .as_ref()
                .is_none_or(|v| !crate::shapes::hex_hash(v))
            {
                return Err(ERROR);
            }
            let names = crate::secrets::gateway_names(&i.tools_json).map_err(|_| ERROR)?;
            if self.files.keys().ne(names.iter())
                || self.files.values().any(|v| !crate::shapes::hex_hash(v))
            {
                return Err(ERROR);
            }
        }
        if let Some(identity) = &self.identity {
            identity
                .0
                .validate(&self.root.0, &self.files, self.phase == Phase::Sealed)
                .map_err(|_| ERROR)?;
        }
        Ok(())
    }
}
