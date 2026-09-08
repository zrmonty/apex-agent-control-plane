//! Immutable stopped-pair ownership with subsequent guarded start and recovery.
//! Start observations do not establish readiness or admission.
use super::{metadata::strict::Object, network, record::Installed};
use serde::{Deserialize, Serialize};
pub(super) const ERROR: &str = "RUNTIME_PAIRED_CONTAINERS_QUARANTINED";
mod provision;
pub(super) mod registration;
pub(super) use provision::run;
pub(super) mod start;
pub(super) mod transition;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(super) enum Phase {
    Prepared,
    GatewayIntent,
    GatewayObserved,
    GuardIntent,
    GuardObserved,
    ConnectIntent,
    Verified,
}
fn phase<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Phase, D::Error> {
    match String::deserialize(d)?.as_str() {
        "Prepared" => Ok(Phase::Prepared),
        "GatewayIntent" => Ok(Phase::GatewayIntent),
        "GatewayObserved" => Ok(Phase::GatewayObserved),
        "GuardIntent" => Ok(Phase::GuardIntent),
        "GuardObserved" => Ok(Phase::GuardObserved),
        "ConnectIntent" => Ok(Phase::ConnectIntent),
        "Verified" => Ok(Phase::Verified),
        _ => Err(serde::de::Error::custom(ERROR)),
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pair {
    pub schema_version: u32,
    #[serde(deserialize_with = "phase")]
    pub phase: Phase,
    pub binding_hash: String,
    pub gateway_image_id: String,
    pub guard_image_id: String,
    pub gateway_unset_env: Vec<String>,
    pub guard_unset_env: Vec<String>,
    pub gateway_id: String,
    pub guard_id: String,
    #[serde(
        default,
        deserialize_with = "start::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub start: Option<start::Observation>,
}
pub(super) fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Pair>, D::Error> {
    Object::<Pair>::deserialize(d).map(|v| Some(v.0))
}
impl Pair {
    pub(super) fn new(
        i: &Installed,
        gateway: (String, Vec<String>),
        guard: (String, Vec<String>),
    ) -> Result<Self, &'static str> {
        let mut p = Self {
            schema_version: 1,
            phase: Phase::Prepared,
            binding_hash: String::new(),
            gateway_image_id: gateway.0,
            guard_image_id: guard.0,
            gateway_unset_env: gateway.1,
            guard_unset_env: guard.1,
            gateway_id: String::new(),
            guard_id: String::new(),
            start: None,
        };
        p.binding_hash = p.binding(i)?;
        Ok(p)
    }
    fn binding(&self, i: &Installed) -> Result<String, &'static str> {
        network::hash(&(
            "apex.runtime.stopped-pair.v1",
            network::owner_hash(i)?,
            &i.mount_profile,
            &i.guard_stage,
            &i.gateway_stage,
            &self.gateway_image_id,
            &self.gateway_unset_env,
            &self.guard_image_id,
            &self.guard_unset_env,
        ))
    }
    pub(super) fn validate(&self, installation: &str, i: &Installed) -> Result<(), &'static str> {
        let g = i.gateway_stage.as_ref().ok_or(ERROR)?;
        g.validate(installation, i)?;
        if g.phase != super::gateway_staging::Phase::Sealed
            || self.schema_version != 1
            || self.binding_hash != self.binding(i)?
            || !crate::shapes::image_id(&self.gateway_image_id)
            || !crate::shapes::image_id(&self.guard_image_id)
        {
            return Err(ERROR);
        }
        for keys in [&self.gateway_unset_env, &self.guard_unset_env] {
            let mut seen = std::collections::BTreeSet::new();
            if keys.len() > 16
                || keys.iter().any(|k| {
                    k.is_empty()
                        || k.len() > 128
                        || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                        || !seen.insert(k)
                })
            {
                return Err(ERROR);
            }
        }
        let gateway = !matches!(self.phase, Phase::Prepared | Phase::GatewayIntent);
        let guard = matches!(
            self.phase,
            Phase::GuardObserved | Phase::ConnectIntent | Phase::Verified
        );
        for (required, id) in [(gateway, &self.gateway_id), (guard, &self.guard_id)] {
            if if required {
                !crate::shapes::hex_hash(id)
            } else {
                !id.is_empty()
            } {
                return Err(ERROR);
            }
        }
        if guard && self.gateway_id == self.guard_id {
            return Err(ERROR);
        }
        if let Some(start) = &self.start {
            start.validate(self)?;
        }
        Ok(())
    }
}
