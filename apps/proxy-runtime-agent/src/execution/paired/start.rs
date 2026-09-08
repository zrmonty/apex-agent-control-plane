//! Additive start observations never replace immutable stopped-pair ownership.
use super::{ERROR, Pair, Phase};
use crate::execution::metadata::strict::Object;
use serde::{Deserialize, Serialize};
mod transition;
pub(in crate::execution) use transition::run;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(in crate::execution) enum Step {
    GuardIntent,
    GuardObserved,
    GatewayIntent,
    Running,
}
fn step<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Step, D::Error> {
    match String::deserialize(d)?.as_str() {
        "GuardIntent" => Ok(Step::GuardIntent),
        "GuardObserved" => Ok(Step::GuardObserved),
        "GatewayIntent" => Ok(Step::GatewayIntent),
        "Running" => Ok(Step::Running),
        _ => Err(serde::de::Error::custom(ERROR)),
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::execution) struct Observation {
    pub schema_version: u32,
    #[serde(deserialize_with = "step")]
    pub phase: Step,
    pub gateway_id: String,
    pub guard_id: String,
    #[serde(
        default,
        deserialize_with = "receipt",
        skip_serializing_if = "Option::is_none"
    )]
    pub guard: Option<Receipt>,
    #[serde(
        default,
        deserialize_with = "receipt",
        skip_serializing_if = "Option::is_none"
    )]
    pub gateway: Option<Receipt>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::execution) struct Receipt {
    pub process_hash: String,
}
fn receipt<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Receipt>, D::Error> {
    Object::<Receipt>::deserialize(d).map(|o| Some(o.0))
}
pub(super) fn present<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Observation>, D::Error> {
    Object::<Observation>::deserialize(d).map(|o| Some(o.0))
}
impl Observation {
    pub(super) fn validate(&self, p: &Pair) -> Result<(), &'static str> {
        if self.schema_version != 1
            || p.phase != Phase::Verified
            || self.gateway_id != p.gateway_id
            || self.guard_id != p.guard_id
            || self.guard.is_some() != (self.phase != Step::GuardIntent)
            || self.gateway.is_some() != (self.phase == Step::Running)
            || [&self.guard, &self.gateway]
                .into_iter()
                .flatten()
                .any(|r| !crate::shapes::hex_hash(&r.process_hash))
        {
            return Err(ERROR);
        }
        Ok(())
    }
}
