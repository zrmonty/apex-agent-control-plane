//! Narrow canonical ProtoJSON profile; no unknowns, aliases or positional records.

use crate::proto;
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};
use std::{fmt, marker::PhantomData};

// The byte ceiling bounds all strings before allocation. Typed records have a
// fixed maximum nesting depth; arrays cannot allocate from attacker lengths.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Report {
    live: bool,
    ready: bool,
    target: Object<Target>,
    observed_at_unix_us: Uint,
    config_hash: String,
    runtime_manifest_hash: String,
    process_instance_id: String,
    launch_context_hash: String,
    checks: [Object<Check>; 9],
    stages: [Object<Stage>; 9],
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Target {
    workspace_id: String,
    namespace_id: String,
    proxy_id: String,
    revision_id: String,
    generation: Uint,
    fencing_token: Uint,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    id: CheckId,
    status: Pass,
    reason: OkReason,
}

struct Pass;
impl<'de> Deserialize<'de> for Pass {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if String::deserialize(deserializer)? == "READINESS_CHECK_STATUS_PASS" {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom("invalid status"))
        }
    }
}

struct OkReason;
impl<'de> Deserialize<'de> for OkReason {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if String::deserialize(deserializer)? == "READINESS_REASON_OK" {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom("invalid reason"))
        }
    }
}

struct CheckId(proto::ReadinessCheckId);
impl<'de> Deserialize<'de> for CheckId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        proto::ReadinessCheckId::from_str_name(&name)
            .filter(|id| *id != proto::ReadinessCheckId::Unspecified)
            .map(Self)
            .ok_or_else(|| serde::de::Error::custom("invalid check"))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Stage {
    name: String,
    started_at_unix_us: Uint,
    // ProtoJSON omits this non-optional scalar when ns < 1000. Explicit null
    // never invokes Default; present values must still be canonical strings.
    #[serde(default)]
    duration_us: Uint,
    duration_ns: Uint,
    process_instance_id: String,
    clock_source: String,
    clock_resolution_ns: Uint,
    #[serde(default, deserialize_with = "present_uint")]
    clock_uncertainty_us: Option<u64>,
    // Trace/span/parent fields have no owner in this profile and are refused,
    // including explicit empty values (the canonical producer omits them).
}

#[derive(Default)]
pub(super) struct Uint(pub(super) u64);
impl<'de> Deserialize<'de> for Uint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || value.len() > 20
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err(serde::de::Error::custom("invalid integer"));
        }
        value
            .parse()
            .map(Self)
            .map_err(|_| serde::de::Error::custom("invalid integer"))
    }
}

fn present_uint<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
    Uint::deserialize(deserializer).map(|value| Some(value.0))
}

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

impl Report {
    pub(super) fn into_proto(self) -> proto::ReadinessReport {
        let target = self.target.0;
        proto::ReadinessReport {
            live: self.live,
            ready: self.ready,
            target: Some(proto::RuntimeTarget {
                workspace_id: target.workspace_id,
                namespace_id: target.namespace_id,
                proxy_id: target.proxy_id,
                revision_id: target.revision_id,
                generation: target.generation.0,
                fencing_token: target.fencing_token.0,
            }),
            observed_at_unix_us: self.observed_at_unix_us.0,
            config_hash: self.config_hash,
            runtime_manifest_hash: self.runtime_manifest_hash,
            process_instance_id: self.process_instance_id,
            launch_context_hash: self.launch_context_hash,
            checks: self
                .checks
                .into_iter()
                .map(|Object(check)| {
                    let Pass = check.status;
                    let OkReason = check.reason;
                    proto::ReadinessCheck {
                        id: check.id.0.into(),
                        status: proto::ReadinessCheckStatus::Pass.into(),
                        reason: proto::ReadinessReason::Ok.into(),
                    }
                })
                .collect(),
            stages: self
                .stages
                .into_iter()
                .map(|Object(stage)| proto::ProxyStageTiming {
                    name: stage.name,
                    started_at_unix_us: stage.started_at_unix_us.0,
                    duration_us: stage.duration_us.0,
                    duration_ns: Some(stage.duration_ns.0),
                    process_instance_id: stage.process_instance_id,
                    clock_source: stage.clock_source,
                    clock_resolution_ns: stage.clock_resolution_ns.0,
                    clock_uncertainty_us: stage.clock_uncertainty_us,
                    ..Default::default()
                })
                .collect(),
        }
    }
}
