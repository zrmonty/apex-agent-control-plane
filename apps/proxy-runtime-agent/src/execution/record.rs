use crate::proto;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
mod attestation;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Installed {
    pub original: proto::RuntimeReconcileRequest,
    pub instance: String,
    pub launch_json: String,
    pub configuration_json: String,
    pub authority_json: String,
    pub tools_json: String,
    pub publication_hash: String,
    pub image_id: String,
    pub mount_profile: String,
    pub unset_env: Vec<String>,
    pub container_id: String,
    pub phase: Phase,
    pub files: BTreeMap<String, String>,
    // Absent on legacy dormant stages; never synthesize a proof during adoption.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_proof_version: Option<u32>,
    // Omitted legacy representation retains existing checksums and dormant semantics.
    #[serde(
        default,
        deserialize_with = "super::network::present",
        skip_serializing_if = "Option::is_none"
    )]
    pub network: Option<super::network::Binding>,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Phase {
    Intent,
    ProofIntent,
    StageIntent,
    Staged,
    CreateIntent,
    Installed,
    RemoveIntent,
    StageRemoveIntent,
    Removed,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub schema_version: u32,
    pub installation: String,
    pub claims: proto::RuntimeReconcileRequest,
    pub instance: String,
    pub original: proto::RuntimeReconcileRequest,
    #[serde(deserialize_with = "optional_installed")]
    pub installed: Option<Installed>,
    #[serde(deserialize_with = "optional_installed")]
    pub predecessor: Option<Installed>,
    pub commands: BTreeMap<String, String>,
    // Tombstone for every ID at/below this value: never silently forget a binding.
    // Omitted on legacy records so their existing checksum remains readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_floor: Option<String>,
}
fn optional_installed<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Installed>, D::Error> {
    struct Object(Installed);
    impl<'de> Deserialize<'de> for Object {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Object;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("an installed object")
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    map: A,
                ) -> Result<Object, A::Error> {
                    Installed::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                        .map(Object)
                }
            }
            d.deserialize_map(Visitor)
        }
    }
    Option::<Object>::deserialize(d).map(|i| i.map(|Object(i)| i))
}
impl Record {
    pub(super) fn select(
        installation: &str,
        claims: &proto::RuntimeReconcileRequest,
        old: Option<Self>,
    ) -> Result<Self, &'static str> {
        let target = claims.target.as_ref().ok_or("RUNTIME_JOURNAL_REFUSED")?;
        if let Some(mut old) = old {
            let previous = old
                .claims
                .target
                .as_ref()
                .ok_or("RUNTIME_JOURNAL_REFUSED")?;
            if old.schema_version != 1
                || old.installation != installation
                || previous.workspace_id != target.workspace_id
                || previous.namespace_id != target.namespace_id
                || previous.proxy_id != target.proxy_id
                || target.fencing_token < previous.fencing_token
                || claims.operation_id != old.claims.operation_id
                || target.generation != previous.generation
                || target.revision_id != previous.revision_id
                || claims.config_hash != old.claims.config_hash
                || old
                    .commands
                    .get(&claims.command_id)
                    .is_some_and(|op| op != &claims.operation_id)
            {
                return Err("RUNTIME_JOURNAL_REFUSED");
            }
            old.retain_command(claims)?;
            old.claims = claims.clone();
            return Ok(old);
        }
        Ok(Self {
            schema_version: 1,
            installation: installation.into(),
            claims: claims.clone(),
            instance: uuid::Uuid::now_v7().to_string(),
            original: claims.clone(),
            installed: None,
            predecessor: None,
            commands: BTreeMap::from([(claims.command_id.clone(), claims.operation_id.clone())]),
            replay_floor: None,
        })
    }
    pub(super) fn advance(
        mut self,
        claims: &proto::RuntimeReconcileRequest,
        serving: bool,
    ) -> Result<Self, &'static str> {
        let a = self
            .claims
            .target
            .as_ref()
            .ok_or("RUNTIME_JOURNAL_REFUSED")?;
        let b = claims.target.as_ref().ok_or("RUNTIME_JOURNAL_REFUSED")?;
        if a.workspace_id != b.workspace_id
            || a.namespace_id != b.namespace_id
            || a.proxy_id != b.proxy_id
            || b.generation <= a.generation
            || b.fencing_token <= a.fencing_token
            || claims.operation_id == self.claims.operation_id
            || self.commands.contains_key(&claims.command_id)
        {
            return Err("RUNTIME_JOURNAL_REFUSED");
        }
        self.retain_command(claims)?;
        if serving {
            if self.predecessor.is_some() {
                return Err("RUNTIME_JOURNAL_CAPACITY");
            }
            self.predecessor = self.installed.take();
            self.instance = uuid::Uuid::now_v7().to_string();
            self.original = claims.clone();
        }
        self.claims = claims.clone();
        Ok(self)
    }
    fn retain_command(
        &mut self,
        claims: &proto::RuntimeReconcileRequest,
    ) -> Result<(), &'static str> {
        if self
            .replay_floor
            .as_ref()
            .is_some_and(|floor| &claims.command_id <= floor)
        {
            return Err("RUNTIME_COMMAND_REPLAY_EXPIRED");
        }
        if let Some(operation) = self.commands.get(&claims.command_id) {
            return if operation == &claims.operation_id {
                Ok(())
            } else {
                Err("RUNTIME_JOURNAL_REFUSED")
            };
        }
        if self.commands.len() >= 64 {
            let (floor, _) = self
                .commands
                .first_key_value()
                .ok_or("RUNTIME_JOURNAL_REFUSED")?;
            if &claims.command_id <= floor {
                return Err("RUNTIME_COMMAND_REPLAY_EXPIRED");
            }
            self.replay_floor = self.commands.pop_first().map(|(id, _)| id);
        }
        self.commands
            .insert(claims.command_id.clone(), claims.operation_id.clone());
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    mod retention;
    fn claims() -> proto::RuntimeReconcileRequest {
        proto::RuntimeReconcileRequest {
            schema_version: 1,
            target: Some(proto::RuntimeTarget {
                workspace_id: "work".into(),
                namespace_id: "ns".into(),
                proxy_id: uuid::Uuid::now_v7().to_string(),
                revision_id: uuid::Uuid::now_v7().to_string(),
                generation: 1,
                fencing_token: 1,
            }),
            operation_id: uuid::Uuid::now_v7().to_string(),
            command_id: uuid::Uuid::now_v7().to_string(),
            config_hash: "a".repeat(64),
        }
    }
    #[test]
    fn retries_and_higher_fence_preserve_one_original_instance() {
        let mut c = claims();
        let install = uuid::Uuid::now_v7().to_string();
        let first = Record::select(&install, &c, None).unwrap();
        let instance = first.instance.clone();
        let original = first.original.clone();
        let second = Record::select(&install, &c, Some(first)).unwrap();
        assert_eq!(second.instance, instance, "same command must resume");
        c.command_id = uuid::Uuid::now_v7().to_string();
        c.target.as_mut().unwrap().fencing_token = 2;
        let third = Record::select(&install, &c, Some(second)).unwrap();
        assert_eq!(third.instance, instance);
        assert_eq!(third.original, original);
        let mut stale = c.clone();
        stale.target.as_mut().unwrap().fencing_token = 1;
        assert!(Record::select(&install, &stale, Some(third)).is_err());
    }
    #[test]
    fn installed_journal_entry_cannot_be_a_positional_array() {
        let c = claims();
        let install = uuid::Uuid::now_v7().to_string();
        let r = Record::select(&install, &c, None).unwrap();
        let mut value = serde_json::to_value(&r).unwrap();
        value["installed"] = serde_json::json!([
            c,
            r.instance,
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            [],
            "",
            "Intent",
            {}
        ]);
        assert!(serde_json::from_value::<Record>(value).is_err());
    }
    #[test]
    fn a_command_from_an_older_operation_cannot_be_reused_in_the_current_operation() {
        let c = claims();
        let install = uuid::Uuid::now_v7().to_string();
        let first = Record::select(&install, &c, None).unwrap();
        let mut next = c.clone();
        next.operation_id = uuid::Uuid::now_v7().to_string();
        next.command_id = uuid::Uuid::now_v7().to_string();
        next.target.as_mut().unwrap().generation += 1;
        next.target.as_mut().unwrap().fencing_token += 1;
        let advanced = first.advance(&next, false).unwrap();
        next.command_id = c.command_id;
        assert!(Record::select(&install, &next, Some(advanced)).is_err());
    }
    #[test]
    fn cleanup_generation_retains_original_and_conflicting_commands_refuse() {
        let c = claims();
        let install = uuid::Uuid::now_v7().to_string();
        let first = Record::select(&install, &c, None).unwrap();
        let instance = first.instance.clone();
        let mut next = c.clone();
        next.operation_id = uuid::Uuid::now_v7().to_string();
        next.command_id = uuid::Uuid::now_v7().to_string();
        next.target.as_mut().unwrap().generation += 1;
        next.target.as_mut().unwrap().fencing_token += 1;
        let paused = first.advance(&next, false).unwrap();
        assert_eq!(paused.instance, instance);
        assert_eq!(paused.original, c);
        let mut conflict = next.clone();
        conflict.config_hash = "b".repeat(64);
        assert!(Record::select(&install, &conflict, Some(paused)).is_err());
        let first = Record::select(&install, &c, None).unwrap();
        next.command_id = c.command_id.clone();
        assert!(first.advance(&next, false).is_err());
    }
}
