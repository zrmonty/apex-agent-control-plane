//! Durable health-exec correlation, never a cached readiness lease.
use crate::proto;
use serde::{Deserialize, Serialize};

pub(super) const ERROR: &str = "RUNTIME_HEALTH_EXEC_QUARANTINED";
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub schema_version: u32,
    pub attempt_id: String,
    pub binding: proto::ManagedDeploymentBinding,
    pub container_id: String,
    pub exec_id: String,
    pub phase: Phase,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Phase {
    CreateIntent,
    Created,
    StartIntent,
    Finished,
}

impl Record {
    pub(super) fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 1
            || !crate::shapes::uuid_v7(&self.attempt_id)
            || !crate::shapes::hex_hash(&self.container_id)
            || if self.phase == Phase::CreateIntent {
                !self.exec_id.is_empty()
            } else {
                !crate::shapes::hex_hash(&self.exec_id)
            }
        {
            return Err(ERROR);
        }
        crate::service::network_readiness::validate(&proto::RuntimeNetworkInspectionRequest {
            schema_version: 1,
            binding: Some(self.binding.clone()),
            nonce: vec![0; 32],
        })
        .map_err(|_| ERROR)
    }
    pub(super) fn follows(&self, previous: &Self) -> bool {
        if self.validate().is_err()
            || previous.validate().is_err()
            || self.binding != previous.binding
            || self.container_id != previous.container_id
        {
            return false;
        }
        if previous.phase == Phase::Finished && self.phase == Phase::CreateIntent {
            return self.attempt_id != previous.attempt_id;
        }
        self.attempt_id == previous.attempt_id
            && (previous.phase == Phase::CreateIntent || self.exec_id == previous.exec_id)
            && matches!(
                (previous.phase, self.phase),
                (Phase::CreateIntent, Phase::Created)
                    | (Phase::Created, Phase::StartIntent)
                    | (Phase::Created | Phase::StartIntent, Phase::Finished)
            )
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(in crate::execution) fn record() -> Record {
        Record {
            schema_version: 1,
            attempt_id: uuid::Uuid::now_v7().to_string(),
            binding: proto::ManagedDeploymentBinding {
                installation_id: uuid::Uuid::now_v7().to_string(),
                target: Some(proto::RuntimeTarget {
                    workspace_id: "work".into(),
                    namespace_id: "ns".into(),
                    proxy_id: uuid::Uuid::now_v7().to_string(),
                    revision_id: uuid::Uuid::now_v7().to_string(),
                    generation: 1,
                    fencing_token: 1,
                }),
                process_instance_id: uuid::Uuid::now_v7().to_string(),
                config_hash: "a".repeat(64),
                launch_context_hash: "b".repeat(64),
            },
            container_id: "c".repeat(64),
            exec_id: String::new(),
            phase: Phase::CreateIntent,
        }
    }
    #[test]
    fn exec_intent_retains_original_binding_and_cannot_skip_start_intent() {
        let intent = record();
        intent.validate().unwrap();
        let mut created = intent.clone();
        created.phase = Phase::Created;
        created.exec_id = "d".repeat(64);
        created.validate().unwrap();
        assert!(created.follows(&intent));
        let mut start = created.clone();
        start.phase = Phase::StartIntent;
        assert!(start.follows(&created));
        assert!(!start.follows(&intent));
        let mut finished = start.clone();
        finished.phase = Phase::Finished;
        assert!(finished.follows(&start));
        assert!(!finished.follows(&intent));
        for mutation in 0..5 {
            let mut wrong = start.clone();
            match mutation {
                0 => wrong.attempt_id = uuid::Uuid::now_v7().to_string(),
                1 => wrong.binding.target.as_mut().unwrap().generation += 1,
                2 => wrong.container_id = "e".repeat(64),
                3 => wrong.exec_id = "e".repeat(64),
                4 => wrong.binding.launch_context_hash = "e".repeat(64),
                _ => unreachable!(),
            }
            assert!(!wrong.follows(&created));
        }
    }
    #[test]
    fn only_complete_terminal_history_can_begin_a_new_attempt() {
        let intent = record();
        let mut next = intent.clone();
        next.attempt_id = uuid::Uuid::now_v7().to_string();
        assert!(!next.follows(&intent));
        let mut finished = intent.clone();
        finished.phase = Phase::Finished;
        finished.exec_id = "d".repeat(64);
        assert!(next.follows(&finished));
        next.container_id = "e".repeat(64);
        assert!(!next.follows(&finished));
    }
}
