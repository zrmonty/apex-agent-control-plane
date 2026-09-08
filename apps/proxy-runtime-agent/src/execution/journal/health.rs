//! Separate exec history: health writes never alter immutable deployment records.
use super::{Journal, document};
use crate::{
    execution::health_record::{ERROR, Phase, Record},
    proto,
};
type History = std::collections::BTreeMap<String, Option<Record>>;
#[derive(Default)]
pub(super) struct State {
    seen: History,
}

impl Journal {
    pub(in crate::execution) fn health_record(
        &self,
        binding: &proto::ManagedDeploymentBinding,
    ) -> Result<Option<Record>, &'static str> {
        let mut state = self.health_lock.lock().map_err(|_| ERROR)?;
        self.load_health(binding, &mut state)
    }
    pub(in crate::execution) fn health_transition(
        &self,
        previous: Option<&Record>,
        next: &Record,
    ) -> Result<(), &'static str> {
        next.validate()?;
        let mut state = self.health_lock.lock().map_err(|_| ERROR)?;
        if self.load_health(&next.binding, &mut state)?.as_ref() != previous
            || previous.map_or(next.phase != Phase::CreateIntent, |p| !next.follows(p))
        {
            return Err(ERROR);
        }
        let name = health_name(&next.binding)?;
        // A fresh read must not turn an uncertain write into permission to start.
        state.seen.insert(name.clone(), None);
        document::save(&self.root, &name, next, 16_384, Record::validate).map_err(|_| ERROR)?;
        state.seen.insert(name, Some(next.clone()));
        Ok(())
    }
    fn load_health(
        &self,
        binding: &proto::ManagedDeploymentBinding,
        state: &mut State,
    ) -> Result<Option<Record>, &'static str> {
        let name = health_name(binding)?;
        if state.seen.get(&name).is_some_and(Option::is_none)
            || (!state.seen.contains_key(&name) && state.seen.len() >= 4096)
        {
            return Err(ERROR);
        }
        let value = document::load(&self.root, &name, 16_384, Record::validate).map_err(|_| ERROR);
        let value = match value {
            Ok(value) => value,
            Err(e) => {
                state.seen.insert(name, None);
                return Err(e);
            }
        };
        if state
            .seen
            .get(&name)
            .is_some_and(|previous| previous != &value)
        {
            state.seen.insert(name, None);
            return Err(ERROR);
        }
        if value.as_ref().is_some_and(|v| &v.binding != binding) {
            return Err(ERROR);
        }
        if let Some(record) = &value {
            state.seen.insert(name, Some(record.clone()));
        }
        Ok(value)
    }
}
fn health_name(binding: &proto::ManagedDeploymentBinding) -> Result<String, &'static str> {
    if !crate::shapes::uuid_v7(&binding.process_instance_id) {
        return Err(ERROR);
    }
    Ok(format!("health-exec-{}.json", binding.process_instance_id))
}
#[cfg(test)]
mod tests;
