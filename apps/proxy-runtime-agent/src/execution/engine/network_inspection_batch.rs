//! Bounded read-only inventory batches; each object still uses the existing inspectors.
use super::*;
use std::collections::BTreeSet;

const BATCH: usize = 16;
const CONCURRENT_BATCHES: usize = 4;
pub(super) enum Kind {
    Network,
    Container,
}
type Observations = Vec<(String, Zeroizing<Vec<u8>>)>;

impl Engine {
    pub(super) fn inspect_many(
        &self,
        kind: Kind,
        ids: BTreeSet<String>,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Observations, &'static str> {
        inspect_batches(kind, ids, deadline, cancel, &|args, deadline, cancel| {
            self.run(args, deadline, cancel)
        })
    }
}

// Private command boundary, shared by production and deterministic batch tests.
fn inspect_batches(
    kind: Kind,
    ids: BTreeSet<String>,
    deadline: Instant,
    cancel: &AtomicBool,
    run: &(
         impl Fn(Vec<String>, Instant, &AtomicBool) -> Result<Zeroizing<Vec<u8>>, &'static str> + Sync
     ),
) -> Result<Observations, &'static str> {
    if ids.len() > 1024 || ids.iter().any(|id| !shapes::hex_hash(id)) {
        return Err(ERROR);
    }
    let command = match kind {
        Kind::Network => "network",
        Kind::Container => "container",
    };
    let ids: Vec<_> = ids.into_iter().collect();
    let mut result = Vec::new();
    let mut total = 0usize;
    #[cfg(test)]
    let hooks = crate::execution::testing::current();
    for wave in ids.chunks(BATCH * CONCURRENT_BATCHES) {
        let outputs = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(CONCURRENT_BATCHES);
            let mut failure = None;
            for batch in wave.chunks(BATCH) {
                let mut args = vec![command.into(), "inspect".into()];
                args.extend_from_slice(batch);
                #[cfg(test)]
                if tests::spawning::refuse_spawn() {
                    failure = Some(ERROR);
                    break;
                }
                // Fallible creation keeps already-started work owned on refusal.
                // run retains the original absolute deadline, external cancellation,
                // 256KiB limit and physical child ownership through kill/reap.
                #[cfg(test)]
                let hooks = hooks.as_ref();
                match std::thread::Builder::new().spawn_scoped(scope, move || {
                    #[cfg(test)]
                    let _hooks = hooks.map(crate::execution::testing::enter);
                    run(args, deadline, cancel)
                }) {
                    Ok(handle) => handles.push(handle),
                    Err(_) => {
                        failure = Some(ERROR);
                        break;
                    }
                }
            }
            let mut outputs = Vec::with_capacity(handles.len());
            // Never short-circuit joins: errors and panics still retain siblings.
            // Joining in input order also makes result/error selection canonical.
            for handle in handles {
                match handle.join().unwrap_or(Err(ERROR)) {
                    Ok(bytes) => outputs.push(bytes),
                    Err(error) => {
                        failure.get_or_insert(error);
                    }
                }
            }
            failure.map_or(Ok(outputs), Err)
        })?;
        for (batch, bytes) in wave.chunks(BATCH).zip(outputs) {
            total = total.checked_add(bytes.len()).ok_or(ERROR)?;
            if total > 4_194_304 {
                return Err(ERROR);
            }
            result.extend(split(&bytes, batch)?);
        }
    }
    Ok(result)
}

fn split(bytes: &[u8], ids: &[String]) -> Result<Observations, &'static str> {
    if ids.is_empty() || ids.len() > BATCH {
        return Err(ERROR);
    }
    // Decode BEFORE serialization: duplicate keys, oversized/deep input never normalize away.
    let parsed = inspect::Json::parse(bytes)?;
    let array = parsed
        .0
        .as_array()
        .filter(|a| a.len() == ids.len())
        .ok_or(ERROR)?;
    array
        .iter()
        .zip(ids)
        .map(|(value, id)| {
            if !shapes::hex_hash(id) || value["Id"] != *id {
                return Err(ERROR);
            }
            let single = Zeroizing::new(serde_json::to_vec(&[value]).map_err(|_| ERROR)?);
            inspect::Json::parse(&single)?;
            Ok((id.clone(), single))
        })
        .collect()
}

#[cfg(test)]
mod tests;
