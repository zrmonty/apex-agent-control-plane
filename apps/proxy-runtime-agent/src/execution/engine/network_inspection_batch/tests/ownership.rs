use super::{concurrency::*, *};
use std::sync::{Mutex, atomic::AtomicUsize, atomic::Ordering, mpsc};

struct Completed<'a>(&'a AtomicUsize, &'a mpsc::Sender<usize>, usize);
impl Drop for Completed<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
        let _ = self.1.send(self.2);
    }
}

#[derive(Clone, Copy, Debug)]
enum Failure {
    Command,
    Panic,
    Missing,
    Malformed,
    Duplicate,
    Spawn,
}

fn retains_siblings(failure: Failure) {
    let count = if matches!(failure, Failure::Spawn) {
        2
    } else {
        4
    };
    let cancel = AtomicBool::new(false);
    let deadline = Instant::now() + WATCHDOG;
    let completed = AtomicUsize::new(0);
    let (entered, arrivals) = mpsc::channel();
    let (finished, completions) = mpsc::channel();
    let (returned, returns) = mpsc::channel();
    let permits: Vec<_> = (0..4)
        .map(|_| {
            let (send, receive) = mpsc::channel::<()>();
            (send, Mutex::new(receive))
        })
        .collect();
    std::thread::scope(|scope| {
        let owner = scope.spawn(|| {
            let _refusal = matches!(failure, Failure::Spawn).then(|| spawning::after(2));
            // Five batches: failure must prevent a later wave from starting.
            let result =
                inspect_batches(Kind::Network, ids(80), deadline, &cancel, &|args, d, c| {
                    assert_eq!(d, deadline);
                    assert!(std::ptr::eq(c, &cancel));
                    assert_eq!(&args[..2], ["network", "inspect"]);
                    let batch = usize::from_str_radix(&args[2], 16).unwrap() / 16;
                    let _completed = Completed(&completed, &finished, batch);
                    entered.send(batch).unwrap();
                    permits[batch]
                        .1
                        .lock()
                        .unwrap()
                        .recv_timeout(WATCHDOG)
                        .map_err(|_| "BATCH_LATCH_WATCHDOG")?;
                    if batch == 0 {
                        match failure {
                            Failure::Command => return Err("EXPECTED_COMMAND_FAILURE"),
                            Failure::Panic => panic!("expected batch worker panic"),
                            Failure::Missing => return Ok(Zeroizing::new(b"[]".to_vec())),
                            Failure::Malformed => return Ok(Zeroizing::new(b"{".to_vec())),
                            Failure::Duplicate => {
                                let mut objects: Vec<_> = args[2..]
                                    .iter()
                                    .map(|id| format!(r#"{{"Id":"{id}"}}"#))
                                    .collect();
                                objects[0] =
                                    format!(r#"{{"Id":"{}","Id":"{}"}}"#, args[2], args[2]);
                                return Ok(Zeroizing::new(
                                    format!("[{}]", objects.join(",")).into_bytes(),
                                ));
                            }
                            Failure::Spawn => {}
                        }
                    }
                    Ok(output(&args))
                });
            returned.send(completed.load(Ordering::SeqCst)).unwrap();
            result
        });
        let mut seen: Vec<_> = (0..count)
            .map(|_| arrivals.recv_timeout(WATCHDOG).unwrap())
            .collect();
        seen.sort_unstable();
        assert_eq!(seen, (0..count).collect::<Vec<_>>());
        permits[0].0.send(()).unwrap();
        assert_eq!(completions.recv_timeout(WATCHDOG).unwrap(), 0);
        assert!(matches!(returns.try_recv(), Err(mpsc::TryRecvError::Empty)));
        // The failed/panicked worker has completed; siblings remain latched until
        // explicitly released. The returned snapshot must include every sibling.
        for batch in (1..count).rev() {
            permits[batch].0.send(()).unwrap();
        }
        assert_eq!(returns.recv_timeout(WATCHDOG).unwrap(), count);
        let error = owner
            .join()
            .expect("worker panic must become refusal")
            .unwrap_err();
        assert_eq!(
            error,
            if matches!(failure, Failure::Command) {
                "EXPECTED_COMMAND_FAILURE"
            } else {
                ERROR
            }
        );
        assert_eq!(completed.load(Ordering::SeqCst), count);
        assert!(matches!(
            arrivals.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    });
}

#[test]
fn batch_failure_and_panic_join_every_sibling_before_refusal() {
    for failure in [Failure::Command, Failure::Panic] {
        retains_siblings(failure);
    }
}

#[test]
fn incomplete_malformed_or_duplicate_batch_invalidates_whole_inventory() {
    for failure in [Failure::Missing, Failure::Malformed, Failure::Duplicate] {
        retains_siblings(failure);
    }
}

#[test]
fn thread_creation_refusal_retains_already_started_siblings() {
    retains_siblings(Failure::Spawn);
}
