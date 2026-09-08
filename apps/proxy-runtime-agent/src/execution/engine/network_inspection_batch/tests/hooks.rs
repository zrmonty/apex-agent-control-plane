use super::{concurrency::*, *};
use crate::execution::testing::{self, Hooks, Point};
use std::sync::Arc;

#[test]
fn scoped_batches_preserve_preflight_and_real_spawn_fault_injection_and_traces() {
    for point in [Point::Preflight, Point::Spawn] {
        let hooks = Arc::new(Hooks::default());
        let _installed = testing::enter(&hooks);
        let mut gate = hooks.arm(point);
        let cancel = AtomicBool::new(false);
        let deadline = Instant::now() + WATCHDOG;
        std::thread::scope(|scope| {
            let release = scope.spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                    .unwrap();
                let reached = runtime
                    .block_on(async { tokio::time::timeout(WATCHDOG, &mut gate.reached).await })
                    .expect("inherited hook must reach the armed gate")
                    .unwrap();
                assert_eq!(
                    reached,
                    if point == Point::Preflight {
                        Some(deadline)
                    } else {
                        None
                    }
                );
                // Existing Gate's Drop also releases a failing gate on watchdog/panic.
                gate.release(true);
            });
            let result = inspect_batches(
                Kind::Container,
                ids(64),
                deadline,
                &cancel,
                &|args, d, c| {
                    // Same private preflight boundary as Engine::run; Spawn below
                    // is exercised inside the unmodified real command owner.
                    testing::at(Point::Preflight, Some(d))?;
                    command::run_until(
                        CommandInput {
                            executable: Path::new("/bin/true"),
                            arguments: &[],
                            directory: Path::new("/"),
                            home: None,
                            budget: Duration::from_secs(30),
                            cancelled: c,
                        },
                        d,
                    )
                    .map(|_| output(&args))
                    .map_err(|_| "EXPECTED_SPAWN_REFUSAL")
                },
            );
            release.join().unwrap();
            assert_eq!(
                result.unwrap_err(),
                if point == Point::Preflight {
                    "RUNTIME_TEST_BOUNDARY_INTERRUPTED"
                } else {
                    "EXPECTED_SPAWN_REFUSAL"
                }
            );
        });
        assert_eq!(hooks.count(Point::Preflight), 4);
        assert_eq!(
            hooks.count(Point::Spawn),
            if point == Point::Preflight { 3 } else { 4 }
        );
        assert!(Arc::ptr_eq(&testing::current().unwrap(), &hooks));
    }
}
