use super::{concurrency::*, *};
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn empty_and_invalid_inventories_never_dispatch() {
    let cancel = AtomicBool::new(false);
    let deadline = Instant::now() + WATCHDOG;
    let run = |_, _, _: &AtomicBool| -> Result<Zeroizing<Vec<u8>>, &'static str> {
        panic!("inventory must not dispatch")
    };
    assert!(
        inspect_batches(Kind::Network, ids(0), deadline, &cancel, &run)
            .unwrap()
            .is_empty()
    );
    for invalid in [ids(1025), BTreeSet::from(["invalid".into()])] {
        assert_eq!(
            inspect_batches(Kind::Container, invalid, deadline, &cancel, &run).unwrap_err(),
            ERROR
        );
    }
}

#[test]
fn maximum_inventory_and_partial_last_batch_are_complete() {
    for count in [1, 17, 65, 1024] {
        let calls = AtomicUsize::new(0);
        let result = inspect_batches(
            Kind::Network,
            ids(count),
            Instant::now() + WATCHDOG,
            &AtomicBool::new(false),
            &|args, _, _| {
                assert!((3..=18).contains(&args.len()));
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(output(&args))
            },
        )
        .unwrap();
        assert_eq!(
            result.into_iter().map(|item| item.0).collect::<Vec<_>>(),
            ids(count).into_iter().collect::<Vec<_>>()
        );
        assert_eq!(calls.load(Ordering::SeqCst), count.div_ceil(16));
    }
}

#[test]
fn aggregate_limit_is_inclusive_and_cannot_be_reset_per_wave() {
    for (count, accepted) in [(256, true), (272, false)] {
        let result = inspect_batches(
            Kind::Container,
            ids(count),
            Instant::now() + WATCHDOG,
            &AtomicBool::new(false),
            &|args, _, _| {
                let mut bytes = output(&args);
                // Valid JSON whitespace counts against raw aggregate output too.
                bytes.resize(262_144, b' ');
                Ok(bytes)
            },
        );
        assert_eq!(result.is_ok(), accepted);
        if let Ok(result) = result {
            assert_eq!(result.len(), 256);
        }
    }
}

#[test]
fn oversized_single_batch_fails_even_below_aggregate_limit() {
    assert!(
        inspect_batches(
            Kind::Container,
            ids(64),
            Instant::now() + WATCHDOG,
            &AtomicBool::new(false),
            &|args, _, _| {
                let mut bytes = output(&args);
                bytes.resize(262_145, b' ');
                Ok(bytes)
            }
        )
        .is_err()
    );
}
