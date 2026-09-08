use super::*;
use std::sync::{Mutex, atomic::Ordering, mpsc};

// A watchdog prevents deadlock under the serial implementation. It is not a
// throughput threshold: success requires four explicit arrivals before release.
pub(super) const WATCHDOG: Duration = Duration::from_secs(10);

pub(super) fn ids(count: usize) -> BTreeSet<String> {
    (0..count).rev().map(|id| format!("{id:064x}")).collect()
}

pub(super) fn output(args: &[String]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        serde_json::to_vec(
            &args[2..]
                .iter()
                .map(|id| serde_json::json!({"Id": id, "State": {"Running": false}}))
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    )
}

#[test]
fn four_batches_overlap_with_ordered_complete_output_and_at_most_four_in_flight() {
    let cancel = AtomicBool::new(false);
    let deadline = Instant::now() + WATCHDOG;
    let active = std::sync::atomic::AtomicUsize::new(0);
    let peak = std::sync::atomic::AtomicUsize::new(0);
    let (arrived, arrivals) = mpsc::channel();
    let releases: Vec<_> = (0..8).map(|_| mpsc::channel::<()>()).collect();
    let permits: Vec<_> = releases
        .into_iter()
        .map(|(send, receive)| (send, Mutex::new(receive)))
        .collect();
    std::thread::scope(|scope| {
        let owner = scope.spawn(|| {
            inspect_batches(
                Kind::Container,
                ids(128),
                deadline,
                &cancel,
                &|args, d, c| {
                    assert_eq!(d, deadline);
                    assert!(std::ptr::eq(c, &cancel));
                    assert_eq!(&args[..2], ["container", "inspect"]);
                    assert_eq!(args.len(), 18);
                    let batch = usize::from_str_radix(&args[2], 16).unwrap() / 16;
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(current, Ordering::SeqCst);
                    arrived.send(batch).unwrap();
                    let released = permits[batch].1.lock().unwrap().recv_timeout(WATCHDOG);
                    active.fetch_sub(1, Ordering::SeqCst);
                    released.map_err(|_| "BATCH_LATCH_WATCHDOG")?;
                    Ok(output(&args))
                },
            )
        });
        let mut batches = Vec::new();
        for _ in 0..2 {
            let mut wave = Vec::new();
            for _ in 0..4 {
                match arrivals.recv_timeout(WATCHDOG) {
                    Ok(batch) => wave.push(batch),
                    Err(_) => break,
                }
            }
            // Release even on failure so the RED run retains no blocked sibling.
            if wave.len() != 4 {
                for (send, _) in &permits {
                    let _ = send.send(());
                }
                let _ = owner.join();
                panic!("four batches must arrive before any batch is released");
            }
            assert_eq!(active.load(Ordering::SeqCst), 4);
            for &batch in wave.iter().rev() {
                permits[batch].0.send(()).unwrap();
            }
            batches.extend(wave);
        }
        let result = owner.join().unwrap().unwrap();
        batches.sort_unstable();
        assert_eq!(batches, (0..8).collect::<Vec<_>>());
        assert_eq!(peak.load(Ordering::SeqCst), 4);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        let expected: Vec<_> = ids(128).into_iter().collect();
        assert_eq!(
            result.iter().map(|item| &item.0).collect::<Vec<_>>(),
            expected.iter().collect::<Vec<_>>()
        );
        for (id, bytes) in result {
            let parsed = inspect::Json::parse(&bytes).unwrap();
            assert_eq!(parsed.0[0]["Id"], id);
            assert_eq!(parsed.0[0]["State"]["Running"], false);
        }
    });
}
