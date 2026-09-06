//! Component scheduling only. The backend below is not PostgreSQL or authority.
use super::*;

#[test]
fn work_is_created_used_and_destroyed_on_one_physical_owner() {
    let thread = Arc::new(std::sync::Mutex::new(None));
    let observed = Arc::clone(&thread);
    let mut owner = Owner::new().unwrap();
    let client = owner
        .start(move || {
            *observed.lock().unwrap() = Some(std::thread::current().id());
            Ok((5, std::rc::Rc::new(()))) // !Send backend never crosses the thread.
        })
        .unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let value = runtime
        .block_on(client.request(
            Instant::now(),
            Duration::from_secs(1),
            Arc::new(|| Ok(())),
            move |store, check| {
                check()?;
                assert_eq!(*thread.lock().unwrap(), Some(std::thread::current().id()));
                store.0 += 1;
                Ok(store.0)
            },
        ))
        .unwrap();
    assert_eq!(value, 6);
    assert!(
        runtime
            .block_on(client.request::<()>(
                Instant::now() - Duration::from_secs(2),
                Duration::from_secs(1),
                Arc::new(|| Ok(())),
                |_, _| panic!("expired job must not run")
            ))
            .is_err()
    );
    drop(runtime);
    owner.shutdown().unwrap();
}

#[test]
fn cancelled_and_queued_work_retains_every_physical_slot_until_cleanup() {
    let mut owner = Owner::new().unwrap();
    let (release, held) = std::sync::mpsc::sync_channel(1);
    let (entered, observed) = std::sync::mpsc::sync_channel(1);
    let client = owner.start(|| Ok(())).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let first = client.clone();
    let active = runtime.spawn(async move {
        first
            .request(
                Instant::now(),
                Duration::from_secs(10),
                Arc::new(|| Ok(())),
                move |_, _| {
                    entered.send(()).unwrap();
                    held.recv().unwrap();
                    Ok(())
                },
            )
            .await
    });
    observed.recv_timeout(Duration::from_secs(2)).unwrap();
    active.abort();
    assert!(runtime.block_on(active).is_err());
    assert_eq!(client.inner.slots.available_permits(), 7);
    let mut queued = Vec::new();
    for _ in 0..7 {
        let client = client.clone();
        queued.push(runtime.spawn(async move {
            client
                .request::<()>(
                    Instant::now(),
                    Duration::from_secs(10),
                    Arc::new(|| Ok(())),
                    |_, _| panic!("cancelled queued work must never dispatch"),
                )
                .await
        }));
    }
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), async {
            while client.inner.slots.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            client
                .request::<()>(
                    Instant::now(),
                    Duration::from_secs(10),
                    Arc::new(|| Ok(())),
                    |_, _| panic!("no capacity")
                )
                .await
                .is_err()
        );
        for pending in queued {
            pending.abort();
            assert!(pending.await.is_err());
        }
    });
    assert_eq!(client.inner.slots.available_permits(), 0);
    owner.stop.store(true, std::sync::atomic::Ordering::Release);
    release.send(()).unwrap();
    owner.shutdown().unwrap();
    assert_eq!(client.inner.slots.available_permits(), 8);
    drop(runtime);
}
