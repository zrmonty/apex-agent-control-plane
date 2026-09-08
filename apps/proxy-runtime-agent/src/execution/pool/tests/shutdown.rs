//! Real authority RPC held at the shared final dispatch check, with a live waiter.
use super::*;
use crate::execution::{paired::transition::Gate, testing};
use std::{
    future::Future,
    task::{Context as TaskContext, Waker},
};
mod rpc;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::execution) enum Fault {
    None,
    Observation,
    Timeout,
    Cancel,
    ExpiredLease,
}

pub(in crate::execution) async fn schedule(
    resources: Resources,
    effect: impl FnOnce(
        &Engine,
        &mut dyn crate::command::Dispatch,
        &AtomicBool,
    ) -> Result<(), &'static str>
    + Send
    + 'static,
    shutdown: bool,
    fault: Fault,
) {
    let rpc = rpc::Fixture::start_with_lease(if fault == Fault::ExpiredLease {
        1
    } else {
        10_000_000
    })
    .await;
    // Setup failures must happen before a Facility owns a thread to join.
    let request = rpc.request().await;
    let (stop, stopped) = watch::channel(false);
    let context = Context {
        resources,
        authority: Arc::clone(&rpc.client),
        shared: Arc::new(Mutex::new(owner::State {
            metadata: Some(Arc::clone(&rpc.metadata)),
            read_started: Instant::now(),
            stopped: false,
        })),
        runtime: tokio::runtime::Handle::current(),
        installation: rpc::INSTALL.into(),
        shutdown: stopped,
    };
    let hooks = Arc::clone(&context.resources.hooks);
    let (sender, receiver) = mpsc::sync_channel::<Work>(1);
    let (sent_flag, flag) = oneshot::channel();
    let (sent_evidence, evidence) = oneshot::channel();
    let mut facility = Facility {
        sender: Some(sender),
        threads: vec![],
        slots: Arc::new(Semaphore::new(8)),
        active: Arc::new(Mutex::new(BTreeSet::new())),
        installation: rpc::INSTALL.into(),
    };
    facility.threads.push(std::thread::spawn(move || {
        let job = receiver.recv().unwrap();
        let Work::Reconcile(job) = job else {
            panic!("expected reconciliation")
        };
        let _scope = testing::enter(&context.resources.hooks);
        sent_flag.send(Arc::clone(&job.cancelled)).unwrap();
        let mut checked = None;
        // Same final callback and trailing deadline as paired::provision::recheck.
        // No injected shutdown error: the real checkpoint must detect the watch.
        let mut check = || {
            let result = provision::checkpoint(&context, &job, None).map(|_| ());
            checked = Some(result);
            result?;
            provision::deadline(&job)?;
            Ok(())
        };
        let deadline = || provision::deadline(&job);
        let mut gate = Gate {
            check: &mut check,
            deadline: &deadline,
            attempted: false,
        };
        let result = effect(&context.resources.engine, &mut gate, &job.cancelled);
        let attempted = gate.attempted;
        let cancelled = job.cancelled.load(Ordering::Acquire);
        let Job {
            reply,
            _permit,
            _proxy,
            ..
        } = job;
        drop(_proxy);
        drop(_permit);
        sent_evidence
            .send((result, checked, attempted, cancelled))
            .unwrap();
        let _ = reply.send(
            result
                .map(|()| proto::RuntimeReconcileResponse::default())
                .map_err(Status::unavailable),
        );
    }));
    let mut waiting = Box::pin(facility.execute(request));
    // No assertions, unwraps or panicking watchdogs while the callback is held.
    // Preserve every observation and its timeout for assertion after cleanup.
    let observations = tokio::time::timeout(Duration::from_secs(10), async {
        let pending_before = waiting
            .as_mut()
            .poll(&mut TaskContext::from_waker(Waker::noop()))
            .is_pending();
        let cancelled = flag.await.map_err(|_| "worker flag unavailable")?;
        rpc.entered
            .acquire()
            .await
            .map_err(|_| "callback unavailable")?
            .forget();
        let timeout = if fault == Fault::Timeout {
            tokio::time::timeout(Duration::ZERO, std::future::pending::<()>()).await
        } else {
            Ok(())
        };
        let spawn =
            hooks.count(testing::Point::NetworkSpawn) + usize::from(fault == Fault::Observation);
        let children = hooks.count(testing::Point::NetworkChild);
        let cancel_before = cancelled.load(Ordering::Acquire);
        let permits = facility.slots.available_permits();
        let active = facility.active.lock().map(|v| v.len()).ok();
        if shutdown {
            stop.send_replace(true);
        }
        if fault == Fault::Cancel {
            cancelled.store(true, Ordering::Release);
        }
        let pending_after = waiting
            .as_mut()
            .poll(&mut TaskContext::from_waker(Waker::noop()))
            .is_pending();
        let cancel_after = cancelled.load(Ordering::Acquire);
        Ok::<_, &'static str>((
            pending_before,
            pending_after,
            spawn,
            children,
            cancel_before,
            cancel_after,
            permits,
            active,
            timeout,
        ))
    })
    .await;
    if !matches!(&observations, Ok(Ok(_))) {
        stop.send_replace(true);
    }
    rpc.release.add_permits(1);
    let response = tokio::time::timeout(Duration::from_secs(10), waiting.as_mut()).await;
    // On a response timeout, cancellation and listener abort free the held RPC
    // while this current-thread runtime continues driving transport and timers.
    drop(waiting);
    let rpc_closed = rpc.close().await;
    facility.sender.take();
    let drained = tokio::time::timeout(Duration::from_secs(10), async {
        while facility.threads.iter().any(|thread| !thread.is_finished()) {
            tokio::task::yield_now().await;
        }
    })
    .await;
    if drained.is_err() {
        // Test-only fatal watchdog: unwinding into synchronous join would hang;
        // detaching/forgetting an unfinished physical owner is also forbidden.
        eprintln!("TASK4Y physical test worker failed to drain after RPC abort/cancellation");
        std::process::abort();
    }
    let permits_after = facility.slots.available_permits();
    let active_after = facility.active.lock().map(|v| v.len()).ok();
    drop(facility);
    let evidence = tokio::time::timeout(Duration::from_secs(1), evidence).await;
    assert!(rpc_closed.is_ok(), "RPC cleanup timeout");
    assert_eq!(permits_after, 8);
    assert_eq!(active_after, Some(0));
    eprintln!("TASK4Y cleanup drained: worker joined, slots=8, active=0, RPC closed");
    let (
        pending_before,
        pending_after,
        spawn,
        children,
        cancel_before,
        cancel_after,
        permits,
        active,
        timeout,
    ) = observations
        .expect("held RPC observation watchdog")
        .expect("held RPC observation unavailable");
    assert!(pending_before && pending_after);
    assert_eq!(children, 0);
    assert!(!cancel_before);
    assert_eq!(cancel_after, fault == Fault::Cancel);
    assert_eq!(permits, 7);
    assert_eq!(active, Some(1));
    let (result, checked, attempted, was_cancelled) = evidence
        .expect("worker evidence timeout")
        .expect("worker evidence unavailable");
    let response = response.expect("worker response timeout");
    assert_eq!(
        was_cancelled,
        fault == Fault::Cancel,
        "shutdown must not rely on dropping the waiting request"
    );
    eprintln!(
        "TASK4Y held-final-RPC shutdown={shutdown} check={checked:?} effect={result:?} attempted={attempted} children={}",
        hooks.count(testing::Point::NetworkChild)
    );
    if shutdown || matches!(fault, Fault::Cancel | Fault::ExpiredLease) {
        assert!(
            !attempted,
            "shutdown during final authority RPC authorized a spawn"
        );
        assert_eq!(hooks.count(testing::Point::NetworkChild), 0);
        if shutdown {
            assert_eq!(checked, Some(Err("RUNTIME_SHUTTING_DOWN")));
        } else if fault == Fault::Cancel {
            assert_eq!(checked, Some(Err("RUNTIME_CANCELLED")));
        } else {
            assert!(
                matches!(checked, Some(Err(_))),
                "expired actual RPC lease must refuse"
            );
        }
        assert_eq!(result, Err("RUNTIME_NETWORK_COMMAND_REFUSED"));
        assert_eq!(
            response.unwrap_err().message(),
            "RUNTIME_NETWORK_COMMAND_REFUSED"
        );
    } else {
        assert_eq!(checked, Some(Ok(())));
        assert_eq!(result, Ok(()));
        assert!(response.is_ok());
        assert!(attempted);
        assert_eq!(hooks.count(testing::Point::NetworkChild), 1);
    }
    // Fault regressions must also pass ownership and dispatch assertions above.
    assert_eq!(spawn, 1, "TASK4Y held observation mismatch");
    timeout.expect("TASK4Y held observation timeout");
}
