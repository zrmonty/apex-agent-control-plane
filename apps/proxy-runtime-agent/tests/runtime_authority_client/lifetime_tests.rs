use apex_proxy_runtime_agent::authority::AuthorityClientError as Error;
use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use tokio::task::JoinSet;
use tonic::Code;

use super::{
    pki::{CONTROLLER, Pki},
    server::Fixture,
    support::*,
};

#[tokio::test]
async fn original_policy_expiring_during_callback_is_refused_at_handoff() {
    // Catches authorizing only before the network await and returning stale local policy evidence.
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    let mut caller = ingress_client(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    let short_policy = policy_for(&pki, "client-policy", false, Duration::from_secs(2));
    let expiry_wait = tokio::time::Instant::now() + Duration::from_millis(2_100);
    {
        let mut settings = fixture.incoming.settings.lock().unwrap();
        settings.policy = short_policy.clone();
        settings.budget = Duration::from_secs(5);
    }
    fixture.state.hold.store(true, Ordering::SeqCst);
    let release_after_expiry = async {
        fixture.state.wait_entered(1).await;
        // This sleep crosses an actual policy validity window, not a microsecond precision proof.
        tokio::time::sleep_until(expiry_wait).await;
        assert!(short_policy.check_current().is_err());
        fixture.state.release.add_permits(1);
    };
    let (result, ()) = tokio::join!(
        within(caller.check_runtime_authority(query())),
        release_after_expiry
    );
    assert_error(result.unwrap_err(), Error::Denied);
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 1);
    drop(caller);
    fixture.shutdown().await;
}

#[tokio::test]
async fn connect_deadline_includes_stalled_tls_and_owns_its_listener() {
    // Catches timing only TCP connect while TLS/readiness can hang forever.
    use apex_proxy_runtime_agent::authority::RuntimeAuthorityClient;
    use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
    struct OwnedTask(JoinHandle<()>);
    impl Drop for OwnedTask {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    let pki = Pki::require();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://{}", listener.local_addr().unwrap());
    let (accepted, arrival) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let mut task = OwnedTask(tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let _ = accepted.send(());
        let _ = released.await;
        drop(socket);
    }));
    let started = Instant::now();
    let (result, arrival) = tokio::join!(
        within(RuntimeAuthorityClient::connect(config(&pki, &endpoint))),
        within(arrival),
    );
    arrival.unwrap();
    assert_eq!(result.unwrap_err(), Error::Deadline);
    assert!(started.elapsed() < Duration::from_secs(7));
    let _ = release.send(());
    within(&mut task.0).await.unwrap();
}

#[tokio::test]
async fn held_response_deadline_drops_network_work_and_recovers_capacity() {
    // Catches timeouts that abandon an owner task or leave its permit occupied.
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    fixture.incoming.settings.lock().unwrap().budget = Duration::from_millis(300);
    fixture.state.hold.store(true, Ordering::SeqCst);
    let mut caller = ingress_client(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    let started = Instant::now();
    let (result, ()) = tokio::join!(
        within(caller.check_runtime_authority(query())),
        fixture.state.wait_entered(1),
    );
    assert_error(result.unwrap_err(), Error::Deadline);
    assert!(started.elapsed() < Duration::from_secs(2));
    fixture.state.wait_departed(1).await;
    assert_eq!(fixture.state.active.load(Ordering::SeqCst), 0);
    fixture.state.hold.store(false, Ordering::SeqCst);
    fixture.incoming.settings.lock().unwrap().budget = BUDGET;
    assert_eq!(
        within(caller.check_runtime_authority(query()))
            .await
            .unwrap()
            .into_inner(),
        snapshot()
    );
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 2);
    drop(caller);
    fixture.shutdown().await;
}

#[tokio::test]
async fn eight_held_checks_refuse_ninth_without_queue_and_cancellation_recovers_all_slots() {
    // Catches per-clone ceilings, unbounded admission queues and detached request ownership.
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    fixture.incoming.settings.lock().unwrap().budget = Duration::from_secs(5);
    fixture.state.hold.store(true, Ordering::SeqCst);
    let caller = ingress_client(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    // JoinSet owns these test callers and aborts every outstanding task on Drop.
    let mut calls = JoinSet::new();
    for _ in 0..8 {
        let mut caller = caller.clone();
        calls.spawn(async move { caller.check_runtime_authority(query()).await });
    }
    fixture.state.wait_entered(8).await;
    assert_eq!(fixture.state.active.load(Ordering::SeqCst), 8);
    let mut ninth = caller.clone();
    let started = Instant::now();
    assert_error(
        within(ninth.check_runtime_authority(query()))
            .await
            .unwrap_err(),
        Error::Overloaded,
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "overload must not wait for held replies"
    );
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 8);
    fixture.incoming.cancel.notify_waiters();
    while let Some(result) = within(calls.join_next()).await {
        assert_eq!(result.unwrap().unwrap_err().code(), Code::Cancelled);
    }
    fixture.state.wait_departed(8).await;
    assert_eq!(fixture.state.active.load(Ordering::SeqCst), 0);
    // Refilling the full ceiling, while holding responses again, proves all permits returned.
    for _ in 0..8 {
        let mut caller = caller.clone();
        calls.spawn(async move { caller.check_runtime_authority(query()).await });
    }
    fixture.state.wait_entered(8).await;
    assert_eq!(fixture.state.active.load(Ordering::SeqCst), 8);
    fixture.state.release.add_permits(8);
    while let Some(result) = within(calls.join_next()).await {
        assert_eq!(result.unwrap().unwrap().into_inner(), snapshot());
    }
    fixture.state.wait_departed(8).await;
    assert_eq!(fixture.state.calls.load(Ordering::SeqCst), 16);
    drop(ninth);
    drop(caller);
    fixture.shutdown().await;
}

#[tokio::test]
async fn arbitrarily_large_requested_budget_still_expires_at_five_seconds() {
    // Catches a caller extending the hard cap or overflowing Instant arithmetic.
    let pki = Pki::require();
    let fixture = Fixture::start(&pki).await;
    fixture.incoming.settings.lock().unwrap().budget = Duration::MAX;
    fixture.state.hold.store(true, Ordering::SeqCst);
    let mut caller = ingress_client(&pki, &fixture.ingress.endpoint, Some(CONTROLLER)).await;
    let started = Instant::now();
    let (result, ()) = tokio::join!(
        within(caller.check_runtime_authority(query())),
        fixture.state.wait_entered(1),
    );
    assert_error(result.unwrap_err(), Error::Deadline);
    assert!(started.elapsed() < Duration::from_secs(7));
    fixture.state.wait_departed(1).await;
    drop(caller);
    fixture.shutdown().await;
}
