use super::{BoundedProviderHttp, dns, test_peer::*};
use crate::browser::errors::BrowserError;
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Condvar, Mutex, mpsc},
    time::{Duration, Instant},
};

#[derive(Default)]
struct GateState {
    started: usize,
    finished: usize,
    released: bool,
}

#[derive(Default)]
struct LookupGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

impl LookupGate {
    fn lookup(&self, _host: &str) -> io::Result<Vec<SocketAddr>> {
        let mut state = self.state.lock().unwrap();
        state.started += 1;
        self.changed.notify_all();
        while !state.released {
            state = self.changed.wait(state).unwrap();
        }
        state.finished += 1;
        self.changed.notify_all();
        Ok(vec!["127.0.0.1:0".parse().unwrap()])
    }

    fn wait_started(&self, count: usize) {
        let state = self.state.lock().unwrap();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, Duration::from_secs(2), |state| state.started < count)
            .unwrap();
        assert!(state.started >= count, "admitted DNS work never started");
    }

    fn started(&self) -> usize {
        self.state.lock().unwrap().started
    }

    fn release(&self) {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .released = true;
        self.changed.notify_all();
    }
}

struct ReleaseOnDrop(Arc<LookupGate>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

fn controlled() -> (Arc<dns::Resolver>, Arc<LookupGate>, ReleaseOnDrop) {
    let gate = Arc::new(LookupGate::default());
    let worker_gate = Arc::clone(&gate);
    let resolver = dns::start_resolver(move |host| worker_gate.lookup(host))
        .expect("construct bounded DNS executor");
    let cleanup = ReleaseOnDrop(Arc::clone(&gate));
    (resolver, gate, cleanup)
}

#[test]
fn default_resolver_is_one_process_shared_executor() {
    let first = dns::global_resolver().expect("process DNS executor");
    let second = dns::global_resolver().expect("reuse process DNS executor");
    assert!(
        Arc::ptr_eq(&first, &second),
        "provider construction created another DNS pool"
    );
}

#[tokio::test]
async fn cancelled_receivers_do_not_release_running_dns_capacity_or_queue_more_work() {
    let (resolver, gate, _cleanup) = controlled();
    let other_provider = Arc::clone(&resolver);
    let deadline = Instant::now() + Duration::from_secs(5);
    let receivers: Vec<_> = (0..8)
        .map(|_| {
            resolver
                .request("blocked.invalid", deadline)
                .expect("admit eight DNS jobs")
        })
        .collect();
    gate.wait_started(8);
    drop(receivers);
    for _ in 0..16 {
        assert!(
            matches!(
                other_provider.request("overflow.invalid", deadline),
                Err(BrowserError::Unavailable)
            ),
            "cancelled callers reopened worker admission"
        );
    }
    assert_eq!(gate.started(), 8);
    gate.release();
    // Completion notification precedes dropping a worker permit. Retry admission
    // briefly; rejected attempts must never enqueue a lookup behind busy workers.
    let recovered = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(reply) = other_provider.request("recovered.invalid", deadline) {
                break reply.await;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("actual worker completion must restore admission");
    assert_eq!(
        recovered.unwrap().unwrap(),
        vec!["127.0.0.1:0".parse::<SocketAddr>().unwrap()]
    );
    assert_eq!(
        gate.started(),
        9,
        "rejected requests were queued and later dispatched"
    );
}

#[tokio::test]
async fn timed_out_dns_futures_keep_worker_admission_until_the_lookup_finishes() {
    let (resolver, gate, _cleanup) = controlled();
    let mut calls = tokio::task::JoinSet::new();
    let deadline = Instant::now() + Duration::from_millis(750);
    for _ in 0..8 {
        let resolver = Arc::clone(&resolver);
        calls.spawn(async move { resolver.lookup("timeout.invalid", deadline).await });
    }
    bounded(async {
        while gate.started() < 8 {
            // If the scaffold returns immediately, expose its semantic failure
            // rather than waiting for a worker that was never implemented.
            if let Some(result) = calls.try_join_next() {
                panic!(
                    "admitted lookup completed before dispatch: {:?}",
                    result.unwrap()
                );
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;
    while let Some(result) = bounded(calls.join_next()).await {
        assert!(matches!(result.unwrap(), Err(BrowserError::Unavailable)));
    }
    assert!(
        matches!(
            resolver.request("overflow.invalid", Instant::now() + Duration::from_secs(1)),
            Err(BrowserError::Unavailable)
        ),
        "timeout freed capacity while OS work was blocked"
    );
    assert_eq!(gate.started(), 8);
    assert_eq!(gate.state.lock().unwrap().finished, 0);
}

struct RuntimeCleanup {
    gate: Arc<LookupGate>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for RuntimeCleanup {
    fn drop(&mut self) {
        self.gate.release();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[test]
fn runtime_shutdown_does_not_wait_for_a_blocked_dns_worker() {
    let (resolver, gate, _release) = controlled();
    let (outcome, observed) = mpsc::channel();
    let (dropped, drop_observed) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(resolver.lookup(
            "runtime-drop.invalid",
            Instant::now() + Duration::from_millis(750),
        ));
        let _ = outcome.send(result);
        drop(runtime);
        let _ = dropped.send(());
    });
    // Unblock and join even when an assertion fails; a shared-blocking-pool
    // regression must fail this test without hanging the enclosing test runner.
    let _cleanup = RuntimeCleanup {
        gate: Arc::clone(&gate),
        thread: Some(thread),
    };
    gate.wait_started(1);
    assert!(matches!(
        observed.recv_timeout(Duration::from_secs(2)).unwrap(),
        Err(BrowserError::Unavailable)
    ));
    assert!(
        drop_observed
            .recv_timeout(Duration::from_millis(500))
            .is_ok(),
        "runtime shutdown waited for uncancellable DNS work"
    );
    assert_eq!(gate.state.lock().unwrap().finished, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn buffered_dns_answer_is_rejected_when_polled_after_its_wall_deadline() {
    let (resolver, gate, _cleanup) = controlled();
    let deadline = Instant::now() + Duration::from_millis(750);
    let lookup = resolver.lookup("buffered.invalid", deadline);
    tokio::pin!(lookup);
    tokio::select! {
        biased;
        _ = async {
            while gate.started() == 0 { tokio::task::yield_now().await; }
        } => {}
        _ = &mut lookup => panic!("DNS lookup completed before its controlled worker ran"),
    }
    gate.release();
    bounded(async {
        while gate.state.lock().unwrap().finished == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    // A returned answer can already be buffered in the oneshot channel.
    // Retain, rather than cancel, the lookup across the real wall deadline.
    std::thread::sleep(Duration::from_millis(800));
    assert!(matches!(
        bounded(lookup).await,
        Err(BrowserError::Unavailable)
    ));
}

#[test]
fn expired_dns_request_is_rejected_without_worker_admission() {
    let (resolver, gate, _cleanup) = controlled();
    assert!(matches!(
        resolver.request("expired.invalid", Instant::now() - Duration::from_millis(1)),
        Err(BrowserError::Unavailable)
    ));
    assert_eq!(gate.started(), 0);
}

fn hostname_config(peer: &Peer, hostname: &str) -> super::super::config::OidcConfig {
    let mut config = peer.config();
    for value in [
        &mut config.issuer,
        &mut config.authorization_endpoint,
        &mut config.token_endpoint,
        &mut config.jwks_uri,
        &mut config.revocation_endpoint,
    ] {
        *value = value.replace("127.0.0.1", hostname);
    }
    config
}

#[tokio::test]
async fn custom_dns_preserves_configured_hostname_ca_and_port_on_real_https() {
    let names = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&names);
    let resolver = dns::start_resolver(move |host| {
        observed.lock().unwrap().push(host.to_owned());
        Ok(vec!["127.0.0.1:0".parse().unwrap()])
    })
    .unwrap();
    let peer = Peer::start(Vec::new()).await;
    let config = hostname_config(&peer, "localhost");
    let http = BoundedProviderHttp::with_resolver(&config, Some(Arc::clone(&resolver))).unwrap();
    assert_eq!(bounded(http.discovery()).await.unwrap(), JSON);
    assert_eq!(
        peer.requests()[0].header("host"),
        Some(format!("localhost:{}", peer.address.port()).as_str())
    );
    assert_eq!(
        names.lock().unwrap().first().map(String::as_str),
        Some("localhost")
    );

    let wrong_name = hostname_config(&peer, "wrong-name.invalid");
    let http =
        BoundedProviderHttp::with_resolver(&wrong_name, Some(Arc::clone(&resolver))).unwrap();
    assert!(matches!(
        bounded(http.discovery()).await,
        Err(BrowserError::Unavailable)
    ));
    assert_eq!(
        peer.requests().len(),
        1,
        "DNS substitution bypassed TLS name verification"
    );

    let untrusted = Peer::start_at("127.0.0.1", "untrusted-host", Vec::new()).await;
    let config = hostname_config(&untrusted, "localhost");
    let http = BoundedProviderHttp::with_resolver(&config, Some(resolver)).unwrap();
    assert!(matches!(
        bounded(http.discovery()).await,
        Err(BrowserError::Unavailable)
    ));
    assert!(
        untrusted.requests().is_empty(),
        "DNS substitution bypassed the configured CA"
    );
}

#[tokio::test]
async fn dns_worker_errors_are_closed_and_do_not_disclose_host_or_source_detail() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let resolver = dns::start_resolver(move |_| {
        observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(io::Error::other("resolver-secret-canary"))
    })
    .unwrap();
    let error = resolver
        .lookup(
            "host-secret-canary.invalid",
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap_err();
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "resolver worker was not exercised"
    );
    assert_eq!(error, BrowserError::Unavailable);
    assert!(!format!("{error:?} {error}").contains("canary"));
    assert!(std::error::Error::source(&error).is_none());
}
