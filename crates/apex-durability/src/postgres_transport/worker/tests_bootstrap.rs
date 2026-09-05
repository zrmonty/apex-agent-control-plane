use super::*;
use crate::postgres_transport::TransportMode;
use std::sync::atomic::AtomicUsize;

fn healthy_primary_does_not_resolve_backup(primary: &str) {
    let peer = Blackhole::new(Stall::Query);
    let backup_calls = Arc::new(AtomicUsize::new(0));
    let counted = backup_calls.clone();
    let (release, released) = mpsc::channel();
    let (resolver, thread) = start_resolver(move |host| {
        if host == "backup.invalid" {
            counted.fetch_add(1, Ordering::Relaxed);
            let _ = released.recv();
        } else {
            assert_eq!(host, "primary.invalid");
        }
        Ok(vec!["127.0.0.1".parse().unwrap()])
    })
    .unwrap();
    let guard = ResolverGuard {
        resolver: Some(resolver),
        release,
        thread: Some(thread),
    };
    let config = format!(
        "host={primary},backup.invalid port={} user=deadline sslmode=disable",
        peer.address.port(),
    )
    .parse()
    .unwrap();
    let start = Instant::now();
    let connected = WorkerPostgresClient::connect_config(
        config,
        TransportMode::LoopbackPlaintext,
        guard.resolver.as_ref(),
    );
    let elapsed = start.elapsed();
    // Release a RED lookup before assertions unwind and join its owned thread.
    drop(guard);
    let client = connected.expect("a healthy primary must connect before backup DNS is required");
    assert!(elapsed < Duration::from_secs(2));
    assert_eq!(backup_calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        peer.events.recv_timeout(Duration::from_secs(1)).unwrap(),
        PeerEvent::Accepted
    );
    drop(client);
    assert_eq!(
        peer.events.recv_timeout(Duration::from_secs(1)).unwrap(),
        PeerEvent::Closed
    );
}

#[test]
fn healthy_numeric_primary_does_not_wait_for_blocked_backup_dns() {
    healthy_primary_does_not_resolve_backup("127.0.0.1");
}

#[test]
fn healthy_hostname_primary_does_not_wait_for_blocked_backup_dns() {
    healthy_primary_does_not_resolve_backup("primary.invalid");
}

#[test]
fn stalled_trust_loader_is_inside_connect_deadline_and_blocks_no_caller_cleanup() {
    let peer = Blackhole::new(Stall::Startup);
    let config = format!(
        "host=127.0.0.1 port={} user=deadline sslmode=require",
        peer.address.port()
    )
    .parse()
    .unwrap();
    let (started, observed) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let (completed, completion) = mpsc::channel();
    // A deliberately stuck loader must not starve parallel TLS controls through
    // the production singleton. This fixture owns/releases/joins its executor.
    let (bootstrap, bootstrap_thread) = BootstrapIo::start().unwrap();
    let caller_bootstrap = bootstrap.clone();
    let thread = thread::spawn(move || {
        let start = Instant::now();
        let result = WorkerPostgresClient::connect_config_with_bootstrap(
            config,
            TransportMode::VerifiedTls,
            None,
            Some(&caller_bootstrap),
            move || {
                let _ = started.send(());
                let _ = released.recv();
                Ok(rustls::RootCertStore::empty())
            },
        );
        let result = result.map(drop);
        let _ = completed.send((result, start.elapsed()));
    });
    let guard = LoaderCallerGuard {
        release,
        thread: Some(thread),
        bootstrap: Some(bootstrap),
        bootstrap_thread: Some(bootstrap_thread),
    };
    observed
        .recv_timeout(Duration::from_secs(1))
        .expect("trust loader did not start");
    let queued_calls = Arc::new(AtomicUsize::new(0));
    let mut queued = Vec::new();
    let executor = guard.bootstrap.as_ref().unwrap();
    for _ in 0..16 {
        let counted = queued_calls.clone();
        queued.push(
            executor
                .request(
                    move || {
                        counted.fetch_add(1, Ordering::Relaxed);
                        Ok(rustls::RootCertStore::empty())
                    },
                    Instant::now(),
                )
                .unwrap(),
        );
    }
    let start = Instant::now();
    assert!(matches!(
        executor.request(|| Ok(rustls::RootCertStore::empty()), Instant::now()),
        Err(WorkerPostgresError::Closed)
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
    let outcome = completion.recv_timeout(TEST_LIMIT);
    // The loader remains blocked until after the connect deadline assertion is
    // captured. This also releases/joins the old synchronous path when RED.
    drop(guard);
    let (result, elapsed) = outcome.expect("connect/runtime cleanup waited for stalled trust I/O");
    assert!(matches!(result, Err(WorkerPostgresError::Deadline)));
    assert!(elapsed < TEST_LIMIT);
    assert_eq!(queued_calls.load(Ordering::Relaxed), 0);
    for mut reply in queued {
        assert!(matches!(
            reply.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        ));
    }
    assert!(
        peer.events.try_recv().is_err(),
        "expired trust loading must not dispatch PostgreSQL"
    );
}

struct LoaderCallerGuard {
    release: mpsc::Sender<()>,
    thread: Option<JoinHandle<()>>,
    bootstrap: Option<BootstrapIo>,
    bootstrap_thread: Option<JoinHandle<()>>,
}

impl Drop for LoaderCallerGuard {
    fn drop(&mut self) {
        let _ = self.release.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.bootstrap.take();
        if let Some(thread) = self.bootstrap_thread.take() {
            let _ = thread.join();
        }
    }
}
