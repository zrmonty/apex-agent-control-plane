use super::endpoints::resolve_host;
use super::resolver::start_resolver;
use super::*;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[path = "tests_bootstrap.rs"]
mod bootstrap;
#[path = "tests_tls.rs"]
mod tls;

const TEST_LIMIT: Duration = Duration::from_secs(7);

#[derive(Debug, PartialEq, Eq)]
enum PeerEvent {
    Accepted,
    Closed,
}

#[derive(Clone, Copy)]
enum Stall {
    Startup,
    Query,
    Rollback,
}

/// A real loopback peer that accepts startup bytes but never answers them.
/// Nonblocking accept/read timeouts keep teardown bounded even on a RED panic.
struct Blackhole {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    events: mpsc::Receiver<PeerEvent>,
    thread: Option<JoinHandle<()>>,
}

impl Blackhole {
    fn new(stall: Stall) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let (sender, events) = mpsc::channel();
        let thread = thread::spawn(move || {
            let mut peer = loop {
                if stopping.load(Ordering::Relaxed) {
                    return;
                }
                match listener.accept() {
                    Ok((peer, _)) => break peer,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("loopback accept failed: {error}"),
                }
            };
            peer.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            if sender.send(PeerEvent::Accepted).is_err() {
                return;
            }
            let mut bytes = [0; 4096];
            let mut buffered = Vec::new();
            let mut startup_done = false;
            let mut begin_done = false;
            while !stopping.load(Ordering::Relaxed) {
                match peer.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(count) => {
                        // This fake peer only exercises transport deadlines. It does not
                        // implement PostgreSQL acceptance or persistence semantics.
                        if matches!(stall, Stall::Startup) {
                            continue;
                        }
                        if !startup_done {
                            buffered.extend_from_slice(&bytes[..count]);
                            if buffered.len() >= 4 {
                                let length = u32::from_be_bytes(buffered[..4].try_into().unwrap());
                                if buffered.len() >= usize::try_from(length).unwrap() {
                                    peer.write_all(b"R\0\0\0\x08\0\0\0\0Z\0\0\0\x05I").unwrap();
                                    startup_done = true;
                                    buffered.clear();
                                }
                            }
                        } else if matches!(stall, Stall::Rollback) && !begin_done {
                            buffered.extend_from_slice(&bytes[..count]);
                            if buffered.len() >= 5 {
                                let length = u32::from_be_bytes(buffered[1..5].try_into().unwrap());
                                if buffered.len() > usize::try_from(length).unwrap() {
                                    assert_eq!(buffered[0], b'Q');
                                    peer.write_all(b"C\0\0\0\x0aBEGIN\0Z\0\0\0\x05T").unwrap();
                                    begin_done = true;
                                    buffered.clear();
                                }
                            }
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                        ) =>
                    {
                        break;
                    }
                    Err(error) => panic!("loopback read failed: {error}"),
                }
            }
            if !stopping.load(Ordering::Relaxed) {
                let _ = sender.send(PeerEvent::Closed);
            }
        });
        Self {
            address,
            stop,
            events,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!(
            "host=127.0.0.1 port={} user=deadline dbname=deadline sslmode=disable",
            self.address.port()
        )
    }
}

impl Drop for Blackhole {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[test]
fn connect_deadline_closes_a_real_protocol_handshake_blackhole() {
    let peer = Blackhole::new(Stall::Startup);
    let start = Instant::now();
    let error = WorkerPostgresClient::connect_with_policy(&peer.url(), true).unwrap_err();
    assert!(matches!(error, WorkerPostgresError::Deadline), "{error:?}");
    assert!(
        start.elapsed() < TEST_LIMIT,
        "connect exceeded the whole-operation deadline"
    );
    assert!(
        start.elapsed() >= Duration::from_secs(4),
        "peer must actually stall startup"
    );
    assert_eq!(
        peer.events.recv_timeout(Duration::from_secs(1)).unwrap(),
        PeerEvent::Accepted
    );
    assert_eq!(
        peer.events.recv_timeout(Duration::from_secs(1)).unwrap(),
        PeerEvent::Closed,
        "returning a timeout must close the accepted socket"
    );
}

#[test]
fn query_deadline_aborts_the_driver_and_closes_the_real_socket() {
    let peer = Blackhole::new(Stall::Query);
    let mut client = WorkerPostgresClient::connect_with_policy(&peer.url(), true).unwrap();
    assert_eq!(
        peer.events.recv_timeout(Duration::from_secs(1)).unwrap(),
        PeerEvent::Accepted
    );
    let start = Instant::now();
    let error = client.query_one("SELECT 1", &[]).unwrap_err();
    assert!(matches!(error, WorkerPostgresError::Deadline));
    assert!(start.elapsed() < TEST_LIMIT);
    assert!(client.is_closed());
    assert_eq!(
        peer.events.recv_timeout(Duration::from_secs(1)).unwrap(),
        PeerEvent::Closed,
        "a timed-out request must not leave the driver/socket alive"
    );
    let start = Instant::now();
    assert!(matches!(
        client.batch_execute("SELECT 2"),
        Err(WorkerPostgresError::Closed)
    ));
    drop(client);
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn dropped_transaction_bounds_rollback_and_closes_the_real_socket() {
    let peer = Blackhole::new(Stall::Rollback);
    let mut client = WorkerPostgresClient::connect_with_policy(&peer.url(), true).unwrap();
    assert_eq!(
        peer.events.recv_timeout(Duration::from_secs(1)).unwrap(),
        PeerEvent::Accepted
    );
    let transaction = client.transaction().unwrap();
    let start = Instant::now();
    drop(transaction);
    assert!(
        start.elapsed() < TEST_LIMIT,
        "rollback Drop must have a whole-operation deadline"
    );
    assert!(client.is_closed());
    assert_eq!(
        peer.events.recv_timeout(Duration::from_secs(1)).unwrap(),
        PeerEvent::Closed
    );
}

#[test]
fn rejected_transport_does_not_expose_connection_credentials() {
    let error = WorkerPostgresClient::connect(
        "host=192.0.2.1 user=operator password=never-log-this sslmode=disable",
    )
    .unwrap_err();
    assert!(!format!("{error} {error:?}").contains("never-log-this"));
    assert!(error.code().is_none());
}

#[test]
fn database_error_format_and_source_do_not_expose_upstream_context() {
    let database_error = "host=127.0.0.1 password=never-log-this invalid_option=private-context"
        .parse::<postgres::Config>()
        .unwrap_err();
    let error = WorkerPostgresError::Database(database_error);
    assert_eq!(format!("{error:?}"), "Database");
    assert_eq!(
        error.to_string(),
        "PostgreSQL worker database operation failed"
    );
    assert!(
        std::error::Error::source(&error).is_none(),
        "source chains must not restore redacted PostgreSQL context"
    );
    for error in [WorkerPostgresError::Deadline, WorkerPostgresError::Closed] {
        assert!(std::error::Error::source(&error).is_none());
        assert!(error.code().is_none());
    }
}

#[test]
fn blocked_dns_deadline_bounds_connect_runtime_drop_and_resolver_queue() {
    let (started, observed) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = calls.clone();
    let (resolver, thread) = start_resolver(move |_| {
        counted.fetch_add(1, Ordering::Relaxed);
        let _ = started.send(());
        let _ = released.recv();
        Ok(vec!["127.0.0.1".parse().unwrap()])
    })
    .unwrap();
    // Scoped cleanup releases the OS-lookup stand-in even if an assertion fails.
    let guard = ResolverGuard {
        resolver: Some(resolver),
        release,
        thread: Some(thread),
    };
    let resolver = guard.resolver.as_ref().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut first = resolver.request("blocked.invalid", deadline).unwrap();
    observed.recv_timeout(Duration::from_secs(1)).unwrap();
    let start = Instant::now();
    let config = "host=worker-dns.invalid user=deadline sslmode=disable"
        .parse()
        .unwrap();
    let result = WorkerPostgresClient::connect_config(
        config,
        super::super::TransportMode::LoopbackPlaintext,
        Some(resolver),
    );
    assert!(matches!(result, Err(WorkerPostgresError::Deadline)));
    assert!(
        start.elapsed() < TEST_LIMIT,
        "runtime Drop must not wait for DNS"
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    // The timed-out connect still occupies one queued slot until the blocked
    // lookup is released. Fill the remaining 15 slots, then reject immediately.
    let mut queued = Vec::new();
    for _ in 0..15 {
        queued.push(resolver.request("queued.invalid", deadline).unwrap());
    }
    let start = Instant::now();
    assert!(matches!(
        resolver.request("overflow.invalid", deadline),
        Err(WorkerPostgresError::Closed)
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
    drop(guard);
    assert!(matches!(
        first.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Closed)
    ));
    for mut reply in queued {
        assert!(matches!(
            reply.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        ));
    }
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "expired/cancelled lookups must not dispatch"
    );
}

#[test]
fn resolved_addresses_preserve_tls_names_options_and_explicit_hostaddr_mapping() {
    use tokio_postgres::config::{
        ChannelBinding, Host, SslMode, SslNegotiation, TargetSessionAttrs,
    };
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = calls.clone();
    let (resolver, thread) = start_resolver(move |host| {
        assert_eq!(host, "primary.invalid");
        counted.fetch_add(1, Ordering::Relaxed);
        Ok(vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()])
    })
    .unwrap();
    let (release, _) = mpsc::channel();
    let guard = ResolverGuard {
        resolver: Some(resolver),
        release,
        thread: Some(thread),
    };
    let resolver = guard.resolver.as_ref().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let config = "host=primary.invalid,127.0.0.2 port=5541,5542 user=worker password=private \
        dbname=worker_db options='-c search_path=worker_schema' application_name=worker_test \
        sslmode=require sslnegotiation=direct channel_binding=require target_session_attrs=read-write"
        .parse().unwrap();
    let resolved = runtime
        .block_on(resolve_host(
            &config,
            0,
            Some(resolver),
            Instant::now() + DEADLINE,
        ))
        .unwrap();
    assert_eq!(
        resolved.get_hosts(),
        &[
            Host::Tcp("primary.invalid".into()),
            Host::Tcp("primary.invalid".into()),
        ]
    );
    assert_eq!(
        resolved.get_hostaddrs(),
        &[
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
            "::1".parse().unwrap(),
        ]
    );
    assert_eq!(resolved.get_ports(), &[5541, 5541]);
    assert_eq!(resolved.get_user(), Some("worker"));
    assert_eq!(resolved.get_password(), Some(b"private".as_slice()));
    assert_eq!(resolved.get_dbname(), Some("worker_db"));
    assert_eq!(resolved.get_application_name(), Some("worker_test"));
    assert_eq!(resolved.get_options(), Some("-c search_path=worker_schema"));
    assert_eq!(resolved.get_ssl_mode(), SslMode::Require);
    assert_eq!(resolved.get_ssl_negotiation(), SslNegotiation::Direct);
    assert_eq!(resolved.get_channel_binding(), ChannelBinding::Require);
    assert_eq!(
        resolved.get_target_session_attrs(),
        TargetSessionAttrs::ReadWrite
    );
    let numeric = runtime
        .block_on(resolve_host(
            &config,
            1,
            Some(resolver),
            Instant::now() + DEADLINE,
        ))
        .unwrap();
    assert_eq!(numeric.get_hosts(), &[Host::Tcp("127.0.0.2".into())]);
    assert_eq!(
        numeric.get_hostaddrs(),
        &["127.0.0.2".parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(numeric.get_ports(), &[5542]);
    let explicit = "host=primary.invalid,secondary.invalid hostaddr=127.0.0.3,127.0.0.4 \
        port=5543,5544 sslmode=require"
        .parse()
        .unwrap();
    let unchanged = runtime
        .block_on(resolve_host(
            &explicit,
            0,
            Some(resolver),
            Instant::now() + DEADLINE,
        ))
        .unwrap();
    assert_eq!(
        unchanged.get_hosts(),
        &[Host::Tcp("primary.invalid".into()),]
    );
    assert_eq!(
        unchanged.get_hostaddrs(),
        &["127.0.0.3".parse::<std::net::IpAddr>().unwrap(),]
    );
    assert_eq!(unchanged.get_ports(), &[5543]);
    let secondary = runtime
        .block_on(resolve_host(
            &explicit,
            1,
            Some(resolver),
            Instant::now() + DEADLINE,
        ))
        .unwrap();
    assert_eq!(
        secondary.get_hosts(),
        &[Host::Tcp("secondary.invalid".into())]
    );
    assert_eq!(
        secondary.get_hostaddrs(),
        &["127.0.0.4".parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(secondary.get_ports(), &[5544]);
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "numeric/explicit addresses must bypass DNS"
    );
}

struct ResolverGuard {
    resolver: Option<Resolver>,
    release: mpsc::Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for ResolverGuard {
    fn drop(&mut self) {
        let _ = self.release.send(());
        self.resolver.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
