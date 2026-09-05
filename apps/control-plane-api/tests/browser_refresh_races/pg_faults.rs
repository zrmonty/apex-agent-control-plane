//! R1: supervise the actual observation helper in a child, so an unbounded
//! blocking PostgreSQL job cannot wedge this test binary or retain front 18461.
use super::{SERIAL, gate::RefreshGate, session, support::Pki};
use apex_control_plane_api::browser::security::LookupDigest;
use std::{
    net::TcpListener,
    panic::{AssertUnwindSafe, catch_unwind},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

#[path = "pg_blackhole.rs"]
mod blackhole;
use blackhole::{Blackhole, Event, Stall};

const CHILD_TEST: &str = "APEX_REFRESH_PG_FAULT_CHILD";
const CHILD_PORT: &str = "APEX_REFRESH_PG_FAULT_PORT";
const CHILD_LIMIT: Duration = Duration::from_secs(10);

#[test]
fn pg_startup_stall_bounds_runtime_drop_and_releases_gate() {
    run_case(
        Stall::Startup,
        "pg_faults::pg_startup_stall_bounds_runtime_drop_and_releases_gate",
    );
}

#[test]
fn pg_query_stall_bounds_runtime_drop_and_releases_gate() {
    run_case(
        Stall::Query,
        "pg_faults::pg_query_stall_bounds_runtime_drop_and_releases_gate",
    );
}

fn run_case(stall: Stall, name: &str) {
    if let Ok(selected) = std::env::var(CHILD_TEST) {
        assert_eq!(
            selected, name,
            "child must run only its selected fault case"
        );
        run_child();
        return;
    }
    let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    let peer = Blackhole::start(stall);
    // Child guard is created after the peer: rescue kills/reaps this exact
    // owned process before the fault endpoint can be closed during unwinding.
    let deadline = Instant::now() + CHILD_LIMIT;
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", name, "--test-threads=1"])
        .env(CHILD_TEST, name)
        .env(CHILD_PORT, peer.address.port().to_string())
        .env("APEX_ALLOW_POSTGRES_PLAINTEXT", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW, owned test child only.
    }
    let mut child = OwnedChild(Some(command.spawn().expect("start owned PG fault child")));
    let expected = match stall {
        Stall::Startup => Event::StartupWithheld,
        Stall::Query => Event::QueryWithheld,
    };
    assert_eq!(
        peer.events
            .recv_timeout(Duration::from_secs(3))
            .expect("child must reach the selected PG stall"),
        expected
    );
    let status = child.wait_before(deadline).expect(
        "R1: observation child exceeded 10s after a confirmed PG stall; killed and reaped only that child",
    );
    assert!(
        status.success(),
        "PG failure/fixture-drop assertions failed in owned child"
    );
    assert!(
        child.0.is_none(),
        "successful child must be reaped before returning"
    );
    // Observe EOF while the peer is still owned/live. Rescue teardown must not
    // supply the socket closure or make a broken timeout appear to pass.
    assert_eq!(
        peer.events.recv_timeout(Duration::from_secs(1)).unwrap(),
        Event::Closed
    );
    let rebound = TcpListener::bind("127.0.0.1:18461")
        .expect("child cleanup must release the real gate port");
    drop(rebound);
}

fn run_child() {
    let port_text = std::env::var(CHILD_PORT).expect("owned PG fault port");
    let port: u16 = port_text.parse().expect("numeric owned loopback PG port");
    assert!(port >= 1024 && port_text == port.to_string());
    let url = format!("host=127.0.0.1 port={port} user=e2_fault dbname=e2_fault sslmode=disable");
    let pki = Pki::require();
    let started = Instant::now();
    let failed = catch_unwind(AssertUnwindSafe(|| {
        let gate = RefreshGate::start(&pki);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(2)
            .build()
            .unwrap();
        // Reproduce the reviewed fixture's relevant Drop order using the real
        // gate and observation helper, with no IdP or database acceptance fake.
        let resources = RuntimeAndGate {
            runtime,
            _gate: gate,
        };
        resources
            .runtime
            .block_on(session::snapshot_at(url, LookupDigest::from_bytes([7; 32])));
    }));
    assert!(
        failed.is_err(),
        "withheld PostgreSQL response must fail the observation"
    );
    assert!(
        started.elapsed() < Duration::from_secs(7),
        "operation failure plus runtime/gate destruction must finish"
    );
    let rebound =
        TcpListener::bind("127.0.0.1:18461").expect("gate must be dropped before child exits");
    drop(rebound);
}

struct RuntimeAndGate {
    runtime: tokio::runtime::Runtime,
    _gate: RefreshGate,
}

struct OwnedChild(Option<Child>);
impl OwnedChild {
    fn wait_before(&mut self, deadline: Instant) -> Result<ExitStatus, ()> {
        loop {
            if Instant::now() >= deadline {
                self.kill_and_reap();
                return Err(());
            }
            if let Some(status) = self
                .0
                .as_mut()
                .unwrap()
                .try_wait()
                .expect("poll owned PG child")
            {
                self.0.take(); // try_wait reaped it; no detached waiter or PID kill.
                return Ok(status);
            }
            // Process supervision only; actual protocol bytes arrange the fault.
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn kill_and_reap(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            child.wait().expect("reap only the owned PG fault child");
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}
