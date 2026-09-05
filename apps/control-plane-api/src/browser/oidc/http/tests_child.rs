use super::child::wait_child;
use std::{
    io::{Read, Write},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};

const CHILD_MODE: &str = "APEX_OIDC_WATCHDOG_CHILD";

// A real child of the current test binary; no external shell, PID-based kill,
// process-global env edits, filesystem marker, or unbounded captured output.
#[test]
fn watchdog_child_fixture() {
    let Ok(address) = std::env::var(CHILD_MODE) else {
        return;
    };
    let mut stream = std::net::TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    stream.write_all(b"READY").unwrap();
    let _ = stream.read(&mut [0]); // Parent holds the socket while checking cleanup.
}

struct Fixture {
    child: Arc<Mutex<Child>>,
    connection: Option<TcpStream>,
}

impl Fixture {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "browser::oidc::http::tests_child::watchdog_child_fixture",
                "--nocapture",
            ])
            .env(CHILD_MODE, listener.local_addr().unwrap().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // Own cleanup before awaiting readiness, including a fixture setup failure.
        let mut fixture = Self {
            child: Arc::new(Mutex::new(child)),
            connection: None,
        };
        let (mut connection, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
            .await
            .expect("child did not connect")
            .unwrap();
        let mut ready = [0; 5];
        tokio::time::timeout(Duration::from_secs(1), connection.read_exact(&mut ready))
            .await
            .expect("child did not announce readiness")
            .unwrap();
        assert_eq!(&ready, b"READY");
        fixture.connection = Some(connection);
        assert!(
            !fixture.reaped(),
            "child exited before watchdog test started"
        );
        fixture
    }

    fn reaped(&self) -> bool {
        self.child.lock().unwrap().try_wait().unwrap().is_some()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Independent rescue cleanup. Measure the helper's result BEFORE this
        // guard runs so it cannot make broken watchdog cleanup pass the test.
        let mut child = self.child.lock().unwrap_or_else(|error| error.into_inner());
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[tokio::test]
async fn watchdog_timeout_kills_and_reaps_the_owned_child_before_returning() {
    let fixture = Fixture::start().await;
    let result = tokio::time::timeout(
        Duration::from_millis(500),
        wait_child(
            Arc::clone(&fixture.child),
            Instant::now() + Duration::from_millis(50),
        ),
    )
    .await;
    let reaped_by_helper = fixture.reaped();
    drop(fixture);
    assert!(
        matches!(result, Ok(Err(error)) if error.kind() == std::io::ErrorKind::TimedOut),
        "watchdog must return its own bounded timeout"
    );
    assert!(
        reaped_by_helper,
        "watchdog returned with its child still alive"
    );
}

#[tokio::test]
async fn cancelling_watchdog_future_kills_and_reaps_its_owned_child() {
    let fixture = Fixture::start().await;
    let mut waiter = Box::pin(wait_child(
        Arc::clone(&fixture.child),
        Instant::now() + Duration::from_secs(5),
    ));
    tokio::select! {
        biased;
        _ = &mut waiter => panic!("watchdog finished while its child was blocked"),
        _ = tokio::time::sleep(Duration::from_millis(25)) => {}
    }
    drop(waiter); // Cancel the already-polled future, not its enclosing runtime.
    let reaped_by_helper = fixture.reaped();
    drop(fixture);
    assert!(reaped_by_helper, "cancelled watchdog left its child alive");
}
