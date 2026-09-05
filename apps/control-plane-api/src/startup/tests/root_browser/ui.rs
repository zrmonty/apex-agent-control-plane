//! Real Chromium/HTTPS UI journey against two successive production roots.
//! The browser runner owns only its TLS frontend/browser; this owner alone
//! stops/restarts the Rust root. No HTTP responses or proxy rows are fabricated.
use super::{flow, pg, support};
use std::{
    io::{BufRead, BufReader, Write},
    net::SocketAddr,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver, TryRecvError},
    thread::JoinHandle,
    time::{Duration, Instant},
};

#[derive(Debug, PartialEq, Eq)]
enum Phase {
    Restart,
    Offline,
    Passed,
}

#[derive(Debug)]
enum ProtocolError {
    Read,
    Invalid,
    Overflow,
}

fn read_phases(
    output: impl std::io::Read,
    send: mpsc::SyncSender<Phase>,
) -> Result<(), ProtocolError> {
    let mut output = BufReader::new(output);
    loop {
        let mut bytes = Vec::with_capacity(128);
        let count = std::io::Read::take(&mut output, 128)
            .read_until(b'\n', &mut bytes)
            .map_err(|_| ProtocolError::Read)?;
        if count == 0 {
            return Ok(());
        }
        let phase = match bytes.as_slice() {
            b"UI_READY_FOR_RESTART\n" => Phase::Restart,
            b"UI_OFFLINE_OBSERVED\n" => Phase::Offline,
            b"UI_JOURNEY_PASSED\n" => Phase::Passed,
            _ => return Err(ProtocolError::Invalid),
        };
        send.try_send(phase).map_err(|_| ProtocolError::Overflow)?;
    }
}

struct Driver {
    child: Child,
    input: Option<ChildStdin>,
    phases: Receiver<Phase>,
    reader: Option<JoinHandle<Result<(), ProtocolError>>>,
    diagnostics: Option<JoinHandle<()>>,
}

pub(super) fn read_diagnostics(input: impl std::io::Read, mut report: impl FnMut(&'static str)) {
    let mut input = BufReader::new(std::io::Read::take(input, 64 * 1024));
    loop {
        let mut bytes = Vec::with_capacity(128);
        let Ok(count) = std::io::Read::take(&mut input, 128).read_until(b'\n', &mut bytes) else {
            return;
        };
        if count == 0 {
            return;
        }
        if let Ok(line) = std::str::from_utf8(&bytes)
            && let Some(category) = super::harness::ui_failure(line)
        {
            report(category);
        }
    }
}

fn runner_command() -> Command {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../operator-ui");
    let mut command = Command::new("node");
    command
        // Node does not accept Rust's Windows verbatim canonical paths as
        // entrypoints. Resolve this fixed relative script in the known UI
        // cwd without changing host state or exposing arbitrary argv.
        .arg("scripts/browser-journey.mjs")
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Node must not inherit the root's parent-facing diagnostic writer:
        // it could retain that pipe after the parent watchdog kills the root.
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    command
}

impl Driver {
    fn start() -> Self {
        let mut command = runner_command();
        let (send, phases) = mpsc::sync_channel(8);
        // Install the exact-process cleanup owner before any fallible reader
        // setup. A failed OS thread spawn must also close/kill/reap this Node.
        let mut driver = Self {
            child: command.spawn().expect("UI runner unavailable"),
            input: None,
            phases,
            reader: None,
            diagnostics: None,
        };
        driver.input = driver.child.stdin.take();
        let output = driver.child.stdout.take().unwrap();
        driver.reader = Some(
            std::thread::Builder::new()
                .name("apex-ui-protocol".into())
                .spawn(move || read_phases(output, send))
                .expect("UI protocol reader unavailable"),
        );
        let errors = driver.child.stderr.take().unwrap();
        driver.diagnostics = Some(
            std::thread::Builder::new()
                .name("apex-ui-diagnostics".into())
                .spawn(move || {
                    read_diagnostics(errors, |category| {
                        // Only static strings cross into the root's diagnostic
                        // pipe. Node cannot forge a Rust source-location record.
                        eprintln!("UI_JOURNEY_FAILED_{category}");
                    })
                })
                .expect("UI diagnostic reader unavailable"),
        );
        driver
    }

    fn send(&mut self, marker: &[u8]) {
        self.input
            .as_mut()
            .unwrap()
            .write_all(marker)
            .expect("UI runner input closed");
        self.input.as_mut().unwrap().flush().unwrap();
    }

    async fn wait(&mut self, expected: Phase) {
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                match self.phases.try_recv() {
                    Ok(phase) => {
                        assert_eq!(phase, expected, "unexpected UI runner phase");
                        return;
                    }
                    Err(TryRecvError::Disconnected) => {
                        panic!("UI runner closed before expected phase")
                    }
                    Err(TryRecvError::Empty) => {}
                }
                // Process exit may precede the reader delivering buffered bytes.
                // Only channel completion proves no further phase can arrive;
                // finalization separately requires exit zero and clean EOF.
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("UI runner phase deadline exceeded");
    }

    fn wait_offline(&mut self) {
        assert!(tokio::runtime::Handle::try_current().is_err());
        assert_eq!(
            self.phases.recv_timeout(Duration::from_secs(30)).unwrap(),
            Phase::Offline
        );
    }

    fn finish(&mut self) {
        assert!(tokio::runtime::Handle::try_current().is_err());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "UI runner failed after final marker");
                if self
                    .reader
                    .as_ref()
                    .is_some_and(|reader| reader.is_finished())
                {
                    self.reader
                        .take()
                        .unwrap()
                        .join()
                        .expect("UI protocol reader panicked")
                        .expect("UI protocol stream was invalid");
                    assert_eq!(
                        self.phases.try_recv(),
                        Err(TryRecvError::Disconnected),
                        "UI protocol contained trailing phases"
                    );
                    return;
                }
            }
            assert!(
                Instant::now() < deadline,
                "UI runner cleanup deadline exceeded"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        // EOF is the runner's cancellation signal; allow it to close Chromium
        // and its TLS frontend before the exact-child emergency kill/reap.
        drop(self.input.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        while matches!(self.child.try_wait(), Ok(None)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.diagnostics.take() {
            let _ = reader.join();
        }
    }
}

async fn ready(control: SocketAddr, browser: SocketAddr, pki: &support::Pki) {
    flow::control_ready(control, pki).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if client
                .get(format!("http://{browser}/api/session"))
                .send()
                .await
                .is_ok_and(|reply| reply.status() == 401)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("real browser edge did not become ready");
}

pub(super) fn run(
    control: SocketAddr,
    browser: SocketAddr,
    pki: &support::Pki,
    observer: &mut postgres::Client,
    root_app: &str,
) {
    let mut driver = None;
    let first = crate::startup::service::run_until(async {
        ready(control, browser, pki).await;
        let active = driver.insert(Driver::start());
        active.wait(Phase::Restart).await;
    });
    assert!(
        first.is_ok(),
        "first production root did not shut down cleanly"
    );
    pg::wait_for_zero(observer, root_app);
    let driver = driver.as_mut().unwrap();
    driver.send(b"D\n");
    driver.wait_offline();
    // Reconstruct every production owner with the same durable rows and keys.
    let second = crate::startup::service::run_until(async {
        ready(control, browser, pki).await;
        driver.send(b"R\n");
        driver.wait(Phase::Passed).await;
    });
    assert!(
        second.is_ok(),
        "restarted production root did not shut down cleanly"
    );
    pg::wait_for_zero(observer, root_app);
    driver.finish();
}

#[path = "ui/tests.rs"]
mod tests;
