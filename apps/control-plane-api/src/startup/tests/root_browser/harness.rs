use super::{Case, child, config::Fixture, database::Database, pg, support};
use std::{
    io::{Read, Write},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

const DEADLINE: Duration = Duration::from_secs(90);
const OUTPUT_LIMIT: usize = 64 * 1024;

#[derive(Default, Debug, Clone)]
struct Diagnostics {
    bytes: usize,
    clean: bool,
    panic: bool,
    panic_locations: Vec<String>,
    ui_failure: Option<&'static str>,
    entered_runtime_panic: bool,
    overflow: bool,
    read_failed: bool,
}

pub(super) fn ui_failure(line: &str) -> Option<&'static str> {
    let category = line
        .strip_prefix("UI_JOURNEY_FAILED_")?
        .strip_suffix('\n')?;
    [
        "configuration",
        "protocol",
        "transport",
        "browser",
        "traffic",
        "login",
        "scope",
        "cookie",
        "cookie_lifetime",
        "privacy",
        "artifact",
        "identity",
        "inventory",
        "offline",
        "logout",
        "response",
        "assertion",
        "cancelled",
        "deadline",
        "internal",
        "cleanup",
        "journey",
    ]
    .into_iter()
    .find(|known| *known == category)
}

fn drain(mut pipe: impl Read + Send + 'static, state: Arc<Mutex<Diagnostics>>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut chunk = [0; 4096];
        let mut tail = Vec::new();
        loop {
            let count = match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    state.lock().unwrap().read_failed = true;
                    break;
                }
            };
            tail.extend_from_slice(&chunk[..count]);
            {
                let mut state = state.lock().unwrap();
                state.bytes = state.bytes.saturating_add(count);
                state.overflow |= state.bytes > OUTPUT_LIMIT;
                let contains =
                    |needle: &[u8]| tail.windows(needle.len()).any(|part| part == needle);
                state.clean |= contains(support::CLEAN.as_bytes());
                state.panic |= contains(b"ROOT_BROWSER_PANIC");
                for line in tail.split_inclusive(|byte| *byte == b'\n') {
                    if line.last() != Some(&b'\n') {
                        continue;
                    }
                    let Ok(line) = std::str::from_utf8(line) else {
                        continue;
                    };
                    state.ui_failure = state.ui_failure.or_else(|| ui_failure(line));
                    let Some(location) = line
                        .trim_end_matches(['\r', '\n'])
                        .strip_prefix("ROOT_BROWSER_PANIC ")
                    else {
                        continue;
                    };
                    let Some((file, number)) = location.rsplit_once(':') else {
                        continue;
                    };
                    if file.len() <= 96
                        && file.ends_with(".rs")
                        && file.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                        })
                        && number.parse::<u32>().is_ok_and(|line| line > 0)
                        && state.panic_locations.len() < 4
                        && !state.panic_locations.iter().any(|known| known == location)
                    {
                        state.panic_locations.push(location.to_owned());
                    }
                }
                state.entered_runtime_panic |= contains(b"ROOT_BROWSER_ENTERED_RUNTIME_PANIC")
                    || contains(b"Cannot start a runtime from within a runtime")
                    || contains(b"Cannot drop a runtime in a context");
            }
            // Retain only enough raw bytes to match split markers/locations. Raw child
            // output is NEVER displayed, including on failure or timeout.
            if tail.len() > 128 {
                drop(tail.drain(..tail.len() - 128));
            }
        }
    })
}

#[test]
fn ui_failure_diagnostics_never_reflect_untrusted_bytes() {
    assert_eq!(ui_failure("UI_JOURNEY_FAILED_login\n"), Some("login"));
    assert_eq!(
        ui_failure("UI_JOURNEY_FAILED_cookie_lifetime\n"),
        Some("cookie_lifetime")
    );
    for line in [
        "UI_JOURNEY_FAILED_cookie_lifetime secret-canary\n",
        "UI_JOURNEY_FAILED_secret-canary\n",
        "UI_JOURNEY_FAILED_login secret-canary\n",
        "UI_JOURNEY_FAILED_login",
        "prefix UI_JOURNEY_FAILED_login\n",
        "UI_JOURNEY_FAILED_login\nsecret-canary",
    ] {
        assert_eq!(ui_failure(line), None);
    }
}

#[test]
fn node_diagnostics_cannot_forge_rust_panic_locations() {
    let input = b"ROOT_BROWSER_PANIC secret-canary.rs:1\nUI_JOURNEY_FAILED_secret-canary\nUI_JOURNEY_FAILED_login\n";
    let mut forwarded = Vec::new();
    super::ui::read_diagnostics(input.as_slice(), |category| {
        writeln!(forwarded, "UI_JOURNEY_FAILED_{category}").unwrap();
    });
    let state = Arc::new(Mutex::new(Diagnostics::default()));
    drain(std::io::Cursor::new(forwarded), Arc::clone(&state))
        .join()
        .unwrap();
    let state = state.lock().unwrap();
    assert!(!state.panic);
    assert!(state.panic_locations.is_empty());
    assert_eq!(state.ui_failure, Some("login"));
    assert!(!format!("{state:?}").contains("secret-canary"));
}

struct ChildGuard {
    process: Arc<Mutex<Child>>,
    stop_watchdog: Arc<(Mutex<bool>, Condvar)>,
    timed_out: Arc<AtomicBool>,
    watchdog: Option<JoinHandle<()>>,
    readers: Vec<JoinHandle<()>>,
}

impl ChildGuard {
    fn spawn(command: &mut Command, timeout: Duration) -> Self {
        let process = Arc::new(Mutex::new(
            command
                .spawn()
                .expect("exact root-test child could not start"),
        ));
        let mut guard = Self {
            process,
            stop_watchdog: Arc::new((Mutex::new(false), Condvar::new())),
            timed_out: Arc::new(AtomicBool::new(false)),
            watchdog: None,
            readers: Vec::new(),
        };
        let process = Arc::clone(&guard.process);
        let stop = Arc::clone(&guard.stop_watchdog);
        let timed_out = Arc::clone(&guard.timed_out);
        guard.watchdog = Some(std::thread::spawn(move || {
            let (lock, wake) = &*stop;
            let (done, wait) = wake
                .wait_timeout_while(lock.lock().unwrap(), timeout, |done| !*done)
                .unwrap();
            if !*done && wait.timed_out() {
                timed_out.store(true, Ordering::SeqCst);
                let mut process = process.lock().unwrap();
                let _ = process.kill();
                let _ = process.wait();
            }
        }));
        guard
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        {
            let (lock, wake) = &*self.stop_watchdog;
            *lock.lock().unwrap_or_else(|error| error.into_inner()) = true;
            wake.notify_all();
        }
        {
            let mut process = self
                .process
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            // Only this exact child PID is ever terminated; always reap before
            // the UUID directory/schema fixtures are allowed to drop.
            if !matches!(process.try_wait(), Ok(Some(_))) {
                let _ = process.kill();
            }
            let _ = process.wait();
        }
        if let Some(watchdog) = self.watchdog.take() {
            let _ = watchdog.join();
        }
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

pub(super) fn run(case: Case, selector: &str) {
    match std::env::var(support::CHILD) {
        Ok(value) => {
            assert!(value == selector, "child selector mismatch");
            child::run(case);
            return;
        }
        Err(std::env::VarError::NotPresent) => {}
        Err(_) => panic!("invalid child selector setting"),
    }
    support::require_platform();
    // Validate the exact owned endpoint BEFORE the reusable helper creates its
    // UUID schema. Do not silently accept another database or skip fixtures.
    let base = support::required("APEX_BROWSER_SESSION_TEST_DATABASE_URL");
    let _ = pg::named_url(&base, "apex_rb_observer_validate");
    let database = Database::new();
    let mut fixture = Fixture::new(case, &database.url);
    if case == Case::Live {
        let seed_url = pg::named_url(
            &database.url,
            &format!("apex_rb_seed_{}", uuid::Uuid::now_v7().simple()),
        );
        pg::seed(&seed_url, &fixture.proxy_id);
    }
    let mut observer = pg::observer(&fixture.observer_url);
    assert_eq!(pg::connections(&mut observer, &fixture.root_app), 0);
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", selector, "--nocapture", "--test-threads=1"])
        .current_dir(&fixture.directory.path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    fixture.configure(&mut command, case, selector);
    let timeout = if case == Case::BrowserJourney {
        Duration::from_secs(150)
    } else {
        DEADLINE
    };
    let mut child = ChildGuard::spawn(&mut command, timeout);
    let (stdout, stderr, mut stdin) = {
        let mut process = child.process.lock().unwrap();
        (
            process.stdout.take().unwrap(),
            process.stderr.take().unwrap(),
            process.stdin.take(),
        )
    };
    let out = Arc::new(Mutex::new(Diagnostics::default()));
    let err = Arc::new(Mutex::new(Diagnostics::default()));
    child.readers.push(drain(stdout, Arc::clone(&out)));
    child.readers.push(drain(stderr, Arc::clone(&err)));
    let deadline = Instant::now() + timeout;
    let mut acknowledged = false;
    let status = loop {
        let out_state = out.lock().unwrap().clone();
        let err_state = err.lock().unwrap().clone();
        assert!(
            !child.timed_out.load(Ordering::SeqCst) && Instant::now() < deadline,
            "root child deadline exceeded; redacted stdout={out_state:?}, stderr={err_state:?}"
        );
        assert!(
            !out_state.overflow
                && !err_state.overflow
                && !out_state.read_failed
                && !err_state.read_failed,
            "root child diagnostic bounds failed; redacted stdout={out_state:?}, stderr={err_state:?}"
        );
        let status = child.process.lock().unwrap().try_wait().unwrap();
        if let Some(status) = status {
            break status;
        }
        if out_state.clean && !acknowledged {
            assert_eq!(
                pg::connections(&mut observer, &fixture.root_app),
                0,
                "parent observed root connections after child reported run_until return"
            );
            assert!(
                child.process.lock().unwrap().try_wait().unwrap().is_none(),
                "cleanup must be observed while the child is alive"
            );
            stdin.as_mut().unwrap().write_all(b"!").unwrap();
            drop(stdin.take());
            acknowledged = true;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // Finish bounded diagnostics before inspecting their final flags. This also
    // reaps the exact child before any fixture deletion, even on assertion unwind.
    drop(child);
    for state in [&out, &err] {
        let state = state.lock().unwrap();
        assert!(
            !state.panic && !state.entered_runtime_panic && !state.overflow && !state.read_failed,
            "root child final diagnostics failed: {state:?}"
        );
    }
    assert!(
        status.success() && acknowledged,
        "root child failed or exited without live cleanup acknowledgement; redacted stdout={:?}, stderr={:?}",
        out.lock().unwrap(),
        err.lock().unwrap()
    );
    pg::wait_for_zero(&mut observer, &fixture.root_app);
}
