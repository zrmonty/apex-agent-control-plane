//! Exact child ownership, bounded redacted diagnostics, cleanup while alive.
use super::{
    Case, child,
    config::{self, RootFixture},
    operation::Fixture,
};
use std::{
    io::{Read, Write},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

#[derive(Default)]
struct Output {
    bytes: AtomicUsize,
    clean: AtomicBool,
    panicked: AtomicBool,
    failed: AtomicBool,
    locations: Mutex<Vec<String>>,
}

fn drain(mut pipe: impl Read + Send + 'static, output: Arc<Output>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut chunk = [0; 2048];
        let mut tail = Vec::new();
        loop {
            let count = match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    output.failed.store(true, Ordering::Release);
                    break;
                }
            };
            output.bytes.fetch_add(count, Ordering::Relaxed);
            tail.extend_from_slice(&chunk[..count]);
            if tail
                .windows(config::CLEAN.len())
                .any(|bytes| bytes == config::CLEAN.as_bytes())
            {
                output.clean.store(true, Ordering::Release);
            }
            if tail
                .windows(b"ROOT_AUTHORITY_PANIC".len())
                .any(|bytes| bytes == b"ROOT_AUTHORITY_PANIC")
            {
                output.panicked.store(true, Ordering::Release);
            }
            for line in tail.split(|byte| *byte == b'\n') {
                let Some(location) = std::str::from_utf8(line).ok().and_then(|line| {
                    line.trim_end_matches('\r')
                        .strip_prefix("ROOT_AUTHORITY_PANIC ")
                }) else {
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
                {
                    let mut locations = output.locations.lock().unwrap();
                    if locations.len() < 4 && !locations.iter().any(|known| known == location) {
                        locations.push(location.to_owned());
                    }
                }
            }
            // Raw output (potential DSN/config data) is neither returned nor logged.
            if tail.len() > 96 {
                tail.drain(..tail.len() - 96);
            }
        }
    })
}

struct ChildOwner {
    process: Child,
    readers: Vec<JoinHandle<()>>,
}
impl Drop for ChildOwner {
    fn drop(&mut self) {
        if !matches!(self.process.try_wait(), Ok(Some(_))) {
            let _ = self.process.kill();
        }
        let _ = self.process.wait();
        for handle in self.readers.drain(..) {
            let _ = handle.join();
        }
    }
}

pub(super) fn run(case: Case, selector: &str) {
    if let Some(selected) = std::env::var_os(config::CHILD) {
        assert_eq!(selected, std::ffi::OsStr::new(selector));
        child::run(case);
        return;
    }
    super::support::require_platform();
    let operation = Fixture::new(true);
    operation.positive();
    let mut fixture = RootFixture::new(&operation);
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", selector, "--nocapture", "--test-threads=1"])
        .current_dir(&fixture.directory.path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    fixture.configure(&mut command, case, selector);
    let mut child = ChildOwner {
        process: command.spawn().expect("exact root child"),
        readers: Vec::new(),
    };
    let output = Arc::new(Output::default());
    child.readers.push(drain(
        child.process.stdout.take().unwrap(),
        Arc::clone(&output),
    ));
    child.readers.push(drain(
        child.process.stderr.take().unwrap(),
        Arc::clone(&output),
    ));
    let mut stdin = child.process.stdin.take();
    let until = Instant::now() + Duration::from_secs(60);
    let mut acknowledged = false;
    let status = loop {
        assert!(
            Instant::now() < until,
            "production root test exceeded its bounded deadline"
        );
        assert!(
            output.bytes.load(Ordering::Relaxed) <= 65_536
                && !output.failed.load(Ordering::Acquire),
            "bounded child diagnostic collection failed"
        );
        if let Some(status) = child.process.try_wait().unwrap() {
            break status;
        }
        if output.clean.load(Ordering::Acquire) && !acknowledged {
            assert_eq!(
                child::connections(&fixture.url, &fixture.name),
                0,
                "parent must observe no root connections while child remains alive"
            );
            assert!(child.process.try_wait().unwrap().is_none());
            stdin.as_mut().unwrap().write_all(b"!").unwrap();
            drop(stdin.take());
            acknowledged = true;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    drop(child); // Reap exact child and both pipe readers before fixtures/schema.
    assert!(
        output.bytes.load(Ordering::Relaxed) <= 65_536 && !output.failed.load(Ordering::Acquire)
    );
    assert!(
        !output.panicked.load(Ordering::Acquire),
        "production root child assertion failed at {:?} (payload redacted)",
        output.locations.lock().unwrap()
    );
    assert!(
        status.success() && acknowledged,
        "root child failed or omitted live cleanup acknowledgement"
    );
    assert_eq!(child::connections(&fixture.url, &fixture.name), 0);
}
