use super::*;
use fixture::{Fixture, frame, inspection, response};
use serde_json::json;
use std::{sync::atomic::Ordering, time::Duration};
pub(in crate::execution) mod fixture;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
fn container() -> String {
    "a".repeat(64)
}
fn exec() -> String {
    "b".repeat(64)
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn create_sends_only_the_fixed_health_process_and_returns_daemon_id() {
    let f = Fixture::new();
    let server = f.serve(
        response(201, serde_json::to_vec(&json!({"Id": exec()})).unwrap()),
        1,
    );
    assert_eq!(
        f.engine
            .health_create(&container(), deadline(), &AtomicBool::new(false)),
        Ok(exec())
    );
    let request = server.join().unwrap();
    assert_eq!(
        request.line,
        format!("POST /v1.47/containers/{}/exec HTTP/1.1", container())
    );
    assert_eq!(
        request.body,
        json!({
            "Cmd": ["/usr/local/bin/node", "/app/apps/mcp-gateway/dist/managed/health-process.js"],
            "User": "10001:10001", "WorkingDir": "/app/apps/mcp-gateway",
            "AttachStdin": false, "AttachStdout": true, "AttachStderr": true,
            "Tty": false, "Privileged": false
        })
    );
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn start_collects_fragmented_stdout_but_eof_does_not_inspect_or_prove_completion() {
    let f = Fixture::new();
    let mut bytes = frame(1, b"{\"healthy\":");
    bytes.extend(frame(1, b"true}\n"));
    let server = f.serve(response(200, bytes), 1);
    assert_eq!(
        &*f.engine
            .health_start(&exec(), deadline(), &AtomicBool::new(false))
            .unwrap(),
        b"{\"healthy\":true}\n"
    );
    let request = server.join().unwrap();
    assert_eq!(
        request.line,
        format!("POST /v1.47/exec/{}/start HTTP/1.1", exec())
    );
    assert_eq!(request.body, json!({"Detach": false, "Tty": false}));
    // A separate daemon observation can still report running after stdout EOF.
    let server = f.serve(
        response(200, serde_json::to_vec(&inspection(true, 0, 123)).unwrap()),
        3,
    );
    assert_eq!(
        f.engine
            .health_inspect(&exec(), &container(), deadline(), &AtomicBool::new(false))
            .unwrap(),
        ExecState {
            running: true,
            exit_code: Some(0),
            pid: 123
        }
    );
    assert_eq!(
        server.join().unwrap().line,
        format!("GET /v1.47/exec/{}/json HTTP/1.1", exec())
    );
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn inspect_preserves_terminal_failure_and_never_started_states() {
    let f = Fixture::new();
    for (running, exit_code, pid) in [(false, 0, 123), (false, 17, 123), (false, 0, 0)] {
        let server = f.serve(
            response(
                200,
                serde_json::to_vec(&inspection(running, exit_code, pid)).unwrap(),
            ),
            7,
        );
        assert_eq!(
            f.engine
                .health_inspect(&exec(), &container(), deadline(), &AtomicBool::new(false))
                .unwrap(),
            ExecState {
                running,
                exit_code: Some(exit_code),
                pid
            }
        );
        assert_eq!(server.join().unwrap().body, serde_json::Value::Null);
    }
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn start_enforces_exact_stdout_limit_and_rejects_bad_multiplex_frames() {
    let f = Fixture::new();
    let server = f.serve(response(200, frame(1, &vec![b'x'; 16385])), 511);
    assert_eq!(
        f.engine
            .health_start(&exec(), deadline(), &AtomicBool::new(false))
            .unwrap()
            .len(),
        16385
    );
    server.join().unwrap();
    let mut nonzero_reserved = frame(1, b"x");
    nonzero_reserved[1] = 1;
    let mut truncated = frame(1, b"abc");
    truncated.pop();
    for bytes in [
        frame(1, &vec![b'x'; 16386]),
        frame(2, b"secret-stderr-canary"),
        frame(2, &vec![b'x'; 1025]),
        frame(0, b"x"),
        frame(3, b"x"),
        nonzero_reserved,
        truncated,
        vec![1, 0, 0, 0, 0, 0, 0],
        vec![1, 0, 0, 0, 255, 255, 255, 255],
    ] {
        let server = f.serve(response(200, bytes), 31);
        assert_eq!(
            f.engine
                .health_start(&exec(), deadline(), &AtomicBool::new(false))
                .unwrap_err(),
            "RUNTIME_ENGINE_HEALTH_REFUSED"
        );
        server.join().unwrap();
    }
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn strict_create_refuses_untrusted_ids_duplicates_overflow_status_and_truncated_http() {
    let f = Fixture::new();
    for body in [
        b"{}".to_vec(),
        serde_json::to_vec(&json!({"Id": "B".repeat(64)})).unwrap(),
        format!("{{\"Id\":\"{}\",\"Id\":\"{}\"}}", exec(), exec()).into_bytes(),
        serde_json::to_vec(&json!({"Id":exec(),"extra":true})).unwrap(),
        vec![b' '; 4097],
        b"[]".to_vec(),
    ] {
        let server = f.serve(response(201, body), 128);
        assert_eq!(
            f.engine
                .health_create(&container(), deadline(), &AtomicBool::new(false))
                .unwrap_err(),
            "RUNTIME_ENGINE_HEALTH_REFUSED"
        );
        server.join().unwrap();
    }
    for reply in [
        response(500, b"secret-error-canary".to_vec()),
        b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1234/evil\r\nContent-Length: 0\r\n\r\n"
            .to_vec(),
        b"HTTP/1.1 201 OK\r\nContent-Length: 100\r\n\r\n{}".to_vec(),
    ] {
        let server = f.serve(reply, 128);
        assert_eq!(
            f.engine
                .health_create(&container(), deadline(), &AtomicBool::new(false))
                .unwrap_err(),
            "RUNTIME_ENGINE_HEALTH_REFUSED"
        );
        server.join().unwrap();
    }
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn inspect_refuses_substitution_missing_fields_duplicates_and_invalid_numbers() {
    let f = Fixture::new();
    for (pointer, bad) in [
        ("/ID", json!("c".repeat(64))),
        ("/ContainerID", json!("c".repeat(64))),
        ("/ProcessConfig/entrypoint", json!("/bin/sh")),
        ("/ProcessConfig/arguments", json!(["-c", "evil"])),
        ("/ProcessConfig/user", json!("0:0")),
        ("/ProcessConfig/privileged", json!(true)),
        ("/ProcessConfig/tty", json!(true)),
        ("/OpenStdin", json!(true)),
        ("/Running", json!("false")),
        ("/ExitCode", json!(2147483648u64)),
        ("/Pid", json!(-1)),
        ("/Pid", json!(4294967296u64)),
    ] {
        let mut value = inspection(false, 0, 123);
        *value.pointer_mut(pointer).unwrap() = bad;
        let server = f.serve(response(200, serde_json::to_vec(&value).unwrap()), 111);
        assert_eq!(
            f.engine
                .health_inspect(&exec(), &container(), deadline(), &AtomicBool::new(false))
                .unwrap_err(),
            "RUNTIME_ENGINE_HEALTH_REFUSED",
            "{pointer}"
        );
        server.join().unwrap();
    }
    for field in [
        "ID",
        "ContainerID",
        "Running",
        "ExitCode",
        "Pid",
        "ProcessConfig",
        "OpenStdin",
    ] {
        let mut value = inspection(false, 0, 123);
        value.as_object_mut().unwrap().remove(field);
        let server = f.serve(response(200, serde_json::to_vec(&value).unwrap()), 512);
        assert!(
            f.engine
                .health_inspect(&exec(), &container(), deadline(), &AtomicBool::new(false))
                .is_err()
        );
        server.join().unwrap();
    }
    for bytes in [
        serde_json::to_string(&inspection(false, 0, 123))
            .unwrap()
            .replacen("\"tty\":false", "\"tty\":false,\"tty\":false", 1)
            .into_bytes(),
        vec![b' '; 16385],
    ] {
        let server = f.serve(response(200, bytes), 512);
        assert!(
            f.engine
                .health_inspect(&exec(), &container(), deadline(), &AtomicBool::new(false))
                .is_err()
        );
        server.join().unwrap();
    }
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn invalid_selectors_cancel_and_expired_deadline_never_dispatch() {
    let f = Fixture::new();
    for id in [
        "".to_owned(),
        "named-container".into(),
        "a".repeat(63),
        "A".repeat(64),
        format!("{}?x=y", exec()),
    ] {
        assert!(
            f.engine
                .health_create(&id, deadline(), &AtomicBool::new(false))
                .is_err()
        );
        assert!(
            f.engine
                .health_start(&id, deadline(), &AtomicBool::new(false))
                .is_err()
        );
        assert!(
            f.engine
                .health_inspect(&id, &container(), deadline(), &AtomicBool::new(false))
                .is_err()
        );
        assert!(
            f.engine
                .health_inspect(&exec(), &id, deadline(), &AtomicBool::new(false))
                .is_err()
        );
    }
    assert_eq!(
        f.engine
            .health_create(&container(), deadline(), &AtomicBool::new(true))
            .unwrap_err(),
        "RUNTIME_ENGINE_COMMAND_CANCELLED"
    );
    assert_eq!(
        f.engine
            .health_start(&exec(), Instant::now(), &AtomicBool::new(false))
            .unwrap_err(),
        "RUNTIME_ENGINE_COMMAND_DEADLINE"
    );
    assert!(matches!(f.listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn stalled_dispatch_and_partial_body_keep_original_deadline_and_drop_transport() {
    use std::io::{Read, Write};
    for headers in [false, true] {
        let f = Fixture::new();
        let server = f.handle(move |mut stream| {
            let request = fixture::read_request(&mut stream);
            if headers {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n\x01\0\0\0")
                    .unwrap();
            }
            let mut byte = [0];
            assert_eq!(
                stream.read(&mut byte).unwrap(),
                0,
                "client must close on deadline"
            );
            request
        });
        let start = Instant::now();
        assert_eq!(
            f.engine
                .health_start(
                    &exec(),
                    start + Duration::from_millis(80),
                    &AtomicBool::new(false)
                )
                .unwrap_err(),
            "RUNTIME_ENGINE_COMMAND_DEADLINE"
        );
        assert!(start.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
    }
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn cancellation_during_read_drops_transport_without_retry_or_completion_claim() {
    use std::io::Read;
    let f = Fixture::new();
    let cancelled = std::sync::Arc::new(AtomicBool::new(false));
    let flag = cancelled.clone();
    let server = f.handle(move |mut stream| {
        let request = fixture::read_request(&mut stream);
        flag.store(true, Ordering::Release);
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).unwrap(), 0);
        request
    });
    let start = Instant::now();
    assert_eq!(
        f.engine
            .health_start(&exec(), deadline(), &cancelled)
            .unwrap_err(),
        "RUNTIME_ENGINE_COMMAND_CANCELLED"
    );
    assert!(start.elapsed() < Duration::from_millis(500));
    server.join().unwrap();
    assert!(matches!(f.listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn original_socket_identity_is_rechecked_before_dispatch_and_after_response() {
    use std::{fs, io::Write, os::unix::net::UnixListener};
    let f = Fixture::new();
    let path = f.root.join("daemon.sock");
    let replaced = path.clone();
    let server = f.handle(move |mut stream| {
        let request = fixture::read_request(&mut stream);
        fs::rename(&replaced, replaced.with_extension("old")).unwrap();
        let _replacement = UnixListener::bind(&replaced).unwrap();
        let _ = stream.write_all(&response(
            201,
            serde_json::to_vec(&json!({"Id":exec()})).unwrap(),
        ));
        request
    });
    assert!(
        f.engine
            .health_create(&container(), deadline(), &AtomicBool::new(false))
            .is_err()
    );
    server.join().unwrap();
    assert!(
        f.engine
            .health_create(&container(), deadline(), &AtomicBool::new(false))
            .is_err()
    );
    assert!(matches!(f.listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
}
