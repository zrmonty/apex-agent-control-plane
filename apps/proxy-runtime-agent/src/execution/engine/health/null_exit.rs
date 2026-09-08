//! Regression for the actual daemon's null (not zero) pre-exit observation.
use super::{
    tests::fixture::{Fixture, inspection, response},
    *,
};

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn explicit_null_exit_is_preserved_without_inventing_a_successful_completion() {
    let f = Fixture::new();
    for (running, pid) in [(false, 0), (true, 123), (false, 123)] {
        let mut value = inspection(running, 0, pid);
        value["ExitCode"] = serde_json::Value::Null;
        let server = f.serve(response(200, serde_json::to_vec(&value).unwrap()), 7);
        let state = f
            .engine
            .health_inspect(
                &"b".repeat(64),
                &"a".repeat(64),
                Instant::now() + Duration::from_secs(2),
                &AtomicBool::new(false),
            )
            .unwrap();
        server.join().unwrap();
        assert_eq!(
            state,
            ExecState {
                running,
                pid,
                exit_code: None
            }
        );
    }
}

#[test]
#[ignore = "requires root-owned protected Unix-socket fixture directory"]
fn missing_or_malformed_exit_is_not_treated_as_explicit_null() {
    let f = Fixture::new();
    for exit in [
        None,
        Some(json!("0")),
        Some(json!(false)),
        Some(json!(0.5)),
        Some(json!(2147483648u64)),
        Some(json!(-2147483649i64)),
    ] {
        let mut value = inspection(false, 0, 123);
        match exit {
            None => {
                value.as_object_mut().unwrap().remove("ExitCode");
            }
            Some(exit) => {
                value["ExitCode"] = exit;
            }
        }
        let server = f.serve(response(200, serde_json::to_vec(&value).unwrap()), 7);
        let result = f.engine.health_inspect(
            &"b".repeat(64),
            &"a".repeat(64),
            Instant::now() + Duration::from_secs(2),
            &AtomicBool::new(false),
        );
        server.join().unwrap();
        assert_eq!(result, Err("RUNTIME_ENGINE_HEALTH_REFUSED"));
    }
}
