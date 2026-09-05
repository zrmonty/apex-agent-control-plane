//! Component refusal checks only; successful SQL and cleanup need real PG tests.

use std::cell::{Cell, RefCell};

use super::{ProxyError, RuntimeTarget, configuration_error, read_checked};

const OPERATION_ID: &str = "019bf123-0000-7000-8000-000000000003";
const WORKER_ID: &str = "controller-a";

fn valid_target() -> RuntimeTarget {
    RuntimeTarget {
        workspace_id: "workspace-a".into(),
        namespace_id: "namespace-a".into(),
        proxy_id: "019bf123-0000-7000-8000-000000000001".into(),
        revision_id: "019bf123-0000-7000-8000-000000000002".into(),
        generation: 1,
        fencing_token: 1,
    }
}

fn assert_refusal_before_connection(expected: ProxyError) {
    let checks = Cell::new(0);
    let target = valid_target();
    let result = read_checked(
        || panic!("a refused read must not attempt connection access"),
        &target,
        OPERATION_ID,
        WORKER_ID,
        &|| {
            assert_eq!(checks.replace(checks.get() + 1), 0);
            Err(expected.clone())
        },
    );

    let error = result.expect_err("a refused read must not return a snapshot");
    assert_eq!(error, expected, "preserve the supplied code and message");
    assert_eq!(checks.get(), 1, "stop at the first checkpoint refusal");
    assert!(std::error::Error::source(&error).is_none());
}

#[test]
fn cancelled_read_preserves_refusal_before_connection_access() {
    assert_refusal_before_connection(ProxyError::new(
        "RUNTIME_AUTHORITY_CANCELLED",
        "Runtime authority request cancelled.",
    ));
}

#[test]
fn expired_read_preserves_refusal_before_connection_access() {
    assert_refusal_before_connection(ProxyError::new(
        "RUNTIME_AUTHORITY_DEADLINE",
        "Runtime authority deadline exceeded.",
    ));
}

#[test]
fn replaced_policy_preserves_refusal_before_connection_access() {
    assert_refusal_before_connection(ProxyError::new(
        "RUNTIME_AUTHORITY_POLICY_CHANGED",
        "Runtime authority policy changed.",
    ));
}

#[test]
fn allowed_checkpoint_precedes_connection_refusal() {
    let events = RefCell::new(Vec::new());
    let target = valid_target();
    let result = read_checked(
        || {
            events.borrow_mut().push("connection");
            Err(configuration_error())
        },
        &target,
        OPERATION_ID,
        WORKER_ID,
        &|| {
            events.borrow_mut().push("check");
            Ok(())
        },
    );

    assert_eq!(
        result.expect_err("connection unavailable"),
        configuration_error()
    );
    assert_eq!(*events.borrow(), ["check", "connection"]);
}
