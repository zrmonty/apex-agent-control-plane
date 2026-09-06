#![cfg(test)]
use super::*;
mod attestation;

fn request() -> proto::RuntimeReconcileRequest {
    proto::RuntimeReconcileRequest {
        schema_version: 1,
        target: Some(proto::RuntimeTarget {
            workspace_id: "workspace".into(),
            namespace_id: "namespace".into(),
            proxy_id: "0191b7f1-7f2c-7c13-9a61-2f29f2be1001".into(),
            revision_id: "0191b7f1-7f2c-7c13-9a61-2f29f2be1002".into(),
            generation: 4,
            fencing_token: 9,
        }),
        operation_id: "0191b7f1-7f2c-7c13-9a61-2f29f2be1003".into(),
        command_id: "0191b7f1-7f2c-7c13-9a61-2f29f2be1004".into(),
        config_hash: "a".repeat(64),
    }
}

#[test]
fn exact_current_claims_do_not_rewrite_older_installed_target_or_infer_retirement() {
    let request = request();
    let mut target = request.target.clone().unwrap();
    target.generation = 3;
    target.fencing_token = 6;
    target.revision_id = "0191b7f1-7f2c-7c13-9a61-2f29f2be1012".into();
    let mut response = proto::RuntimeReconcileResponse {
        schema_version: 1,
        claims: Some(request.clone()),
        observed_state: proto::ProxyObservedState::Paused as i32,
        error_code: String::new(),
        runtime: Some(proto::RuntimeObservation {
            target: Some(target.clone()),
            runtime_id: "a".repeat(64),
            state: "not-serving".into(),
            observed_at_unix_us: 1788655506965685,
            ..Default::default()
        }),
    };
    validate_response(&request, &response, proto::ProxyDesiredState::Paused)
        .expect("authenticated explicit pause may retain prior installed identity");
    assert_eq!(
        response.runtime.as_ref().unwrap().target.as_ref(),
        Some(&target)
    );
    response.runtime = None;
    assert!(validate_response(&request, &response, proto::ProxyDesiredState::Retired).is_err());
    response.observed_state = proto::ProxyObservedState::Retired as i32;
    validate_response(&request, &response, proto::ProxyDesiredState::Retired).unwrap();
    response
        .claims
        .as_mut()
        .unwrap()
        .target
        .as_mut()
        .unwrap()
        .fencing_token = 8;
    assert!(validate_response(&request, &response, proto::ProxyDesiredState::Retired).is_err());
}

#[test]
fn explicit_paused_without_installed_runtime_requires_exact_response_claims() {
    let request = request();
    let mut response = proto::RuntimeReconcileResponse {
        schema_version: 1,
        claims: Some(request.clone()),
        observed_state: proto::ProxyObservedState::Paused as i32,
        runtime: None,
        ..Default::default()
    };
    validate_response(&request, &response, proto::ProxyDesiredState::Paused)
        .expect("explicit authenticated pause can retain sealed stage without a container");
    assert!(validate_response(&request, &response, proto::ProxyDesiredState::Retired).is_err());
    response.claims = None;
    assert!(validate_response(&request, &response, proto::ProxyDesiredState::Paused).is_err());
    response.observed_state = proto::ProxyObservedState::Retired as i32;
    assert!(validate_response(&request, &response, proto::ProxyDesiredState::Retired).is_err());
    // No transport response is not an explicit outcome; an empty message cannot
    // substitute for the missing authenticated response either.
    for desired in [
        proto::ProxyDesiredState::Paused,
        proto::ProxyDesiredState::Retired,
    ] {
        assert!(validate_response(&request, &Default::default(), desired).is_err());
    }
}

#[test]
fn ready_unknown_schema_or_runtime_admission_never_pass_the_dormant_boundary() {
    let request = request();
    let mut response = proto::RuntimeReconcileResponse {
        schema_version: 1,
        claims: Some(request.clone()),
        observed_state: proto::ProxyObservedState::Ready as i32,
        ..Default::default()
    };
    assert!(validate_response(&request, &response, proto::ProxyDesiredState::Serving).is_err());
    response.observed_state = proto::ProxyObservedState::NotServing as i32;
    response.schema_version = 2;
    assert!(validate_response(&request, &response, proto::ProxyDesiredState::Serving).is_err());
    response.schema_version = 1;
    response.runtime = Some(proto::RuntimeObservation {
        target: request.target.clone(),
        runtime_id: "a".repeat(64),
        state: "not-serving".into(),
        observed_at_unix_us: 1,
        admitting: true,
        ..Default::default()
    });
    assert!(validate_response(&request, &response, proto::ProxyDesiredState::Serving).is_err());
}
