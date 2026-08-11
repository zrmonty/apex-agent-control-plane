//! `SubmitCommand` tests: the single-operator write path.

use prost_types::Struct as ProstStruct;

use crate::proto;
use crate::proto::control_gateway_server::ControlGateway as _;
use crate::service::*;

use super::support::*;

#[tokio::test]
async fn submit_command_accepts_a_well_formed_stop_command() {
    let service = service();
    let response = service
        .submit_command(authed_request(stop_request()))
        .await
        .unwrap()
        .into_inner();
    assert!(!response.duplicate);
    assert!(!response.command_id.is_empty());
}

#[tokio::test]
async fn submit_command_is_idempotent_for_a_repeated_command_id() {
    let service = service();
    let mut request = stop_request();
    request.command_id = Some(fresh_command_id(1));
    let first = service
        .submit_command(authed_request(request.clone()))
        .await
        .unwrap()
        .into_inner();
    let second = service
        .submit_command(authed_request(request))
        .await
        .unwrap()
        .into_inner();
    assert!(!first.duplicate);
    assert!(second.duplicate);
    assert_eq!(first.command_id, second.command_id);
}

#[tokio::test]
async fn submit_command_rejects_a_reused_command_id_with_different_fields() {
    let service = service();
    let mut first_request = stop_request();
    first_request.command_id = Some(fresh_command_id(2));
    service
        .submit_command(authed_request(first_request))
        .await
        .unwrap();

    let mut second_request = stop_request();
    second_request.command_id = Some(fresh_command_id(2));
    second_request.action = proto::ControlAction::Pause as i32; // different fields, same id.
    let status = service
        .submit_command(authed_request(second_request))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn submit_command_rate_limits_a_single_operator_after_the_per_second_ceiling() {
    let service = service();
    for index in 0..DEFAULT_MAX_COMMANDS_PER_WINDOW {
        let mut request = stop_request();
        request.command_id = Some(fresh_command_id(u64::from(index)));
        service
            .submit_command(authed_request(request))
            .await
            .unwrap();
    }
    let mut request = stop_request();
    request.command_id = Some(fresh_command_id(0xffff_ffff));
    let status = service
        .submit_command(authed_request(request))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);
}

#[tokio::test]
async fn submit_command_handles_concurrent_duplicate_submissions_without_a_torn_write() {
    let service = Arc::new(service());
    let command_id = fresh_command_id(0xab);
    let mut handles = Vec::new();
    for _ in 0..8 {
        let service = service.clone();
        let mut request = stop_request();
        request.command_id = Some(command_id.clone());
        handles.push(tokio::spawn(async move {
            service.submit_command(authed_request(request)).await
        }));
    }
    let mut accepted_non_duplicate = 0;
    for handle in handles {
        let response = handle.await.unwrap().unwrap().into_inner();
        assert_eq!(response.command_id, command_id);
        if !response.duplicate {
            accepted_non_duplicate += 1;
        }
    }
    // Exactly one concurrent submission of the same command_id with the
    // same fields is the "first" acceptance; every other racer must see
    // it as a duplicate, never as a second independent enqueue.
    assert_eq!(accepted_non_duplicate, 1);
}

#[tokio::test]
async fn submit_command_rejects_a_scope_the_operator_does_not_hold() {
    let service = service();
    let mut request = stop_request();
    request.workspace_id = "other-workspace".to_owned();
    let status = service
        .submit_command(authed_request(request))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn submit_command_rejects_missing_authentication() {
    let service = service();
    let request = tonic::Request::new(stop_request());
    let status = service.submit_command(request).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn submit_command_rejects_inject_without_untrusted_classification() {
    let service = service();
    let mut request = stop_request();
    request.action = proto::ControlAction::Inject as i32;
    let mut fields = std::collections::BTreeMap::new();
    fields.insert(
        "content".to_owned(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue("hello".to_owned())),
        },
    );
    // Missing content_classification: "untrusted" -- must be rejected.
    request.parameters = Some(ProstStruct {
        fields: fields.into_iter().collect(),
    });
    let status = service
        .submit_command(authed_request(request))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}
