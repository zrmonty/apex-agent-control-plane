//! Actual loopback RPC codec behavior, not mTLS, PG, current-lease or production
//! authority acceptance. No valid authority response is returned by any fixture.
#[path = "proxy_runtime_authority_codec/services.rs"]
mod services;
#[path = "proxy_runtime_authority_codec/support.rs"]
mod support;

use apex_control_plane_api::proto::{
    self, control_gateway_client::ControlGatewayClient,
    control_gateway_server::ControlGatewayServer,
    runtime_authority_service_client::RuntimeAuthorityServiceClient,
    runtime_authority_service_server::RuntimeAuthorityServiceServer,
};
use services::{MalformedReply, MarkerService};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use support::*;
use tonic::transport::Server;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generated_authority_server_redacts_actual_malformed_request_before_handler() {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = RuntimeAuthorityServiceServer::new(MarkerService(Arc::clone(&calls)))
        .max_decoding_message_size(LIMIT)
        .max_encoding_message_size(LIMIT);
    let router = Server::builder()
        .concurrency_limit_per_connection(1)
        .timeout(RPC)
        .add_service(service);
    exercise(router, move |endpoint| async move {
        malformed_control::<proto::CheckRuntimeAuthorityRequest>(
            BAD_TARGET,
            "CheckRuntimeAuthorityRequest",
        );
        let channel = connect(endpoint).await;
        let mut client = RuntimeAuthorityServiceClient::new(channel.clone())
            .max_decoding_message_size(LIMIT)
            .max_encoding_message_size(LIMIT);
        marker(
            within(client.check_runtime_authority(request(authority_request())))
                .await
                .unwrap_err(),
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let malformed =
            raw_call::<proto::RuntimeAuthoritySnapshot>(channel, AUTHORITY_PATH, BAD_TARGET).await;
        let after_malformed = calls.load(Ordering::SeqCst);
        // Check the healthy-after control even if the malformed status is wrong
        // under main's temporary default-codec RED selection.
        marker(
            within(client.check_runtime_authority(request(authority_request())))
                .await
                .unwrap_err(),
        );
        assert_eq!(
            after_malformed, 1,
            "malformed request must not reach handler"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        redacted(malformed);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generated_authority_client_redacts_actual_malformed_response_after_valid_request() {
    let service = MalformedReply::default();
    let state = service.clone();
    let router = Server::builder()
        .concurrency_limit_per_connection(1)
        .timeout(RPC)
        .add_service(service);
    exercise(router, move |endpoint| async move {
        malformed_control::<proto::RuntimeAuthoritySnapshot>(
            BAD_TARGET,
            "RuntimeAuthoritySnapshot",
        );
        let mut client = RuntimeAuthorityServiceClient::new(connect(endpoint).await)
            .max_decoding_message_size(LIMIT)
            .max_encoding_message_size(LIMIT);
        marker(
            within(client.check_runtime_authority(request(authority_request())))
                .await
                .unwrap_err(),
        );
        assert_eq!(state.calls.load(Ordering::SeqCst), 1);

        state.corrupt.store(true, Ordering::SeqCst);
        let malformed = within(client.check_runtime_authority(request(authority_request())))
            .await
            .unwrap_err();
        let after_malformed = state.calls.load(Ordering::SeqCst);
        state.corrupt.store(false, Ordering::SeqCst);
        marker(
            within(client.check_runtime_authority(request(authority_request())))
                .await
                .unwrap_err(),
        );
        assert_eq!(
            after_malformed, 2,
            "valid request reached raw-reply fixture"
        );
        assert_eq!(state.calls.load(Ordering::SeqCst), 3);
        redacted(malformed);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_generated_submit_command_redacts_actual_malformed_request_before_handler() {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = ControlGatewayServer::new(MarkerService(Arc::clone(&calls)))
        .max_decoding_message_size(LIMIT)
        .max_encoding_message_size(LIMIT);
    let router = Server::builder()
        .concurrency_limit_per_connection(1)
        .timeout(RPC)
        .add_service(service);
    exercise(router, move |endpoint| async move {
        malformed_control::<proto::ControlCommandRequest>(BAD_LEGACY, "ControlCommandRequest");
        let channel = connect(endpoint).await;
        let mut client = ControlGatewayClient::new(channel.clone())
            .max_decoding_message_size(LIMIT)
            .max_encoding_message_size(LIMIT);
        marker(
            within(client.submit_command(request(legacy_request())))
                .await
                .unwrap_err(),
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let malformed =
            raw_call::<proto::ControlCommandResponse>(channel, LEGACY_PATH, BAD_LEGACY).await;
        let after_malformed = calls.load(Ordering::SeqCst);
        marker(
            within(client.submit_command(request(legacy_request())))
                .await
                .unwrap_err(),
        );
        assert_eq!(
            after_malformed, 1,
            "malformed request must not reach legacy handler"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        redacted(malformed);
    })
    .await;
}
