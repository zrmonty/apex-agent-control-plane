use super::peer::{Mode, Peer};
use super::support::*;
use apex_control_plane_api::{
    MAX_CONTROL_REQUEST_BYTES,
    browser::{errors::BrowserError, rpc::MAX_RPC_RESPONSE_BYTES},
    proto,
};
use prost::Message;
use serde_json::{Value, json};

#[tokio::test]
async fn oversized_grpc_response_is_rejected_by_the_production_decoder_over_mtls() {
    let pki = Pki::require();
    let peer = Peer::start(&pki, Mode::OversizedResponse).await;
    // A separately bounded client proves the peer actually sends a valid
    // oversized protobuf rather than rejecting its own encoding operation.
    let mut raw = within(raw_client(&pki, &peer.target, true)).await.unwrap();
    let reply = within(
        raw.get_proxy_capabilities(raw_request(proto::GetProxyCapabilitiesRequest::default())),
    )
    .await
    .unwrap()
    .into_inner();
    assert!(reply.encoded_len() > MAX_CONTROL_REQUEST_BYTES);
    assert!(reply.encoded_len() < TEST_SERVER_MESSAGE_LIMIT);
    assert!(serde_json::to_vec(&reply).unwrap().len() < MAX_RPC_RESPONSE_BYTES);

    let bridge = connect(&pki, &peer.target, RPC_TIMEOUT).await;
    let outcome =
        within(bridge.forward(decode("GetProxyCapabilities", &json!({})), &access())).await;
    assert!(
        outcome.is_err(),
        "oversized protobuf reached the JSON response writer"
    );
    assert_eq!(peer.state.capability_replies(), 2);
    assert_eq!(peer.state.rpc_calls(), 2);
    assert!(peer.state.peer_identity_and_metadata_match());
    drop(raw);
    drop(bridge);
    peer.shutdown().await;
}

#[tokio::test]
async fn committed_mutation_with_lost_reply_is_not_retried_until_caller_reuses_its_uuid() {
    let pki = Pki::require();
    let peer = Peer::start(&pki, Mode::DelayFirstCreateReply).await;
    let bridge = connect(&pki, &peer.target, RPC_TIMEOUT).await;
    let request_id = uuid::Uuid::now_v7().to_string();
    let proxy_id = uuid::Uuid::now_v7().to_string();
    let body = json!({
        "requestId": request_id,
        "workspaceId": "work",
        "namespaceId": "ns",
        "proxyId": proxy_id,
        "displayName": "Committed before reply loss",
        "slug": "committed-before-reply-loss"
    });
    let first_request = decode("CreateProxy", &body);
    let first_bridge = bridge.clone();
    let first =
        TestTask::spawn(async move { first_bridge.forward(first_request, &access()).await });
    // This signal follows successful completion of the real create handler,
    // including its state write and event sink. The fixture then withholds
    // only the reply; it never fabricates the business/idempotency outcome.
    within(peer.state.committed.notified()).await;
    let committed = peer.state.committed_response();
    assert!(!committed.duplicate);
    assert_eq!(committed.proxy.as_ref().unwrap().proxy_id, proxy_id);
    assert_eq!(first.join().await, Err(BrowserError::Unavailable));
    assert_eq!(peer.state.create_ids(), vec![request_id.clone()]);

    // Observe the committed resource through a public RPC before any retry.
    // The same bridge also proves the timed-out call released admission.
    let fetched = within(bridge.forward(
        decode(
            "GetProxy",
            &json!({
                "workspaceId": "work", "namespaceId": "ns", "proxyId": proxy_id
            }),
        ),
        &access(),
    ))
    .await
    .unwrap();
    let fetched: Value = serde_json::from_slice(&fetched).unwrap();
    let original = serde_json::to_value(committed).unwrap();
    assert_eq!(fetched["proxy"], original["proxy"]);
    assert_eq!(peer.state.create_ids(), vec![request_id.clone()]);

    // This is an explicit caller retry with exactly the original UUID/body.
    let retry = within(bridge.forward(decode("CreateProxy", &body), &access()))
        .await
        .unwrap();
    let retry: Value = serde_json::from_slice(&retry).unwrap();
    assert_eq!(retry["duplicate"], true);
    assert_eq!(retry["proxy"], original["proxy"]);
    assert_eq!(
        peer.state.create_ids(),
        vec![request_id.clone(), request_id]
    );
    let listed = within(bridge.forward(list_request(), &access()))
        .await
        .unwrap();
    let listed: Value = serde_json::from_slice(&listed).unwrap();
    assert_eq!(listed["proxies"].as_array().unwrap().len(), 1);
    assert!(peer.state.peer_identity_and_metadata_match());
    drop(bridge);
    peer.shutdown().await;
}
