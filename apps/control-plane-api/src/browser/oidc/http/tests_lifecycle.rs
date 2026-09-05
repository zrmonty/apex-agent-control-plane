use super::super::protocol::ProviderHttp;
use super::{BoundedProviderHttp, test_peer::*};
use crate::browser::errors::BrowserError;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::task::JoinSet;

#[tokio::test]
async fn configured_ca_accepts_trusted_peer_and_rejects_an_untrusted_server() {
    let trusted = Peer::start(Vec::new()).await;
    let http = BoundedProviderHttp::new(&trusted.config()).unwrap();
    assert_eq!(bounded(http.discovery()).await.unwrap(), JSON);
    let untrusted = Peer::start_at("127.0.0.1", "untrusted-host", Vec::new()).await;
    let http = BoundedProviderHttp::new(&untrusted.config()).unwrap();
    let error = bounded(http.discovery()).await.unwrap_err();
    assert_eq!(error, BrowserError::Unavailable);
    assert!(!format!("{error:?} {error}").contains("127.0.0.1"));
    assert!(std::error::Error::source(&error).is_none());
    assert!(
        untrusted.connections() >= 1,
        "test never exercised TLS verification"
    );
    assert!(untrusted.requests().is_empty());
}

#[tokio::test]
async fn trusted_ca_does_not_disable_server_name_verification() {
    // The generated certificate has 127.0.0.1/::1/localhost SANs, not 127.0.0.2.
    // Bind that second loopback address; no DNS override or weak client mode.
    let peer = Peer::start_at("127.0.0.2", "trusted-host", Vec::new()).await;
    let http = BoundedProviderHttp::new(&peer.config()).unwrap();
    assert_eq!(
        bounded(http.jwks()).await.unwrap_err(),
        BrowserError::Unavailable
    );
    assert!(
        peer.connections() >= 1,
        "wrong-name test never reached the TLS peer"
    );
    assert!(peer.requests().is_empty());
}

#[tokio::test]
async fn client_hello_blackhole_is_bounded_by_two_second_connect_deadline() {
    let peer = Blackhole::start().await;
    let http = BoundedProviderHttp::new(&fixture_config(peer.address)).unwrap();
    let started = Instant::now();
    let error = tokio::time::timeout(Duration::from_secs(4), http.discovery())
        .await
        .expect("TLS handshake exceeded the connect deadline")
        .unwrap_err();
    assert_eq!(error, BrowserError::Unavailable);
    assert!(
        started.elapsed() >= Duration::from_millis(1500),
        "failed before exercising the connect deadline"
    );
    peer.assert_client_hello();
}

#[tokio::test]
async fn provider_stalling_before_response_headers_hits_whole_call_deadline() {
    let peer = Peer::start(vec![Reply::stall()]).await;
    let config = peer.config();
    let http = BoundedProviderHttp::new(&config).unwrap();
    let started = Instant::now();
    assert_eq!(
        bounded(http.send(post(&config.token_endpoint)))
            .await
            .unwrap_err(),
        BrowserError::Unavailable
    );
    assert!(started.elapsed() >= Duration::from_millis(4500));
    assert!(started.elapsed() < Duration::from_millis(6500));
    assert_eq!(peer.requests().len(), 1);
}

#[tokio::test]
async fn five_second_deadline_includes_headers_and_stalled_body_without_resetting() {
    let partial =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"
            .to_vec();
    let peer = Peer::start(vec![Reply {
        pieces: vec![(Duration::from_secs(3), partial)],
        hold_open: true,
    }])
    .await;
    let http = BoundedProviderHttp::new(&peer.config()).unwrap();
    let started = Instant::now();
    assert_eq!(
        bounded(http.jwks()).await.unwrap_err(),
        BrowserError::Unavailable
    );
    assert!(started.elapsed() >= Duration::from_millis(4500));
    assert!(
        started.elapsed() < Duration::from_millis(6500),
        "body read started a fresh five-second budget"
    );
    assert_eq!(peer.requests().len(), 1);
    assert_eq!(
        bounded(http.jwks()).await.unwrap(),
        JSON,
        "timed-out call poisoned later calls"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn retained_unpolled_http_future_rejects_buffered_success_after_wall_deadline() {
    let peer = Peer::start(Vec::new()).await;
    let config = peer.config();
    let http = BoundedProviderHttp::new(&config).unwrap();
    // The same peer/config must support an on-time success first.
    assert_eq!(bounded(http.discovery()).await.unwrap(), JSON);

    let started = Instant::now();
    let response = http.send(post(&config.token_endpoint));
    tokio::pin!(response);
    // Drive the real request until the peer has received it, retaining rather
    // than cancelling the future. The biased observation branch prevents a
    // ready response from being consumed on the next select poll.
    tokio::select! {
        biased;
        _ = peer.wait_requests(2) => {}
        _ = &mut response => panic!("HTTP call completed before the fixture parked it"),
    }
    peer.wait_written_responses(2).await;
    // Let the independent hyper connection driver buffer the complete response
    // without polling the retained caller future or its timeout wrapper.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "fixture missed the pre-deadline window"
    );

    // Deliberately block this test-only single-thread executor: after resuming,
    // already-buffered success and an expired timer compete on the first poll.
    // No paused clock: the acceptance boundary is std::time::Instant. Tokio's
    // timeout_at polls the inner future first, so expiry must also be checked
    // after its await (and while consuming ready chunks), before returning Ok.
    std::thread::sleep(Duration::from_millis(5200));
    assert_eq!(
        bounded(&mut response).await.unwrap_err(),
        BrowserError::Unavailable
    );
    assert_eq!(
        peer.requests().len(),
        2,
        "late completion triggered another POST"
    );
    assert_eq!(peer.requests()[1].body, FORM);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_entrypoints_share_eight_nonqueued_permits_and_cancellation_releases_all() {
    let peer = Peer::start((0..16).map(|_| Reply::stall()).collect()).await;
    let config = peer.config();
    let http = Arc::new(BoundedProviderHttp::new(&config).unwrap());
    for batch in 0..2 {
        let mut calls = JoinSet::new();
        for index in 0..8 {
            let http = Arc::clone(&http);
            let uri = config.token_endpoint.clone();
            calls.spawn(async move {
                match index % 3 {
                    0 => http.discovery().await,
                    1 => http.jwks().await,
                    _ => http
                        .send(post(&uri))
                        .await
                        .map(|response| response.into_body()),
                }
            });
        }
        peer.wait_requests((batch + 1) * 8).await;
        let before = peer.connections();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            http.send(post(&config.revocation_endpoint)),
        )
        .await
        .expect("ninth request queued instead of failing admission immediately");
        assert!(matches!(
            result,
            Err(BrowserError::Unavailable | BrowserError::RateLimited)
        ));
        assert_eq!(
            peer.connections(),
            before,
            "over-capacity request reached the provider"
        );
        assert_eq!(peer.requests().len(), (batch + 1) * 8);
        calls.abort_all();
        while let Some(result) = calls.join_next().await {
            assert!(
                result.unwrap_err().is_cancelled(),
                "held provider request completed before cancellation"
            );
        }
    }
    assert_eq!(bounded(http.discovery()).await.unwrap(), JSON);
    assert_eq!(peer.requests().len(), 17);
}

#[tokio::test]
async fn fully_received_post_then_lost_reply_is_one_automatic_attempt() {
    // The peer records the entire POST body before dropping TLS. This is an
    // ambiguous transport failure, not an IdP refresh-rotation acceptance test.
    // This HTTP/1.1 peer does not inject HTTP/2 protocol NACKs; construction must
    // still explicitly disable reqwest's built-in retries with retry::never().
    let peer = Peer::start(vec![Reply::close()]).await;
    let config = peer.config();
    let http = BoundedProviderHttp::new(&config).unwrap();
    assert_eq!(
        bounded(http.send(post(&config.token_endpoint)))
            .await
            .unwrap_err(),
        BrowserError::Unavailable
    );
    let calls = peer.requests();
    assert_eq!(calls.len(), 1, "ambiguous POST was automatically retried");
    assert_eq!(calls[0].body, FORM);
    assert_eq!(calls[0].method, "POST");
    // A different safe GET demonstrates that the failure did not destroy the client.
    assert_eq!(bounded(http.jwks()).await.unwrap(), JSON);
    assert_eq!(peer.requests().len(), 2);
}

#[tokio::test]
async fn retry_after_provider_error_does_not_trigger_an_automatic_post_retry() {
    let body = br#"{"error":"temporarily_unavailable"}"#;
    let mut wire = format!("HTTP/1.1 503 Unavailable\r\nRetry-After: 0\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    wire.extend_from_slice(body);
    let peer = Peer::start(vec![Reply::wire(wire)]).await;
    let config = peer.config();
    let http = BoundedProviderHttp::new(&config).unwrap();
    let response = bounded(http.send(post(&config.token_endpoint)))
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(response.body(), body);
    assert_eq!(
        peer.requests().len(),
        1,
        "provider error caused an automatic POST retry"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn environment_proxies_do_not_intercept_provider_https() {
    const CHILD: &str = "APEX_OIDC_HTTP_TEST_PROXY_CHILD";
    if let Some(address) = std::env::var_os(CHILD) {
        let config = fixture_config(address.to_str().unwrap().parse().unwrap());
        let http = BoundedProviderHttp::new(&config).unwrap();
        assert_eq!(bounded(http.discovery()).await.unwrap(), JSON);
        return;
    }
    let target = Peer::start(Vec::new()).await;
    let proxy_trap = Peer::start(Vec::new()).await;
    let address = target.address;
    let proxy = format!("http://{}", proxy_trap.address);
    // Isolate env mutation in a subprocess. set_var is unsafe in a multithreaded
    // test runner and would race unrelated transport tests in this shared suite.
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "browser::oidc::http::tests_lifecycle::environment_proxies_do_not_intercept_provider_https", "--nocapture"])
        .env(CHILD, address.to_string()).env("NO_PROXY", "").env("no_proxy", "");
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env(name, &proxy);
    }
    // No captured, unbounded output and no blocking-pool task that can outlive
    // the timeout. The shared helper owns the exact child across cancellation.
    let child = command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let status = super::child::wait_child(
        Arc::new(std::sync::Mutex::new(child)),
        Instant::now() + Duration::from_secs(12),
    )
    .await
    .expect("proxy-isolation child exceeded its watchdog or could not be reaped");
    assert!(status.success(), "proxy-isolation child failed: {status}");
    assert_eq!(target.requests().len(), 1);
    assert_eq!(
        proxy_trap.connections(),
        0,
        "environment proxy intercepted provider HTTPS"
    );
}
