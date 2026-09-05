use super::super::protocol::{ProtocolClient, ProviderHttp, TokenRequest};
use super::{BoundedProviderHttp, test_peer::*};
use crate::browser::errors::BrowserError;
use std::time::Duration;

fn sized_json(size: usize) -> Vec<u8> {
    let body = format!(r#"{{"padding":"{}"}}"#, "x".repeat(size - 14)).into_bytes();
    assert_eq!(body.len(), size);
    body
}

#[tokio::test]
async fn response_accepts_exactly_65536_bytes_for_length_chunked_and_eof_framing() {
    let body = sized_json(65536);
    let mut eof =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n".to_vec();
    eof.extend_from_slice(&body);
    for wire in [
        response(200, Some("application/json"), &body),
        chunked(&body, "", true),
        eof,
    ] {
        let peer = Peer::start(vec![Reply::wire(wire)]).await;
        let http = BoundedProviderHttp::new(&peer.config()).unwrap();
        assert_eq!(bounded(http.jwks()).await.unwrap(), body);
        assert_eq!(peer.requests().len(), 1);
    }
}

#[tokio::test]
async fn oversized_chunked_and_eof_bodies_are_stopped_before_waiting_for_end_of_body() {
    let body = sized_json(65537);
    let mut eof =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n".to_vec();
    eof.extend_from_slice(&body);
    for wire in [chunked(&body, "", false), eof] {
        let peer = Peer::start(vec![Reply {
            pieces: vec![(Duration::ZERO, wire)],
            hold_open: true,
        }])
        .await;
        let http = BoundedProviderHttp::new(&peer.config()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), http.jwks())
            .await
            .expect("reader waited for EOF instead of enforcing the streaming byte ceiling");
        assert!(result.is_err());
        assert_eq!(peer.requests().len(), 1);
    }
}

#[tokio::test]
async fn oversized_declared_length_is_rejected_without_waiting_for_body() {
    let wire =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 65537\r\n\r\n"
            .to_vec();
    let peer = Peer::start(vec![Reply {
        pieces: vec![(Duration::ZERO, wire)],
        hold_open: true,
    }])
    .await;
    let http = BoundedProviderHttp::new(&peer.config()).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), http.discovery())
        .await
        .expect("oversized Content-Length was not rejected at headers");
    assert!(result.is_err());
    assert_eq!(peer.requests().len(), 1);
}

#[tokio::test]
async fn oauth_token_revocation_and_error_bodies_share_the_response_byte_ceiling() {
    let oversized = sized_json(65537);
    let peer = Peer::start(vec![
        Reply::json(200, &oversized),
        Reply::json(400, &oversized),
        Reply::json(200, &oversized),
        Reply::json(400, &oversized),
    ])
    .await;
    let config = peer.config();
    let http = BoundedProviderHttp::new(&config).unwrap();
    for uri in [
        &config.token_endpoint,
        &config.token_endpoint,
        &config.revocation_endpoint,
        &config.revocation_endpoint,
    ] {
        assert!(bounded(http.send(post(uri))).await.is_err());
    }
    assert_eq!(peer.requests().len(), 4);
}

#[tokio::test]
async fn lying_or_conflicting_content_length_cannot_bypass_json_and_byte_limits() {
    let mut short = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1\r\nConnection: close\r\n\r\n".to_vec();
    short.extend_from_slice(JSON);
    let mut truncated = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 42\r\nConnection: close\r\n\r\n".to_vec();
    truncated.extend_from_slice(JSON);
    let conflict = chunked(&sized_json(65537), "Content-Length: 1\r\n", true);
    for wire in [short, truncated, conflict] {
        let peer = Peer::start(vec![Reply::wire(wire)]).await;
        let http = BoundedProviderHttp::new(&peer.config()).unwrap();
        assert!(bounded(http.jwks()).await.is_err());
        assert_eq!(peer.requests().len(), 1);
    }
}

#[tokio::test]
async fn malformed_duplicate_escaped_duplicate_and_nested_duplicate_json_are_rejected() {
    let invalid: &[&[u8]] = &[
        br#"{"key":null,"key":1}"#,
        br#"{"key":1,"\u006bey":2}"#,
        br#"{"nested":{"key":1,"key":2}}"#,
        br#"{"items":[{"key":1,"key":2}]}"#,
        br#"{"key":1} {"other":2}"#,
        br#"{"key":}"#,
        b"\xff",
        b"",
    ];
    for body in invalid {
        let peer = Peer::start(vec![Reply::json(200, body), Reply::json(400, body)]).await;
        let config = peer.config();
        let http = BoundedProviderHttp::new(&config).unwrap();
        assert!(bounded(http.discovery()).await.is_err());
        assert!(
            bounded(http.send(post(&config.token_endpoint)))
                .await
                .is_err(),
            "OAuth error body bypassed unique JSON gate"
        );
        assert_eq!(peer.requests().len(), 2);
    }
}

#[tokio::test]
async fn json_requires_exact_single_content_type_on_success_and_oauth_error_bodies() {
    for content_type in [
        None,
        Some("text/html"),
        Some("application/jwk-set+json"),
        Some("application/json; charset=utf-8"),
        Some("application/json, text/html"),
    ] {
        let peer = Peer::start(vec![
            Reply::wire(response(200, content_type, JSON)),
            Reply::wire(response(400, content_type, br#"{"error":"invalid_grant"}"#)),
        ])
        .await;
        let config = peer.config();
        let http = BoundedProviderHttp::new(&config).unwrap();
        assert!(bounded(http.jwks()).await.is_err());
        assert!(
            bounded(http.send(post(&config.token_endpoint)))
                .await
                .is_err()
        );
        assert_eq!(peer.requests().len(), 2);
    }
    for second in ["application/json", "text/html"] {
        let wire = format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\nContent-Type: {second}\r\nConnection: close\r\n\r\n{{}}").into_bytes();
        let peer = Peer::start(vec![Reply::wire(wire)]).await;
        let http = BoundedProviderHttp::new(&peer.config()).unwrap();
        assert!(bounded(http.discovery()).await.is_err());
    }
}

#[tokio::test]
async fn content_encoding_is_rejected_including_chunked_and_oauth_error_responses() {
    for encoding in ["gzip", "br", "deflate", "zstd", "gzip, br"] {
        let success = chunked(JSON, &format!("Content-Encoding: {encoding}\r\n"), true);
        let error = format!("HTTP/1.1 400 Error\r\nContent-Type: application/json\r\nContent-Encoding: {encoding}\r\nContent-Length: 25\r\nConnection: close\r\n\r\n{{\"error\":\"invalid_grant\"}}").into_bytes();
        let peer = Peer::start(vec![Reply::wire(success), Reply::wire(error)]).await;
        let config = peer.config();
        let http = BoundedProviderHttp::new(&config).unwrap();
        assert!(bounded(http.discovery()).await.is_err());
        assert!(
            bounded(http.send(post(&config.token_endpoint)))
                .await
                .is_err()
        );
        assert_eq!(peer.requests().len(), 2);
    }
}

#[tokio::test]
async fn bounded_unique_oauth_error_json_reaches_protocol_mapper_without_detail_leak() {
    let error_body = br#"{"error":"invalid_grant","error_description":"provider-secret-canary","error_uri":"https://private.example/secret-canary"}"#;
    let peer = Peer::start(vec![
        Reply::json(400, error_body),
        Reply::json(400, error_body),
    ])
    .await;
    let config = peer.config();
    let http = BoundedProviderHttp::new(&config).unwrap();
    let response = bounded(http.send(post(&config.token_endpoint)))
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert_eq!(response.body(), error_body);
    let protocol = ProtocolClient::new(&config).unwrap();
    let error = bounded(protocol.exchange(
        TokenRequest::Refresh {
            token: "old-refresh",
        },
        &http,
    ))
    .await
    .err()
    .unwrap();
    assert_eq!(error, BrowserError::Unauthenticated);
    assert!(!format!("{error:?} {error}").contains("canary"));
    assert!(std::error::Error::source(&error).is_none());
    assert_eq!(peer.requests().len(), 2);
}

#[tokio::test]
async fn provider_html_errors_and_failed_metadata_requests_are_redacted() {
    let peer = Peer::start(vec![
        Reply::wire(response(
            502,
            Some("text/html"),
            b"<html>provider-secret-canary</html>",
        )),
        Reply::json(503, br#"{"error_description":"provider-secret-canary"}"#),
    ])
    .await;
    let config = peer.config();
    let http = BoundedProviderHttp::new(&config).unwrap();
    let errors = [
        bounded(http.send(post(&config.token_endpoint)))
            .await
            .err()
            .unwrap(),
        bounded(http.discovery()).await.err().unwrap(),
    ];
    for error in errors {
        assert_eq!(error, BrowserError::Unavailable);
        assert!(!format!("{error:?} {error}").contains("canary"));
        assert!(std::error::Error::source(&error).is_none());
    }
    assert_eq!(peer.requests().len(), 2);
}

#[tokio::test]
async fn only_successful_revocation_can_return_an_empty_body() {
    let peer = Peer::start(vec![
        Reply::wire(response(200, None, b"")),
        Reply::wire(response(200, None, b"")),
        Reply::wire(response(200, None, b"")),
        Reply::wire(response(204, None, b"")),
        Reply::wire(response(400, None, b"")),
    ])
    .await;
    let config = peer.config();
    let http = BoundedProviderHttp::new(&config).unwrap();
    let response = bounded(http.send(post(&config.revocation_endpoint)))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.body().is_empty());
    assert!(
        bounded(http.send(post(&config.token_endpoint)))
            .await
            .is_err()
    );
    assert!(bounded(http.discovery()).await.is_err());
    assert!(
        bounded(http.send(post(&config.revocation_endpoint)))
            .await
            .is_err()
    );
    assert!(
        bounded(http.send(post(&config.revocation_endpoint)))
            .await
            .is_err()
    );
    assert_eq!(peer.requests().len(), 5);
}

#[tokio::test]
async fn every_redirect_status_fails_without_a_request_to_the_target() {
    let target = Peer::start(Vec::new()).await;
    for status in [301, 302, 303, 307, 308] {
        let wire = format!("HTTP/1.1 {status} Redirect\r\nLocation: https://{}/secret-canary\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", target.address).into_bytes();
        let peer = Peer::start(vec![
            Reply::wire(wire.clone()),
            Reply::wire(wire.clone()),
            Reply::wire(wire),
        ])
        .await;
        let config = peer.config();
        let http = BoundedProviderHttp::new(&config).unwrap();
        let errors = [
            bounded(http.discovery()).await.err().unwrap(),
            bounded(http.jwks()).await.err().unwrap(),
            bounded(http.send(post(&config.token_endpoint)))
                .await
                .err()
                .unwrap(),
        ];
        for error in errors {
            assert_eq!(error, BrowserError::Unavailable);
            assert!(!format!("{error:?} {error}").contains("canary"));
        }
        assert_eq!(peer.requests().len(), 3);
    }
    assert_eq!(
        target.connections(),
        0,
        "redirect target received network traffic"
    );
}
