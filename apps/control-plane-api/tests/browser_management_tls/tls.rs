use super::peer::{Mode, Peer};
use super::support::*;
use apex_control_plane_api::browser::{errors::BrowserError, rpc::ManagementBridge};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

#[tokio::test]
async fn production_bridge_authenticates_server_and_dedicated_client_then_resolves_operator() {
    let pki = Pki::require();
    let peer = Peer::start(&pki, Mode::Real).await;
    let bridge = connect(&pki, &peer.target, RPC_TIMEOUT).await;
    assert_eq!(
        access().caller().subject(),
        "operator:keycloak:browser-tls-component"
    );
    assert_eq!(
        within(bridge.forward(list_request(), &access()))
            .await
            .unwrap(),
        b"{}"
    );
    assert_eq!(peer.state.rpc_calls(), 1);
    assert!(peer.state.peer_identity_and_metadata_match());

    // A credential accepted by a different edge resolver still has to pass
    // the real peer's resolver. The client certificate is already valid.
    let unknown = access_for("not-in-the-peer-operator-table");
    assert_eq!(
        within(bridge.forward(list_request(), &unknown)).await,
        Err(BrowserError::Unauthenticated)
    );
    drop(bridge);
    peer.shutdown().await;
}

#[tokio::test]
async fn production_bridge_rejects_wrong_server_name_before_any_rpc() {
    let pki = Pki::require();
    let peer = Peer::start(&pki, Mode::Real).await;
    peer.assert_healthy(&pki).await;
    let mut config = pki.config(&peer.target, RPC_TIMEOUT);
    config.server_name = "wrong-control-name.invalid".into();
    peer.assert_rejected_before_rpc(config).await;
    peer.shutdown().await;
}

#[tokio::test]
async fn production_bridge_rejects_server_signed_by_an_untrusted_ca() {
    let pki = Pki::require();
    let peer = Peer::start(&pki, Mode::Real).await;
    peer.assert_healthy(&pki).await;
    let mut config = pki.config(&peer.target, RPC_TIMEOUT);
    config.ca_pem = pki.untrusted("ca.pem");
    peer.assert_rejected_before_rpc(config).await;
    peer.shutdown().await;
}

#[tokio::test]
async fn production_bridge_cannot_use_a_client_identity_outside_the_peers_trust() {
    let pki = Pki::require();
    let peer = Peer::start(&pki, Mode::Real).await;
    peer.assert_healthy(&pki).await;
    let mut config = pki.config(&peer.target, RPC_TIMEOUT);
    // Keep the correct server CA/name; change only the client issuer.
    config.client_certificate_pem = pki.untrusted("control-operator-client.pem");
    config.client_key_pem = Zeroizing::new(pki.untrusted("control-operator-client.key"));
    peer.assert_rejected_before_rpc(config).await;
    peer.shutdown().await;
}

#[tokio::test]
async fn production_bridge_rejects_missing_invalid_and_mismatched_client_material() {
    let pki = Pki::require();
    let peer = Peer::start(&pki, Mode::Real).await;
    peer.assert_healthy(&pki).await;
    for case in 0..4 {
        let mut config = pki.config(&peer.target, RPC_TIMEOUT);
        match case {
            0 => config.client_key_pem.clear(),
            1 => config.client_key_pem = Zeroizing::new(b"not a PEM private key".to_vec()),
            2 => {
                config.client_key_pem =
                    Zeroizing::new(pki.untrusted("control-operator-client.key"));
            }
            _ => config.client_certificate_pem.clear(),
        }
        peer.assert_rejected_before_rpc(config).await;
    }
    peer.shutdown().await;
}

#[tokio::test]
async fn tls_peer_requires_a_client_certificate_even_with_a_valid_operator_token() {
    let pki = Pki::require();
    let peer = Peer::start(&pki, Mode::Real).await;
    peer.assert_healthy(&pki).await;
    let before = peer.state.rpc_calls();
    // Independent negative control: the production constructor correctly
    // refuses empty identity material before it can test the peer's TLS gate.
    let rejected = within(async {
        match raw_client(&pki, &peer.target, false).await {
            Err(_) => true,
            Ok(mut client) => client
                .list_proxies(raw_request(list_input()))
                .await
                .is_err(),
        }
    })
    .await;
    assert!(rejected, "peer accepted a TLS client without a certificate");
    assert_eq!(
        peer.state.rpc_calls(),
        before,
        "TLS refusal must precede RPC dispatch"
    );
    peer.shutdown().await;
}

#[tokio::test]
async fn production_connect_deadline_covers_a_real_tls_client_hello_blackhole() {
    let pki = Pki::require();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!("https://{}", listener.local_addr().unwrap());
    let mut config = pki.config(&target, RPC_TIMEOUT);
    config.connect_timeout = Duration::from_secs(1);
    let deadline = config.connect_timeout;
    let started = Instant::now();
    let connecting = TestTask::spawn(async move { ManagementBridge::connect(config).await });
    let (mut socket, _) = within(listener.accept()).await.unwrap();
    let mut hello = [0_u8; 6];
    within(socket.read_exact(&mut hello)).await.unwrap();
    assert_eq!(hello[0], 0x16, "client must send a TLS handshake record");
    assert_eq!(hello[1], 0x03, "TLS record version must be present");
    assert_eq!(hello[5], 0x01, "handshake must start with ClientHello");
    // Keep the accepted socket open but never send ServerHello. A TCP refusal
    // or a plaintext HTTP/2 readiness stall cannot satisfy this test.
    assert!(matches!(
        connecting.join().await,
        Err(BrowserError::Unavailable)
    ));
    assert!(
        started.elapsed() >= deadline,
        "connection failed before the configured deadline"
    );
    drop(socket);
}
