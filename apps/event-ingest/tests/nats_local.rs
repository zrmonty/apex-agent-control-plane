use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::PathBuf;
use std::thread;

use apex_event_ingest::{AsyncNatsJetStreamClient, NatsTlsConfig};

fn fixture_dir() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "apex-nats-local-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn local_tls_boundary_maps_handshake_failure_without_raw_transport_details() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut bytes = [0; 1024];
        let _ = stream.read(&mut bytes);
    });

    let root = fixture_dir();
    let ca = root.join("ca.pem");
    let cert = root.join("client-cert.pem");
    let key = root.join("client-key.pem");
    fs::write(
        &ca,
        b"-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----",
    )
    .unwrap();
    fs::write(
        &cert,
        b"-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----",
    )
    .unwrap();
    fs::write(
        &key,
        b"-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----",
    )
    .unwrap();
    let config = NatsTlsConfig {
        server_url: format!("tls://127.0.0.1:{port}"),
        ca_file: ca,
        client_cert_file: cert,
        client_key_file: key,
        username_file: None,
        password_file: None,
    };

    let error = match AsyncNatsJetStreamClient::connect(&config, &root) {
        Ok(_) => panic!("fixture must not complete a TLS handshake"),
        Err(error) => error,
    };
    assert_eq!(
        error.code,
        apex_event_ingest::GatewayErrorCode::NatsConnectionFailed
    );
    assert!(error.summary.contains("NATS"));
    assert!(!error.cause.contains("127.0.0.1"));
    server.join().unwrap();
}
