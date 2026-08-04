use std::fs;

use super::client::NatsClient;
use super::config::{NatsTlsConfig, valid_endpoint, validate_secret_path};
use super::secrets::{read_auth_file, validate_pem_material};
use super::transport::{
    NatsJetStreamTransport, valid_message_id, valid_publish_subject, validate_publish_request,
};
use crate::{GatewayError, GatewayErrorCode, MAX_ENVELOPE_BYTES};

#[test]
fn endpoint_and_publish_validators_cover_host_and_port_edges() {
    assert!(valid_endpoint("nats.example:4222"));
    assert!(valid_endpoint("[2001:db8::1]:4222"));
    assert!(valid_endpoint("localhost"));
    for value in [
        "",
        ".host",
        "host.",
        "host:0",
        "host:abc",
        "host/path",
        "[bad]:4222",
    ] {
        assert!(!valid_endpoint(value));
    }
    assert!(valid_publish_subject("apex.workspace.prod"));
    assert!(!valid_publish_subject(""));
    assert!(!valid_publish_subject("apex..prod"));
    assert!(!valid_publish_subject("apex/../../secret"));
    assert!(valid_message_id("018f5c91:event"));
    assert!(!valid_message_id(""));
    assert!(!valid_message_id("bad id"));
}

#[test]
fn auth_and_pem_readers_reject_unsafe_material() {
    let root = std::env::temp_dir().join(format!("apex-nats-{}", std::process::id()));
    let _ = fs::create_dir_all(&root);
    let auth = root.join("auth");
    fs::write(&auth, "user\n").unwrap();
    assert_eq!(read_auth_file(&auth).unwrap(), "user");
    fs::write(&auth, b"bad value").unwrap();
    assert!(read_auth_file(&auth).is_err());
    let ca = root.join("ca.pem");
    let cert = root.join("cert.pem");
    let key = root.join("key.pem");
    fs::write(
        &ca,
        "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
    )
    .unwrap();
    fs::write(
        &cert,
        "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
    )
    .unwrap();
    fs::write(
        &key,
        "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----",
    )
    .unwrap();
    let config = NatsTlsConfig {
        server_url: "tls://localhost:4222".to_owned(),
        ca_file: ca,
        client_cert_file: cert,
        client_key_file: key,
        username_file: None,
        password_file: None,
    };
    assert!(validate_pem_material(&config).is_ok());
    let missing = NatsTlsConfig {
        ca_file: root.join("missing"),
        ..config
    };
    assert!(validate_pem_material(&missing).is_err());
}

#[test]
fn secret_paths_and_configuration_reject_escape_and_credential_mismatch() {
    let root = std::env::temp_dir().join(format!("apex-nats-path-{}", std::process::id()));
    let _ = fs::create_dir_all(&root);
    let ca = root.join("ca");
    let cert = root.join("cert");
    let key = root.join("key");
    fs::write(&ca, b"ca").unwrap();
    fs::write(&cert, b"cert").unwrap();
    fs::write(&key, b"key").unwrap();
    let base = root.canonicalize().unwrap();
    assert!(validate_secret_path(&ca, &base, false).is_ok());
    assert!(validate_secret_path(&root.join("missing"), &base, false).is_err());
    let config = NatsTlsConfig {
        server_url: "tls://localhost:4222".to_owned(),
        ca_file: ca,
        client_cert_file: cert,
        client_key_file: key,
        username_file: Some(root.join("user")),
        password_file: None,
    };
    assert!(config.validate(&base).is_err());
    assert!(
        NatsTlsConfig {
            server_url: "nats://localhost:4222".to_owned(),
            ..config
        }
        .validate(&base)
        .is_err()
    );
}

#[test]
fn auth_reader_rejects_binary_and_oversized_values() {
    let root = std::env::temp_dir().join(format!("apex-nats-auth-{}", std::process::id()));
    let _ = fs::create_dir_all(&root);
    let path = root.join("auth");
    fs::write(&path, [0xff, 0xfe]).unwrap();
    assert!(read_auth_file(&path).is_err());
    fs::write(&path, vec![b'a'; 4097]).unwrap();
    assert!(read_auth_file(&path).is_err());
}

#[test]
fn transport_constructor_preserves_validated_configuration() {
    struct Noop;
    impl NatsClient for Noop {
        fn publish(&mut self, _: &str, _: &str, _: &[u8]) -> Result<(), GatewayError> {
            Ok(())
        }
    }
    let root = std::env::temp_dir().join(format!("apex-nats-transport-{}", std::process::id()));
    let _ = fs::create_dir_all(&root);
    let ca = root.join("ca");
    let cert = root.join("cert");
    let key = root.join("key");
    fs::write(&ca, b"ca").unwrap();
    fs::write(&cert, b"cert").unwrap();
    fs::write(&key, b"key").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let config = NatsTlsConfig {
        server_url: "tls://localhost:4222".to_owned(),
        ca_file: ca,
        client_cert_file: cert,
        client_key_file: key,
        username_file: None,
        password_file: None,
    };
    let transport = NatsJetStreamTransport::new(Noop, config, &root).unwrap();
    assert_eq!(transport.config().server_url, "tls://localhost:4222");
}

#[test]
fn publish_request_rejects_empty_oversized_and_invalid_inputs() {
    assert!(validate_publish_request("apex.events", "id", b"event").is_ok());
    assert_eq!(
        validate_publish_request("", "id", b"event")
            .unwrap_err()
            .code,
        GatewayErrorCode::InvalidNatsPublishRequest
    );
    assert_eq!(
        validate_publish_request("apex.events", "", b"event")
            .unwrap_err()
            .code,
        GatewayErrorCode::InvalidNatsPublishRequest
    );
    assert_eq!(
        validate_publish_request("apex.events", "id", &vec![0; MAX_ENVELOPE_BYTES + 1])
            .unwrap_err()
            .code,
        GatewayErrorCode::PayloadTooLarge
    );
}
