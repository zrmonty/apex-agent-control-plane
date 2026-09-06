//! Metadata parsing tests; positive TLS provenance is a separate network gate.
use super::*;
use tonic::metadata::MetadataValue;

fn metadata() -> MetadataMap {
    let mut result = MetadataMap::new();
    result.insert(
        "authorization",
        "Bearer managed-test-token-123".parse().unwrap(),
    );
    result.insert_bin(
        "apex-instance-proof-bin",
        MetadataValue::from_bytes(&[7; 32]),
    );
    result
}

#[test]
fn credential_parser_preserves_digests_and_rejects_ambiguous_metadata() {
    let input = metadata();
    let result = Presentation::parse(&input, [9; 32]).expect("bounded private parser");
    assert_eq!(result.certificate, [9; 32]);
    assert_eq!(
        result.token,
        <[u8; 32]>::from(Sha256::digest(b"managed-test-token-123"))
    );
    assert_eq!(result.proof, <[u8; 32]>::from(Sha256::digest([7; 32])));
    for malformed in [
        "Bearer short",
        "bearer managed-test-token-123",
        "Bearer  managed-test-token-123",
        "Bearer managed-test-token-123,second",
        "Bearer managed=test-token-123",
    ] {
        let mut input = metadata();
        input.insert("authorization", malformed.parse().unwrap());
        assert!(Presentation::parse(&input, [9; 32]).is_err());
    }
    for size in [0, 1, 31, 33, 64] {
        let mut input = metadata();
        input.insert_bin(
            "apex-instance-proof-bin",
            MetadataValue::from_bytes(&vec![7; size]),
        );
        assert!(Presentation::parse(&input, [9; 32]).is_err());
    }
    let mut input = metadata();
    input.append(
        "authorization",
        "Bearer managed-test-token-123".parse().unwrap(),
    );
    assert!(Presentation::parse(&input, [9; 32]).is_err());
    let mut input = metadata();
    input.append_bin(
        "apex-instance-proof-bin",
        MetadataValue::from_bytes(&[7; 32]),
    );
    assert!(Presentation::parse(&input, [9; 32]).is_err());
    assert!(Presentation::parse(&MetadataMap::new(), [9; 32]).is_err());
}

#[test]
fn synthetic_peer_extension_cannot_replace_the_real_tls_acceptor() {
    let mut request = tonic::Request::new(());
    *request.metadata_mut() = metadata();
    request.extensions_mut().insert(apex_auth::PeerIdentity {
        certificate_sha256: [9; 32],
    });
    assert!(Presentation::from_request(&request).is_err());
}
