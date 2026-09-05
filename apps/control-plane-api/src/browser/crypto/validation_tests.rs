use super::tests::*;
use super::*;
use std::error::Error;
use zeroize::Zeroizing;

#[test]
fn record_digest_is_sha256_of_exact_bounded_identifier_bytes() {
    let expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    let digest = RecordDigest::of_record_id(b"abc").unwrap();
    assert_eq!(digest.as_bytes(), &expected);
    assert_eq!(RecordDigest::from_sha256(&expected).unwrap(), digest);
    assert_ne!(RecordDigest::of_record_id(b"abc\0").unwrap(), digest);
    assert!(RecordDigest::of_record_id(&[7; 1_024]).is_ok());
    assert!(RecordDigest::of_record_id(&[]).is_err());
    assert!(RecordDigest::of_record_id(&[7; 1_025]).is_err());
    for size in [0, 31, 33, 1_024] {
        assert!(RecordDigest::from_sha256(&vec![7; size]).is_err());
    }
}

#[test]
fn malformed_key_ids_are_rejected_for_config_and_storage() {
    let too_long = "k".repeat(65);
    for id in [
        "",
        " ",
        "key id",
        "key\n",
        "key/one",
        "key\0",
        "κλειδί",
        too_long.as_str(),
    ] {
        assert!(TokenKey::active(id, Zeroizing::new([1; 32])).is_err());
        assert!(TokenKey::retired(id, Zeroizing::new([1; 32]), EXPIRY).is_err());
        assert!(TokenEnvelope::from_storage(1, id, &[0; 24], &[0; 16]).is_err());
    }
    for id in ["A_1-key.v1", "k".repeat(64).as_str()] {
        let keyring = TokenKeyring::new(vec![active(id, 1)]).unwrap();
        let sealed = keyring.seal(TOKEN, &binding(), NOW).unwrap();
        assert_eq!(sealed.key_id(), id);
        assert_eq!(
            keyring
                .open(&sealed, &binding(), NOW)
                .unwrap()
                .expose_bytes(),
            TOKEN
        );
    }
}

#[test]
fn keyring_requires_exactly_one_active_key_unique_ids_and_at_most_four_keys() {
    assert!(TokenKeyring::new(vec![]).is_err());
    assert!(TokenKeyring::new(vec![retired("old", 1, EXPIRY)]).is_err());
    assert!(TokenKeyring::new(vec![active("a", 1), active("b", 2)]).is_err());
    assert!(TokenKeyring::new(vec![active("same", 1), retired("same", 2, EXPIRY)]).is_err());
    assert!(
        TokenKeyring::new(vec![
            active("a", 1),
            retired("b", 2, EXPIRY),
            retired("b", 3, EXPIRY),
        ])
        .is_err()
    );
    assert!(
        TokenKeyring::new(vec![
            active("a", 1),
            retired("b", 2, EXPIRY),
            retired("c", 3, EXPIRY),
            retired("d", 4, EXPIRY),
            retired("e", 5, EXPIRY),
        ])
        .is_err()
    );
    for expiry in [0, -1, i64::MIN] {
        assert!(TokenKey::retired("old", Zeroizing::new([1; 32]), expiry).is_err());
    }
}

#[test]
fn unsupported_version_and_malformed_storage_lengths_fail_at_the_boundary() {
    for version in [0, 2, 255, u32::MAX] {
        assert_eq!(
            TokenEnvelope::from_storage(version, "key", &[0; 24], &[0; 16]).unwrap_err(),
            CryptoError::UnsupportedVersion,
        );
    }
    for nonce_len in [0, 12, 23, 25, 1_024] {
        assert!(TokenEnvelope::from_storage(1, "key", &vec![0; nonce_len], &[0; 16]).is_err());
    }
    for ciphertext_len in [0, 1, 15, 65_553, 131_072] {
        assert!(TokenEnvelope::from_storage(1, "key", &[0; 24], &vec![0; ciphertext_len]).is_err());
    }
    // Structural validity is distinct from authenticating the AEAD tag.
    for ciphertext_len in [16, 65_552] {
        let invalid_tag =
            TokenEnvelope::from_storage(1, "key-2026-09", &[0; 24], &vec![0; ciphertext_len])
                .unwrap();
        assert_eq!(
            ring().open(&invalid_tag, &binding(), NOW).unwrap_err(),
            CryptoError::AuthenticationFailed
        );
    }
}

#[test]
fn binding_rejects_missing_or_malformed_metadata_and_invalid_expiry() {
    let too_long_issuer = "i".repeat(2_049);
    let too_long_client = "c".repeat(257);
    let too_long_subject = "s".repeat(513);
    for bad in ["", " ", "\n", "value\0", "value\u{7f}", " value", "value "] {
        assert!(
            TokenBinding::new(
                EnvelopePurpose::OperatorSession,
                digest(),
                bad,
                CLIENT,
                Some(SUBJECT),
                EXPIRY
            )
            .is_err()
        );
        assert!(
            TokenBinding::new(
                EnvelopePurpose::OperatorSession,
                digest(),
                ISSUER,
                bad,
                Some(SUBJECT),
                EXPIRY
            )
            .is_err()
        );
        assert!(
            TokenBinding::new(
                EnvelopePurpose::OperatorSession,
                digest(),
                ISSUER,
                CLIENT,
                Some(bad),
                EXPIRY
            )
            .is_err()
        );
    }
    assert!(
        TokenBinding::new(
            EnvelopePurpose::OperatorSession,
            digest(),
            &too_long_issuer,
            CLIENT,
            Some(SUBJECT),
            EXPIRY
        )
        .is_err()
    );
    assert!(
        TokenBinding::new(
            EnvelopePurpose::OperatorSession,
            digest(),
            ISSUER,
            &too_long_client,
            Some(SUBJECT),
            EXPIRY
        )
        .is_err()
    );
    assert!(
        TokenBinding::new(
            EnvelopePurpose::OperatorSession,
            digest(),
            ISSUER,
            CLIENT,
            Some(&too_long_subject),
            EXPIRY
        )
        .is_err()
    );
    assert!(
        TokenBinding::new(
            EnvelopePurpose::OperatorSession,
            digest(),
            ISSUER,
            CLIENT,
            None,
            EXPIRY
        )
        .is_err()
    );
    for expiry in [0, -1, i64::MIN] {
        assert!(
            TokenBinding::new(
                EnvelopePurpose::LoginAttempt,
                digest(),
                ISSUER,
                CLIENT,
                None,
                expiry
            )
            .is_err()
        );
    }
}

#[test]
fn maximum_binding_lengths_roundtrip_without_normalizing_identity_bytes() {
    let issuer = format!("https://issuer.example/{}", "i".repeat(2_025));
    assert_eq!(issuer.len(), 2_048);
    let client = "c".repeat(256);
    let subject = "é".repeat(256);
    let binding = TokenBinding::new(
        EnvelopePurpose::OperatorSession,
        digest(),
        &issuer,
        &client,
        Some(&subject),
        EXPIRY,
    )
    .unwrap();
    let keyring = ring();
    let sealed = keyring.seal(TOKEN, &binding, NOW).unwrap();
    assert_eq!(
        keyring.open(&sealed, &binding, NOW).unwrap().expose_bytes(),
        TOKEN
    );
}

#[test]
fn debug_redacts_keys_plaintext_binding_and_envelope_contents() {
    let key = active("fixture-sensitive-key-id", 0x41);
    let key_debug = format!("{key:?} {key:#?}");
    let keyring = TokenKeyring::new(vec![key]).unwrap();
    let binding = binding();
    let envelope = keyring.seal(TOKEN, &binding, NOW).unwrap();
    let plaintext = keyring.open(&envelope, &binding, NOW).unwrap();
    let debug = format!(
        "{key_debug} {keyring:?} {keyring:#?} {binding:?} {binding:#?} {envelope:?} {envelope:#?} {plaintext:?} {plaintext:#?} {:?}",
        digest(),
    );
    for sensitive in [
        "fixture-sensitive-key-id".to_owned(),
        ISSUER.to_owned(),
        CLIENT.to_owned(),
        SUBJECT.to_owned(),
        "fixture-access-token".to_owned(),
        "fixture-refresh-token".to_owned(),
        format!("{:?}", [0x41_u8; 32]),
        format!("{:?}", TOKEN),
        format!("{:?}", envelope.ciphertext()),
        format!("{:?}", envelope.nonce()),
        format!("{:?}", digest().as_bytes()),
    ] {
        assert!(!debug.contains(&sensitive));
    }
}

#[test]
fn actual_failures_expose_only_static_errors_without_source_chains() {
    let keyring = ring();
    let sealed = keyring.seal(TOKEN, &binding(), NOW).unwrap();
    let wrong = TokenBinding::new(
        EnvelopePurpose::OperatorSession,
        digest(),
        ISSUER,
        CLIENT,
        Some("fixture-private-subject"),
        EXPIRY,
    )
    .unwrap();
    let errors = [
        keyring.open(&sealed, &wrong, NOW).unwrap_err(),
        keyring.open(&sealed, &binding(), EXPIRY).unwrap_err(),
        keyring
            .seal(&vec![0x41; 65_537], &binding(), NOW)
            .unwrap_err(),
        TokenKey::active("fixture-secret\nkey", Zeroizing::new([0x41; 32])).unwrap_err(),
        TokenEnvelope::from_storage(1, "fixture-secret\nkey", &[0; 24], TOKEN).unwrap_err(),
    ];
    for error in errors {
        let rendered = format!("{error} {error:?} {error:#?}");
        assert!(error.source().is_none());
        assert!(rendered.len() < 256);
        for sensitive in ["fixture", ISSUER, CLIENT, SUBJECT, "65, 65, 65"] {
            assert!(!rendered.contains(sensitive));
        }
    }
}
