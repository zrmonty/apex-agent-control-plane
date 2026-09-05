//! Behavioral contract: these tests deliberately precede the implementation.

use super::*;
use std::collections::HashSet;
use zeroize::Zeroizing;

pub(super) const NOW: i64 = 1_788_480_000;
pub(super) const EXPIRY: i64 = NOW + 3_600;
pub(super) const ISSUER: &str = "https://issuer.example/realms/operators";
pub(super) const CLIENT: &str = "browser-client";
pub(super) const SUBJECT: &str = "operator:keycloak:alice";
pub(super) const TOKEN: &[u8] = b"fixture-access-token\0fixture-refresh-token\xff";

pub(super) fn active(id: &str, byte: u8) -> TokenKey {
    TokenKey::active(id, Zeroizing::new([byte; 32])).unwrap()
}

pub(super) fn retired(id: &str, byte: u8, until: i64) -> TokenKey {
    TokenKey::retired(id, Zeroizing::new([byte; 32]), until).unwrap()
}

pub(super) fn ring() -> TokenKeyring {
    TokenKeyring::new(vec![active("key-2026-09", 0x41)]).unwrap()
}

pub(super) fn digest() -> RecordDigest {
    RecordDigest::of_record_id(b"fixture-opaque-session-id").unwrap()
}

pub(super) fn binding() -> TokenBinding<'static> {
    TokenBinding::new(
        EnvelopePurpose::OperatorSession,
        digest(),
        ISSUER,
        CLIENT,
        Some(SUBJECT),
        EXPIRY,
    )
    .unwrap()
}

fn stored_with(
    envelope: &TokenEnvelope,
    key_id: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> TokenEnvelope {
    TokenEnvelope::from_storage(envelope.version(), key_id, nonce, ciphertext).unwrap()
}

#[test]
fn opaque_bytes_roundtrip_without_text_conversion_including_empty_and_64_kib() {
    let keyring = ring();
    let binding = binding();
    let binary: Vec<u8> = (0..=255).cycle().take(65_536).collect();
    for plaintext in [&[][..], TOKEN, binary.as_slice()] {
        let sealed = keyring.seal(plaintext, &binding, NOW).unwrap();
        assert_eq!(sealed.version(), 1);
        assert_eq!(sealed.key_id(), "key-2026-09");
        assert_eq!(sealed.nonce().len(), 24);
        assert_eq!(sealed.ciphertext().len(), plaintext.len() + 16);
        let opened = keyring.open(&sealed, &binding, NOW).unwrap();
        assert_eq!(opened.expose_bytes(), plaintext);
    }
}

#[test]
fn each_seal_uses_a_fresh_nonce_even_after_keyring_reconstruction() {
    let mut nonces = HashSet::new();
    let keyring = ring();
    for _ in 0..64 {
        let sealed = keyring.seal(TOKEN, &binding(), NOW).unwrap();
        assert!(nonces.insert(*sealed.nonce()));
        let after_restart = ring().seal(TOKEN, &binding(), NOW).unwrap();
        assert!(nonces.insert(*after_restart.nonce()));
    }
}

#[test]
fn storage_fields_survive_keyring_reconstruction() {
    let sealed = ring().seal(TOKEN, &binding(), NOW).unwrap();
    let restored = TokenEnvelope::from_storage(
        sealed.version(),
        sealed.key_id(),
        sealed.nonce(),
        sealed.ciphertext(),
    )
    .unwrap();
    assert_eq!(
        ring()
            .open(&restored, &binding(), NOW + 1)
            .unwrap()
            .expose_bytes(),
        TOKEN,
    );
}

#[test]
fn every_ciphertext_and_tag_byte_is_authenticated() {
    let keyring = ring();
    let binding = binding();
    let sealed = keyring.seal(TOKEN, &binding, NOW).unwrap();
    for index in 0..sealed.ciphertext().len() {
        let mut damaged = sealed.ciphertext().to_vec();
        damaged[index] ^= 1;
        let altered = stored_with(&sealed, sealed.key_id(), sealed.nonce(), &damaged);
        assert_eq!(
            keyring.open(&altered, &binding, NOW).unwrap_err(),
            CryptoError::AuthenticationFailed,
        );
    }
}

#[test]
fn every_nonce_byte_is_authenticated() {
    let keyring = ring();
    let binding = binding();
    let sealed = keyring.seal(TOKEN, &binding, NOW).unwrap();
    for index in 0..24 {
        let mut damaged = *sealed.nonce();
        damaged[index] ^= 1;
        let altered = stored_with(&sealed, sealed.key_id(), &damaged, sealed.ciphertext());
        assert!(keyring.open(&altered, &binding, NOW).is_err());
    }
}

#[test]
fn truncation_or_appending_cannot_yield_any_plaintext() {
    let keyring = ring();
    let binding = binding();
    let sealed = keyring.seal(TOKEN, &binding, NOW).unwrap();
    for end in 0..sealed.ciphertext().len() {
        let restored = TokenEnvelope::from_storage(
            1,
            sealed.key_id(),
            sealed.nonce(),
            &sealed.ciphertext()[..end],
        );
        assert!(
            restored
                .and_then(|v| keyring.open(&v, &binding, NOW))
                .is_err()
        );
    }
    let mut extended = sealed.ciphertext().to_vec();
    extended.push(0);
    let altered = stored_with(&sealed, sealed.key_id(), sealed.nonce(), &extended);
    assert!(keyring.open(&altered, &binding, NOW).is_err());
}

#[test]
fn wrong_purpose_row_exact_issuer_client_subject_or_absolute_expiry_fails() {
    let keyring = ring();
    let sealed = keyring.seal(TOKEN, &binding(), NOW).unwrap();
    let row_two = RecordDigest::of_record_id(b"different-session-id").unwrap();
    let variants = [
        (
            EnvelopePurpose::LoginAttempt,
            digest(),
            ISSUER,
            CLIENT,
            SUBJECT,
            EXPIRY,
        ),
        (
            EnvelopePurpose::OperatorSession,
            row_two,
            ISSUER,
            CLIENT,
            SUBJECT,
            EXPIRY,
        ),
        (
            EnvelopePurpose::OperatorSession,
            digest(),
            "https://other.example",
            CLIENT,
            SUBJECT,
            EXPIRY,
        ),
        (
            EnvelopePurpose::OperatorSession,
            digest(),
            "https://issuer.example/realms/operators/",
            CLIENT,
            SUBJECT,
            EXPIRY,
        ),
        (
            EnvelopePurpose::OperatorSession,
            digest(),
            "https://ISSUER.example/realms/operators",
            CLIENT,
            SUBJECT,
            EXPIRY,
        ),
        (
            EnvelopePurpose::OperatorSession,
            digest(),
            ISSUER,
            "other-client",
            SUBJECT,
            EXPIRY,
        ),
        (
            EnvelopePurpose::OperatorSession,
            digest(),
            ISSUER,
            CLIENT,
            "operator:keycloak:bob",
            EXPIRY,
        ),
        (
            EnvelopePurpose::OperatorSession,
            digest(),
            ISSUER,
            CLIENT,
            SUBJECT,
            EXPIRY - 1,
        ),
        (
            EnvelopePurpose::OperatorSession,
            digest(),
            ISSUER,
            CLIENT,
            SUBJECT,
            EXPIRY + 1,
        ),
    ];
    for (purpose, record, issuer, client, subject, expiry) in variants {
        let wrong =
            TokenBinding::new(purpose, record, issuer, client, Some(subject), expiry).unwrap();
        assert_eq!(
            keyring.open(&sealed, &wrong, NOW).unwrap_err(),
            CryptoError::AuthenticationFailed,
        );
    }
}

#[test]
fn aad_field_boundaries_cannot_be_shifted_between_client_and_subject() {
    let keyring = ring();
    let original = TokenBinding::new(
        EnvelopePurpose::OperatorSession,
        digest(),
        ISSUER,
        "ab",
        Some("c"),
        EXPIRY,
    )
    .unwrap();
    let shifted = TokenBinding::new(
        EnvelopePurpose::OperatorSession,
        digest(),
        ISSUER,
        "a",
        Some("bc"),
        EXPIRY,
    )
    .unwrap();
    let sealed = keyring.seal(TOKEN, &original, NOW).unwrap();
    assert!(keyring.open(&sealed, &shifted, NOW).is_err());
}

#[test]
fn login_attempt_without_subject_roundtrips_but_subject_presence_is_bound() {
    let keyring = ring();
    let login = TokenBinding::new(
        EnvelopePurpose::LoginAttempt,
        digest(),
        ISSUER,
        CLIENT,
        None,
        EXPIRY,
    )
    .unwrap();
    let identified = TokenBinding::new(
        EnvelopePurpose::LoginAttempt,
        digest(),
        ISSUER,
        CLIENT,
        Some(SUBJECT),
        EXPIRY,
    )
    .unwrap();
    let sealed = keyring.seal(TOKEN, &login, NOW).unwrap();
    assert_eq!(
        keyring.open(&sealed, &login, NOW).unwrap().expose_bytes(),
        TOKEN
    );
    assert!(keyring.open(&sealed, &identified, NOW).is_err());
}

#[test]
fn binding_expiry_is_exclusive_and_checked_on_both_seal_and_open() {
    let keyring = ring();
    let binding = binding();
    let sealed = keyring.seal(TOKEN, &binding, EXPIRY - 1).unwrap();
    assert!(keyring.open(&sealed, &binding, EXPIRY - 1).is_ok());
    for now in [EXPIRY, EXPIRY + 1, i64::MAX] {
        assert_eq!(
            keyring.seal(TOKEN, &binding, now).unwrap_err(),
            CryptoError::ExpiredBinding
        );
        assert_eq!(
            keyring.open(&sealed, &binding, now).unwrap_err(),
            CryptoError::ExpiredBinding
        );
    }
    assert!(keyring.seal(TOKEN, &binding, -1).is_err());
    assert!(keyring.open(&sealed, &binding, -1).is_err());
}

#[test]
fn rotation_keeps_three_old_keys_only_within_each_explicit_decryption_window() {
    let keyring = TokenKeyring::new(vec![
        retired("old-1", 1, NOW + 10),
        active("current", 4),
        retired("old-2", 2, NOW + 20),
        retired("old-3", 3, NOW + 30),
    ])
    .unwrap();
    let current = keyring.seal(TOKEN, &binding(), NOW).unwrap();
    assert_eq!(current.key_id(), "current");
    for (id, byte, until) in [
        ("old-1", 1, NOW + 10),
        ("old-2", 2, NOW + 20),
        ("old-3", 3, NOW + 30),
    ] {
        let previous = TokenKeyring::new(vec![active(id, byte)]).unwrap();
        let old = previous.seal(TOKEN, &binding(), NOW).unwrap();
        assert_eq!(
            keyring
                .open(&old, &binding(), until - 1)
                .unwrap()
                .expose_bytes(),
            TOKEN
        );
        assert_eq!(
            keyring.open(&old, &binding(), until).unwrap_err(),
            CryptoError::ExpiredKey
        );
        assert_eq!(
            keyring.open(&old, &binding(), until + 1).unwrap_err(),
            CryptoError::ExpiredKey
        );
    }
    assert!(keyring.open(&current, &binding(), NOW + 31).is_ok());
    assert!(keyring.seal(TOKEN, &binding(), NOW + 31).is_ok());
}

#[test]
fn missing_key_id_is_rejected_without_trying_an_available_key() {
    let sealed = ring().seal(TOKEN, &binding(), NOW).unwrap();
    let absent = TokenKeyring::new(vec![active("different-id-same-material", 0x41)]).unwrap();
    assert_eq!(
        absent.open(&sealed, &binding(), NOW).unwrap_err(),
        CryptoError::UnknownKey
    );
}

#[test]
fn authentication_failure_does_not_fall_back_to_another_key() {
    let sealed = ring().seal(TOKEN, &binding(), NOW).unwrap();
    let changed = TokenKeyring::new(vec![
        active("key-2026-09", 0x42),
        retired("other-key-with-original-material", 0x41, EXPIRY),
    ])
    .unwrap();
    assert_eq!(
        changed.open(&sealed, &binding(), NOW).unwrap_err(),
        CryptoError::AuthenticationFailed
    );
}

#[test]
fn key_id_is_authenticated_even_if_two_ids_have_the_same_material() {
    let keyring = TokenKeyring::new(vec![
        active("current", 0x41),
        retired("alias", 0x41, EXPIRY),
    ])
    .unwrap();
    let sealed = keyring.seal(TOKEN, &binding(), NOW).unwrap();
    let altered = stored_with(&sealed, "alias", sealed.nonce(), sealed.ciphertext());
    assert_eq!(
        keyring.open(&altered, &binding(), NOW).unwrap_err(),
        CryptoError::AuthenticationFailed
    );
}

#[test]
fn sealing_one_byte_over_64_kib_is_rejected() {
    assert_eq!(
        ring()
            .seal(&vec![0xa5; 65_537], &binding(), NOW)
            .unwrap_err(),
        CryptoError::InputTooLarge,
    );
}
