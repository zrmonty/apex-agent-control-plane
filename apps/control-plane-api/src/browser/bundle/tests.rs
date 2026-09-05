use super::*;
use crate::browser::{crypto::TokenKey, oidc::config::tests::config, security::CsrfBinding};
const NOW: i64 = 2_000_000_000;
fn keys() -> TokenKeyring {
    TokenKeyring::new(vec![
        TokenKey::active("active", Zeroizing::new([7; 32])).unwrap(),
    ])
    .unwrap()
}
fn login() -> LoginBundle {
    LoginBundle {
        pkce: OpaqueToken::generate().unwrap(),
        nonce: OpaqueToken::generate().unwrap(),
    }
}
fn binding() -> LoginBinding {
    LoginBinding {
        state: OpaqueToken::generate().unwrap().lookup_digest(),
        browser: OpaqueToken::generate().unwrap().lookup_digest(),
        expires_at: NOW + 300,
    }
}
fn bundle() -> SessionBundle {
    SessionBundle {
        access: Zeroizing::new("access-secret-canary".into()),
        refresh: Zeroizing::new("refresh-secret-canary".into()),
        nonce: OpaqueToken::generate().unwrap(),
        csrf: CsrfToken::generate().unwrap(),
        generation: 0,
        access_expires_at: NOW + 300,
        refresh_expires_at: NOW + 1800,
    }
}
fn identity() -> SessionIdentity {
    SessionIdentity {
        digest: OpaqueToken::generate().unwrap().lookup_digest(),
        issuer: config().issuer,
        client_id: config().client_id,
        subject: "subject-123".into(),
        absolute_expires_at: NOW + 3600,
    }
}
fn stored(bundle: &SessionBundle) -> StoredSession {
    let identity = identity();
    let envelope = bundle.seal(&identity, &keys(), NOW).unwrap();
    StoredSession {
        identity,
        envelope,
        csrf_binding: bundle.csrf.binding(),
        access_expires_at: bundle.access_expires_at,
        refresh_expires_at: bundle.refresh_expires_at,
        idle_expires_at: NOW + 900,
        generation: bundle.generation,
        refresh_deadline: None,
    }
}
#[test]
fn login_round_trip_restores_pkce_nonce_after_keyring_reconstruction_without_plaintext() {
    let payload = login();
    let row = payload.seal(&binding(), &config(), &keys(), NOW).unwrap();
    assert!(
        !row.envelope
            .ciphertext()
            .windows(43)
            .any(|part| part == payload.pkce.expose_secret().as_bytes())
    );
    let loaded = LoginBundle::open(&row, &config(), &keys(), NOW + 1).unwrap();
    assert_eq!(loaded.pkce.expose_secret(), payload.pkce.expose_secret());
    assert_eq!(loaded.nonce.expose_secret(), payload.nonce.expose_secret());
    assert!(!format!("{loaded:?}").contains(payload.pkce.expose_secret()));
}
#[test]
fn login_payload_authenticates_browser_binding_and_exact_deployment_context() {
    for change in 0..6 {
        let mut row = login().seal(&binding(), &config(), &keys(), NOW).unwrap();
        match change {
            0 => row.browser = LookupDigest::from_bytes([0; 32]),
            1 => row.state = LookupDigest::from_bytes([0; 32]),
            2 => row.issuer.push('/'),
            3 => row.client_id.push('x'),
            4 => row.expires_at += 1,
            _ => row.expires_at = NOW,
        }
        assert!(
            LoginBundle::open(&row, &config(), &keys(), NOW).is_err(),
            "{change}"
        );
    }
    let row = login().seal(&binding(), &config(), &keys(), NOW).unwrap();
    let mut other = config();
    other.issuer.push('/');
    assert!(LoginBundle::open(&row, &other, &keys(), NOW).is_err());
}
#[test]
fn session_round_trip_binds_metadata_and_supports_retired_key_window() {
    let payload = bundle();
    let row = stored(&payload);
    let rotated = TokenKeyring::new(vec![
        TokenKey::active("new", Zeroizing::new([8; 32])).unwrap(),
        TokenKey::retired("active", Zeroizing::new([7; 32]), NOW + 30).unwrap(),
    ])
    .unwrap();
    let restored = SessionBundle::open(&row, &config(), &rotated, NOW + 1).unwrap();
    assert_eq!(restored.access.as_str(), payload.access.as_str());
    assert_eq!(restored.refresh.as_str(), payload.refresh.as_str());
    assert_eq!(restored.csrf.expose_secret(), payload.csrf.expose_secret());
    assert_eq!(
        restored.nonce.expose_secret(),
        payload.nonce.expose_secret()
    );
    assert_eq!(restored.generation, 0);
    assert!(!format!("{restored:?}").contains("canary"));
    assert!(SessionBundle::open(&row, &config(), &rotated, NOW + 30).is_err());
}
#[test]
fn unauthenticated_row_changes_cannot_extend_tokens_replace_csrf_or_cross_sessions() {
    for change in 0..10 {
        let mut row = stored(&bundle());
        match change {
            0 => row.access_expires_at += 1,
            1 => row.refresh_expires_at += 1,
            2 => row.generation += 1,
            3 => row.csrf_binding = CsrfBinding::from_bytes([0; 32]),
            4 => row.identity.subject.push('x'),
            5 => row.identity.digest = LookupDigest::from_bytes([0; 32]),
            6 => row.identity.absolute_expires_at += 1,
            7 => row.identity.issuer.push('/'),
            8 => row.identity.client_id.push('x'),
            _ => row.idle_expires_at = NOW,
        }
        assert!(
            SessionBundle::open(&row, &config(), &keys(), NOW).is_err(),
            "{change}"
        );
    }
}
#[test]
fn refresh_claim_advances_row_once_without_relabeling_old_ciphertext() {
    let mut row = stored(&bundle());
    row.generation = 1;
    row.refresh_deadline = Some(NOW + 15);
    assert_eq!(
        SessionBundle::open(&row, &config(), &keys(), NOW)
            .unwrap()
            .generation,
        0
    );
    row.generation = 2;
    assert!(SessionBundle::open(&row, &config(), &keys(), NOW).is_err());
    row.generation = 0;
    assert!(SessionBundle::open(&row, &config(), &keys(), NOW).is_err());
    row.generation = 1;
    assert!(SessionBundle::open(&row, &config(), &keys(), NOW + 15).is_err());
    // An expired access token is decryptable only to permit the separate fenced
    // refresh flow; this helper is not an authorization decision.
    let mut expired = stored(&bundle());
    expired.idle_expires_at = NOW + 900;
    assert!(SessionBundle::open(&expired, &config(), &keys(), NOW + 301).is_ok());
}
#[test]
fn new_bundles_reject_invalid_secret_sizes_generations_and_expiries() {
    for change in 0..7 {
        let mut payload = bundle();
        match change {
            0 => payload.access.clear(),
            1 => payload.access = Zeroizing::new("x".repeat(4097)),
            2 => payload.refresh = Zeroizing::new("bad refresh".into()),
            3 => payload.generation = u64::MAX,
            4 => payload.access_expires_at = NOW,
            5 => payload.refresh_expires_at = NOW,
            _ => payload.refresh.clear(),
        };
        assert!(payload.seal(&identity(), &keys(), NOW).is_err());
    }
    let mut too_long = binding();
    too_long.expires_at = NOW + 601;
    assert!(login().seal(&too_long, &config(), &keys(), NOW).is_err());
}

#[test]
fn authenticated_payloads_still_require_exact_versioned_bounded_framing() {
    let payload = bundle();
    let good = codec::encode(&payload).unwrap();
    assert!(codec::decode(&good).is_ok());
    for length in 0..good.len() {
        assert!(
            codec::decode(&good[..length]).is_err(),
            "truncation {length}"
        );
    }
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(codec::decode(&trailing).is_err());
    let mut version = good.clone();
    version[0] = 2;
    assert!(codec::decode(&version).is_err());
    let mut oversized = good.clone();
    oversized[111] = 255;
    oversized[112] = 255;
    assert!(codec::decode(&oversized).is_err());
    let mut malformed = good;
    malformed[25] = b'!';
    assert!(codec::decode(&malformed).is_err());
    let mut row = stored(&payload);
    row.envelope = keys()
        .seal(&trailing, &row.identity.token_binding().unwrap(), NOW)
        .unwrap();
    assert!(SessionBundle::open(&row, &config(), &keys(), NOW).is_err());
}
