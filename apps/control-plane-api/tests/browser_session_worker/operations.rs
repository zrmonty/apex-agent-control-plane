//! Real PostgreSQL coverage for all session methods at the async facade seam.

use super::*;
use apex_control_plane_api::browser::{
    crypto::TokenEnvelope,
    errors::BrowserError,
    security::CsrfBinding,
    sessions::{NewSession, RefreshCommit, SessionIdentity},
};

fn envelope(digest: LookupDigest, expires_at: i64) -> TokenEnvelope {
    let keys = TokenKeyring::new(vec![
        TokenKey::active("worker-session-fixture", Zeroizing::new([8; 32])).unwrap(),
    ])
    .unwrap();
    let binding = TokenBinding::new(
        EnvelopePurpose::OperatorSession,
        RecordDigest::from_sha256(digest.as_bytes()).unwrap(),
        "https://issuer.example/realm",
        "apex-browser",
        Some("operator:keycloak:worker"),
        expires_at,
    )
    .unwrap();
    keys.seal(b"worker-session-fixture", &binding, now())
        .unwrap()
}

#[test]
fn real_postgres_session_methods_preserve_generation_expiry_and_revocation() {
    let database = Database::new();
    let (connection_string, application_name) = worker_url(&database);
    let store = BrowserSessionStore::connect(&connection_string).unwrap();
    let mut observer = observer(&database);
    let digest = LookupDigest::from_bytes([7; 32]);
    let expires_at = now() + 3600;
    let input = NewSession {
        identity: SessionIdentity {
            digest,
            issuer: "https://issuer.example/realm".into(),
            client_id: "apex-browser".into(),
            subject: "operator:keycloak:worker".into(),
            absolute_expires_at: expires_at,
        },
        csrf_binding: CsrfBinding::from_bytes([5; 32]),
        envelope: envelope(digest, expires_at),
        access_expires_at: now() + 15,
        refresh_expires_at: expires_at,
        idle_timeout_secs: 600,
    };
    runtime().block_on(async move {
        store.create_session(input).await.unwrap();
        let loaded = store.load(digest).await.unwrap().unwrap();
        assert_eq!(loaded.identity.subject, "operator:keycloak:worker");
        assert_eq!(loaded.identity.absolute_expires_at, expires_at);
        assert_eq!(loaded.csrf_binding.as_bytes(), &[5; 32]);
        assert_eq!(loaded.generation, 0);
        assert!(loaded.refresh_deadline.is_none());
        assert_eq!(
            store.load(digest).await.unwrap().unwrap().idle_expires_at,
            loaded.idle_expires_at
        );
        assert!(!store.touch(digest, 1, 600).await.unwrap());
        assert!(store.touch(digest, 0, 600).await.unwrap());

        let claim = store.claim_refresh(digest, 0).await.unwrap().unwrap();
        assert_eq!(claim.generation, 1);
        assert!(claim.refresh_deadline.is_some());
        assert!(store.claim_refresh(digest, 0).await.unwrap().is_none());
        let commit = |generation| RefreshCommit {
            digest,
            generation,
            envelope: envelope(digest, expires_at),
            access_expires_at: now() + 300,
            refresh_expires_at: expires_at,
        };
        assert!(!store.finish_refresh(commit(0)).await.unwrap());
        assert!(store.finish_refresh(commit(1)).await.unwrap());
        let refreshed = store.load(digest).await.unwrap().unwrap();
        assert_eq!(refreshed.generation, 1);
        assert_eq!(refreshed.identity.absolute_expires_at, expires_at);
        assert!(refreshed.refresh_deadline.is_none());
        assert!(store.revoke(digest).await.unwrap());
        assert!(store.load(digest).await.unwrap().is_none());
        assert!(!store.finish_refresh(commit(1)).await.unwrap());
        assert!(!store.touch(digest, 1, 600).await.unwrap());
        assert_eq!(store.prune_expired().await.unwrap(), 1);
        assert_eq!(store.prune_expired().await.unwrap(), 0);
    });
    wait_closed(&mut observer, &application_name);
}

#[test]
fn real_postgres_receiver_errors_are_redacted_and_failed_mutations_are_not_replayed() {
    let database = Database::new();
    let (connection_string, application_name) = worker_url(&database);
    let store = BrowserSessionStore::connect(&connection_string).unwrap();
    let mut observer = observer(&database);
    // PostgreSQL sequences are not rolled back: this counts attempts even when
    // the fixture transaction fails, without relying on actor internals.
    observer
        .batch_execute(
            "CREATE SEQUENCE worker_mutation_attempts;
         CREATE FUNCTION refuse_worker_login() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
             PERFORM nextval('worker_mutation_attempts');
             RAISE EXCEPTION 'worker-private-database-canary';
         END $$;
         CREATE TRIGGER refuse_worker_login BEFORE INSERT ON apex_browser_login_attempts
         FOR EACH ROW EXECUTE FUNCTION refuse_worker_login()",
        )
        .unwrap();
    runtime().block_on(async move {
        let error = store
            .create_login(login_attempt(
                LookupDigest::from_bytes([8; 32]),
                LookupDigest::from_bytes([9; 32]),
            ))
            .await
            .unwrap_err();
        assert_eq!(error, BrowserError::Unavailable);
        assert_eq!(error.to_string(), "unavailable");
        assert_eq!(format!("{error:?}"), "Unavailable");
        assert!(std::error::Error::source(&error).is_none());
    });
    wait_closed(&mut observer, &application_name);
    let row = observer
        .query_one(
            "SELECT last_value, is_called FROM worker_mutation_attempts",
            &[],
        )
        .unwrap();
    assert_eq!(
        row.get::<_, i64>(0),
        1,
        "one submission must execute only once"
    );
    assert!(row.get::<_, bool>(1));
}
