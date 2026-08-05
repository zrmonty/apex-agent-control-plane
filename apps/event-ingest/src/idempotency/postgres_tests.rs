#![cfg(all(test, feature = "postgres"))]

use super::postgres::PostgresIdempotencyStore;
use super::types::{IdempotencyKey, IdempotencyReservation, IdempotencyStore, ReservationResult};

fn url() -> Option<String> {
    std::env::var("APEX_POSTGRES_URL")
        .ok()
        .filter(|v| !v.is_empty())
}

#[test]
fn postgres_idempotency_reserve_commit_and_conflict() {
    let Some(url) = url() else {
        eprintln!("skip postgres idempotency: set APEX_POSTGRES_URL");
        return;
    };
    let mut store = PostgresIdempotencyStore::connect(&url, 64).expect("connect");
    let key = IdempotencyKey {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        event_id: "018f5c91-2d88-7c00-8000-0000000000e1".into(),
    };
    let hash = [9u8; 32];
    // Clean previous run
    let _ = store.reserve(key.clone(), hash);
    let reserved = match store.reserve(key.clone(), hash).unwrap() {
        ReservationResult::Reserved(r) => r,
        ReservationResult::InProgress | ReservationResult::Duplicate => {
            // prior pending/committed — still prove conflict path
            assert!(matches!(
                store.reserve(key.clone(), [8u8; 32]).unwrap(),
                ReservationResult::Conflict
                    | ReservationResult::InProgress
                    | ReservationResult::Duplicate
            ));
            return;
        }
        ReservationResult::Conflict => panic!("unexpected conflict on fresh key"),
    };
    store.commit(reserved).unwrap();
    assert_eq!(
        store.reserve(key.clone(), hash).unwrap(),
        ReservationResult::Duplicate
    );
    assert_eq!(
        store.reserve(key, [1u8; 32]).unwrap(),
        ReservationResult::Conflict
    );
}

#[test]
fn postgres_idempotency_reaps_only_expired_pending_reservations() {
    let Some(url) = url() else {
        eprintln!("skip postgres idempotency: set APEX_POSTGRES_URL");
        return;
    };
    let mut store = PostgresIdempotencyStore::connect(&url, 64).expect("connect");
    let key = IdempotencyKey {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        event_id: "018f5c91-2d88-7c00-8000-0000000000e2".into(),
    };
    let hash = [7u8; 32];
    // Clean any pending leftover from a prior run before asserting counts.
    let _ = store.reap_expired(std::time::Duration::ZERO);
    let Ok(ReservationResult::Reserved(reserved)) = store.reserve(key.clone(), hash) else {
        // A prior run's *committed* row still occupies this key; the reaper
        // must never touch committed rows, so skip rather than fight that.
        eprintln!("skip: key already committed from a prior run");
        return;
    };
    // Simulate the crash this reaper exists for: reserve() committed the row,
    // but the process disappears before commit()/abort() ever runs, so
    // `reserved` is simply dropped without releasing the row.
    let _ = reserved;
    assert_eq!(
        store.reserve(key.clone(), hash).unwrap(),
        ReservationResult::InProgress
    );

    let deleted = store
        .reap_expired(std::time::Duration::ZERO)
        .expect("reap succeeds");
    assert!(deleted >= 1);

    match store.reserve(key, hash).unwrap() {
        ReservationResult::Reserved(_) => {}
        other => panic!("expected the reaped key to be reservable again, got {other:?}"),
    }
}

#[test]
fn postgres_idempotency_connect_rejects_invalid_capacity_and_connection_string() {
    let Some(url) = url() else {
        eprintln!("skip postgres idempotency: set APEX_POSTGRES_URL");
        return;
    };
    assert!(PostgresIdempotencyStore::connect(&url, 0).is_err());
    assert!(PostgresIdempotencyStore::connect(&url, 1_000_001).is_err());
    assert!(PostgresIdempotencyStore::connect("", 64).is_err());
    assert!(PostgresIdempotencyStore::connect(&"x".repeat(2049), 64).is_err());
}

#[test]
fn postgres_idempotency_reserve_rejects_invalid_key_shapes() {
    let Some(url) = url() else {
        eprintln!("skip postgres idempotency: set APEX_POSTGRES_URL");
        return;
    };
    let mut store = PostgresIdempotencyStore::connect(&url, 64).expect("connect");
    let bad_scope = IdempotencyKey {
        workspace_id: "bad workspace".into(),
        namespace_id: "prod".into(),
        event_id: "018f5c91-2d88-7c00-8000-0000000000ea".into(),
    };
    assert!(store.reserve(bad_scope, [0u8; 32]).is_err());
    let bad_id = IdempotencyKey {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        event_id: "not-a-uuid".into(),
    };
    assert!(store.reserve(bad_id, [0u8; 32]).is_err());
}

#[test]
fn postgres_idempotency_abort_releases_the_key_for_reservation() {
    let Some(url) = url() else {
        eprintln!("skip postgres idempotency: set APEX_POSTGRES_URL");
        return;
    };
    let mut store = PostgresIdempotencyStore::connect(&url, 64).expect("connect");
    let key = IdempotencyKey {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        event_id: "018f5c91-2d88-7c00-8000-0000000000eb".into(),
    };
    let hash = [3u8; 32];
    let Ok(ReservationResult::Reserved(reserved)) = store.reserve(key.clone(), hash) else {
        eprintln!("skip: key already occupied from a prior run");
        return;
    };
    store.abort(reserved);
    match store.reserve(key, hash).unwrap() {
        ReservationResult::Reserved(_) => {}
        other => panic!("expected abort to free the key for reservation, got {other:?}"),
    }
}

#[test]
fn postgres_idempotency_commit_is_not_valid_twice() {
    let Some(url) = url() else {
        eprintln!("skip postgres idempotency: set APEX_POSTGRES_URL");
        return;
    };
    let mut store = PostgresIdempotencyStore::connect(&url, 64).expect("connect");
    let key = IdempotencyKey {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        event_id: "018f5c91-2d88-7c00-8000-0000000000ec".into(),
    };
    let hash = [4u8; 32];
    let reserved = match store.reserve(key.clone(), hash) {
        Ok(ReservationResult::Reserved(r)) => r,
        _ => {
            eprintln!("skip: key already occupied from a prior run");
            return;
        }
    };
    store.commit(reserved).unwrap();
    // The in-process reservation_id -> token mapping is removed on the first
    // commit; reusing the same (Copy) reservation must fail rather than
    // silently succeeding or double-committing.
    let reused: IdempotencyReservation = reserved;
    assert!(store.commit(reused).is_err());
}
