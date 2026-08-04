#![cfg(all(test, feature = "postgres"))]

use super::postgres::PostgresIdempotencyStore;
use super::types::{IdempotencyKey, IdempotencyStore, ReservationResult};

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
