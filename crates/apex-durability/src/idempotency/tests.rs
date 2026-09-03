use super::*;
use crate::GatewayErrorCode;

fn key(event_id: &str) -> IdempotencyKey {
    IdempotencyKey {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        event_id: event_id.into(),
    }
}

#[test]
fn memory_idempotency_rejects_zero_and_oversized_capacity() {
    assert_eq!(
        InMemoryIdempotencyStore::new(0).unwrap_err().code,
        GatewayErrorCode::IdempotencyCapacity
    );
    assert_eq!(
        InMemoryIdempotencyStore::new(1_000_001).unwrap_err().code,
        GatewayErrorCode::IdempotencyCapacity
    );
}

#[test]
fn reservation_commit_duplicate_conflict_and_abort_are_distinct() {
    let mut store = InMemoryIdempotencyStore::new(2).unwrap();
    let hash = [7; 32];
    let reservation = match store.reserve(key("one"), hash).unwrap() {
        ReservationResult::Reserved(value) => value,
        other => panic!("unexpected reservation result: {other:?}"),
    };
    assert_eq!(
        store.reserve(key("one"), hash).unwrap(),
        ReservationResult::InProgress
    );
    assert_eq!(
        store.reserve(key("one"), [8; 32]).unwrap(),
        ReservationResult::Conflict
    );
    store.commit(reservation).unwrap();
    let pending = match store.reserve(key("two"), [9; 32]).unwrap() {
        ReservationResult::Reserved(value) => value,
        other => panic!("unexpected reservation result: {other:?}"),
    };
    store.abort(pending);
    assert!(matches!(
        store.reserve(key("two"), [9; 32]).unwrap(),
        ReservationResult::Reserved(_)
    ));
}

#[test]
fn failed_commit_does_not_release_an_uncertain_reservation() {
    let mut store = InMemoryIdempotencyStore::new(2).unwrap();
    let reservation = match store.reserve(key("uncertain"), [4; 32]).unwrap() {
        ReservationResult::Reserved(value) => value,
        other => panic!("unexpected reservation result: {other:?}"),
    };
    assert!(store.commit(IdempotencyReservation { token: 999 }).is_err());
    assert_eq!(
        store.reserve(key("uncertain"), [4; 32]).unwrap(),
        ReservationResult::InProgress
    );
    store.commit(reservation).unwrap();
    assert_eq!(
        store.reserve(key("uncertain"), [4; 32]).unwrap(),
        ReservationResult::Duplicate
    );
}

#[test]
fn token_exhaustion_fails_closed_before_u64_wraparound() {
    let mut store = InMemoryIdempotencyStore::new(1).unwrap();
    store.next_token = u64::MAX;

    let error = store.reserve(key("exhausted"), [1; 32]).unwrap_err();

    assert_eq!(error.code, GatewayErrorCode::IdempotencyCapacity);
    assert!(store.pending.is_empty());
    assert_eq!(store.next_token, u64::MAX);
}

#[test]
fn idempotency_quota_isolated_per_scope() {
    let mut store = InMemoryIdempotencyStore::new(8).unwrap();
    for event_id in [
        "018f5c91-2d88-7c00-8000-000000000001",
        "018f5c91-2d88-7c00-8000-000000000002",
    ] {
        assert!(matches!(
            store.reserve(key(event_id), [1; 32]).unwrap(),
            ReservationResult::Reserved(_)
        ));
    }
    assert_eq!(
        store
            .reserve(key("018f5c91-2d88-7c00-8000-000000000003"), [1; 32])
            .unwrap_err()
            .code,
        GatewayErrorCode::IdempotencyCapacity
    );
    let other_scope = IdempotencyKey {
        workspace_id: "other-workspace".into(),
        namespace_id: "prod".into(),
        event_id: "018f5c91-2d88-7c00-8000-000000000004".into(),
    };
    assert!(matches!(
        store.reserve(other_scope, [2; 32]).unwrap(),
        ReservationResult::Reserved(_)
    ));
}

#[test]
fn file_idempotency_restores_committed_keys_across_restart() {
    let base = std::env::temp_dir().join(format!(
        "apex-idempotency-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&base).unwrap();
    let path = base.join("idempotency.jsonl");
    let event_key = key("018f5c91-2d88-7c00-8000-000000000001");
    {
        let mut store = FileIdempotencyStore::open(&path, &base, 4).unwrap();
        let reservation = match store.reserve(event_key.clone(), [3; 32]).unwrap() {
            ReservationResult::Reserved(value) => value,
            other => panic!("unexpected reservation result: {other:?}"),
        };
        store.commit(reservation).unwrap();
    }
    let mut reopened = FileIdempotencyStore::open(&path, &base, 4).unwrap();
    assert_eq!(
        reopened.reserve(event_key.clone(), [3; 32]).unwrap(),
        ReservationResult::Duplicate
    );
    assert_eq!(
        reopened.reserve(event_key, [4; 32]).unwrap(),
        ReservationResult::Conflict
    );
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn file_idempotency_covers_capacity_pending_abort_and_path_rejection() {
    let base = std::env::temp_dir().join(format!(
        "apex-idempotency-edges-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&base).unwrap();
    let path = base.join("idempotency.jsonl");
    assert_eq!(
        FileIdempotencyStore::open(&path, &base, 0)
            .unwrap_err()
            .code,
        GatewayErrorCode::IdempotencyCapacity
    );
    let outside = std::env::temp_dir().join(format!(
        "apex-idempotency-outside-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&outside).unwrap();
    assert_eq!(
        FileIdempotencyStore::open(&outside.join("idempotency.jsonl"), &base, 4)
            .unwrap_err()
            .code,
        GatewayErrorCode::InvalidIdempotencyConfiguration
    );
    std::fs::remove_dir_all(&outside).unwrap();

    {
        let mut store = FileIdempotencyStore::open(&path, &base, 1).unwrap();
        let reserved = match store
            .reserve(key("018f5c91-2d88-7c00-8000-000000000001"), [1; 32])
            .unwrap()
        {
            ReservationResult::Reserved(value) => value,
            other => panic!("unexpected: {other:?}"),
        };
        assert_eq!(
            store
                .reserve(key("018f5c91-2d88-7c00-8000-000000000001"), [1; 32])
                .unwrap(),
            ReservationResult::InProgress
        );
        assert_eq!(
            store
                .reserve(key("018f5c91-2d88-7c00-8000-000000000001"), [2; 32])
                .unwrap(),
            ReservationResult::Conflict
        );
        assert_eq!(
            store
                .reserve(key("018f5c91-2d88-7c00-8000-000000000002"), [3; 32])
                .unwrap_err()
                .code,
            GatewayErrorCode::IdempotencyCapacity
        );
        store.abort(reserved);
        assert!(matches!(
            store
                .reserve(key("018f5c91-2d88-7c00-8000-000000000001"), [1; 32])
                .unwrap(),
            ReservationResult::Reserved(_)
        ));
    }

    // Invalid scope identifiers in durable journal must fail closed.
    let corrupt = base.join("corrupt.jsonl");
    std::fs::write(
        &corrupt,
        br#"{"op":"committed","workspace_id":"bad workspace","namespace_id":"prod","event_id":"018f5c91-2d88-7c00-8000-000000000001","payload_hash":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]}"#,
    )
    .unwrap();
    assert_eq!(
        FileIdempotencyStore::open(&corrupt, &base, 4)
            .unwrap_err()
            .code,
        GatewayErrorCode::InvalidIdempotencyConfiguration
    );

    // Conflicting hashes for the same committed key fail closed on load.
    let conflict_path = base.join("conflict.jsonl");
    std::fs::write(
        &conflict_path,
        concat!(
            r#"{"op":"committed","workspace_id":"acme","namespace_id":"prod","event_id":"018f5c91-2d88-7c00-8000-000000000001","payload_hash":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]}"#,
            "\n",
            r#"{"op":"committed","workspace_id":"acme","namespace_id":"prod","event_id":"018f5c91-2d88-7c00-8000-000000000001","payload_hash":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2]}"#,
            "\n"
        ),
    )
    .unwrap();
    assert_eq!(
        FileIdempotencyStore::open(&conflict_path, &base, 4)
            .unwrap_err()
            .code,
        GatewayErrorCode::IdempotencyConflict
    );
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn file_idempotency_maintains_committed_retention_and_reuses_capacity() {
    let base = std::env::temp_dir().join(format!(
        "apex-idempotency-retention-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&base).unwrap();
    let path = base.join("idempotency.jsonl");
    let expired_key = key("018f5c91-2d88-7c00-8000-000000000001");
    let live_key = key("018f5c91-2d88-7c00-8000-000000000002");

    {
        let mut store = FileIdempotencyStore::open(&path, &base, 1).unwrap();
        let reservation = match store.reserve(expired_key.clone(), [1; 32]).unwrap() {
            ReservationResult::Reserved(value) => value,
            other => panic!("unexpected reservation result: {other:?}"),
        };
        store.commit(reservation).unwrap();
        assert_eq!(
            store.reserve(live_key.clone(), [2; 32]).unwrap_err().code,
            GatewayErrorCode::IdempotencyCapacity
        );

        store.maintain(u64::MAX, 0).unwrap();

        let reservation = match store.reserve(live_key.clone(), [2; 32]).unwrap() {
            ReservationResult::Reserved(value) => value,
            other => panic!("expired committed key did not release capacity: {other:?}"),
        };
        store.commit(reservation).unwrap();
    }

    let journal = std::fs::read_to_string(&path).unwrap();
    assert!(!journal.contains(&expired_key.event_id));
    assert!(journal.contains(&live_key.event_id));
    std::fs::remove_dir_all(base).unwrap();
}
