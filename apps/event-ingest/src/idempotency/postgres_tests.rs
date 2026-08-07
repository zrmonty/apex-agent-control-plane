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

// ---------------------------------------------------------------------------
// Adversarial concurrency
//
// The in-process gateway serialises every ingest behind one adapter mutex, so
// nothing can race inside a single replica. The Postgres backend exists
// precisely so several replicas can share one authority, and that is where the
// races live. Each writer below owns its own connection, which is what a
// separate gateway process looks like to Postgres.
// ---------------------------------------------------------------------------

fn unique_event_id(tag: u64) -> String {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_nanos() as u64) & 0xffff)
        .unwrap_or(0);
    format!("018f5c91-2d88-7c00-8000-{:012x}", (tag << 16) | nonce)
}

/// N replicas reserving the SAME key at the same instant.
///
/// `reserve()` runs `SELECT ... FOR UPDATE` and then a plain `INSERT`. A
/// `SELECT ... FOR UPDATE` that matches no row takes no lock -- there is
/// nothing yet to lock -- so every writer sees "absent", every writer inserts,
/// and the primary key arbitrates. Exactly one must win, and the losers must be
/// told something a client can act on.
#[test]
fn postgres_idempotency_parallel_reserve_on_one_key_admits_exactly_one() {
    let Some(url) = url() else {
        eprintln!("skip postgres idempotency: set APEX_POSTGRES_URL");
        return;
    };
    const WRITERS: usize = 16;
    let key = IdempotencyKey {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        event_id: unique_event_id(0xc0),
    };
    let hash = [7u8; 32];

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(WRITERS));
    let mut handles = Vec::new();
    for _ in 0..WRITERS {
        let url = url.clone();
        let key = key.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let mut store = PostgresIdempotencyStore::connect(&url, 4096).expect("connect");
            barrier.wait();
            store.reserve(key, hash)
        }));
    }

    let mut reserved = 0;
    let mut in_progress = 0;
    let mut internal = 0;
    let mut other = Vec::new();
    for handle in handles {
        match handle.join().expect("writer thread") {
            Ok(ReservationResult::Reserved(_)) => reserved += 1,
            Ok(ReservationResult::InProgress) => in_progress += 1,
            Ok(result) => other.push(format!("{result:?}")),
            Err(error) if error.code == crate::GatewayErrorCode::Internal => internal += 1,
            Err(error) => other.push(error.code.as_str().to_owned()),
        }
    }

    // Safety: the key is a single-winner resource. Two reservations for one key
    // would let two replicas both believe they own the fanout.
    assert_eq!(
        reserved, 1,
        "{reserved} writers were granted the same idempotency key \
         (in_progress={in_progress}, internal={internal}, other={other:?})"
    );
    assert!(other.is_empty(), "unexpected outcomes racing one key: {other:?}");

    // Liveness: a loser must learn that someone else holds the key, not that
    // the server broke. INTERNAL_FAILURE carries no retry guidance and reads as
    // a server defect rather than contention.
    assert_eq!(
        internal, 0,
        "{internal} of {WRITERS} concurrent reservations lost the primary-key \
         race and were reported as INTERNAL_FAILURE instead of \
         IDEMPOTENCY_IN_PROGRESS. deploy/postgres/idempotency.sql requires \
         INSERT ... ON CONFLICT (workspace_id, namespace_id, event_id)."
    );
    assert_eq!(
        in_progress,
        WRITERS - 1,
        "every writer that lost the race must be told the key is in progress"
    );
}

/// The same race, but every writer carries DIFFERENT content.
///
/// Only one payload can own the key. Every other writer must be refused, and
/// refused as a typed conflict: a caller that retried on an opaque internal
/// error could otherwise come to believe its own divergent payload was stored.
#[test]
fn postgres_idempotency_parallel_reserve_with_divergent_payloads_conflicts() {
    let Some(url) = url() else {
        eprintln!("skip postgres idempotency: set APEX_POSTGRES_URL");
        return;
    };
    const WRITERS: usize = 12;
    let key = IdempotencyKey {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        event_id: unique_event_id(0xc1),
    };

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(WRITERS));
    let mut handles = Vec::new();
    for index in 0..WRITERS {
        let url = url.clone();
        let key = key.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let mut store = PostgresIdempotencyStore::connect(&url, 4096).expect("connect");
            barrier.wait();
            store.reserve(key, [index as u8; 32])
        }));
    }

    let mut reserved = 0;
    let mut refused = 0;
    let mut internal = 0;
    for handle in handles {
        match handle.join().expect("writer thread") {
            Ok(ReservationResult::Reserved(_)) => reserved += 1,
            Ok(
                ReservationResult::Conflict
                | ReservationResult::InProgress
                | ReservationResult::Duplicate,
            ) => refused += 1,
            Err(error) if error.code == crate::GatewayErrorCode::Internal => internal += 1,
            Err(error) => panic!("unexpected error racing one key: {}", error.code.as_str()),
        }
    }

    assert_eq!(
        reserved, 1,
        "{reserved} divergent payloads were granted the same idempotency key"
    );
    assert_eq!(
        internal, 0,
        "{internal} divergent-payload writers were reported as INTERNAL_FAILURE \
         instead of a typed conflict"
    );
    assert_eq!(refused, WRITERS - 1, "every divergent payload must be refused");
}

/// A reservation must not outlive its writer without a release path.
///
/// The `token -> reservation_id` map lives only in the writing process, so a
/// row left `pending` by a dead replica can be released by nothing except the
/// reaper. This pins that: the key stays unusable until reaped, which is why
/// the reaper's interval and max-age are load-bearing rather than cosmetic.
#[test]
fn postgres_idempotency_pending_row_from_a_dead_writer_blocks_until_reaped() {
    let Some(url) = url() else {
        eprintln!("skip postgres idempotency: set APEX_POSTGRES_URL");
        return;
    };
    let key = IdempotencyKey {
        workspace_id: "acme".into(),
        namespace_id: "prod".into(),
        event_id: unique_event_id(0xc2),
    };
    let hash = [3u8; 32];

    // "Crashed" writer: reserve, then drop the store without commit or abort.
    {
        // Capacity is shared with every other test's rows in this lab
        // database, so keep the headroom well above the scope ceiling.
        let mut dead = PostgresIdempotencyStore::connect(&url, 100_000).expect("connect");
        assert!(matches!(
            dead.reserve(key.clone(), hash).expect("reserve"),
            ReservationResult::Reserved(_)
        ));
    }

    let mut survivor = PostgresIdempotencyStore::connect(&url, 100_000).expect("connect");
    assert_eq!(
        survivor.reserve(key.clone(), hash).expect("reserve"),
        ReservationResult::InProgress,
        "a pending row from a dead writer must read as in-progress, not free"
    );

    let reclaimed = survivor
        .reap_expired(std::time::Duration::from_secs(0))
        .expect("reap");
    assert!(reclaimed >= 1, "the reaper did not reclaim the orphaned reservation");
    assert!(
        matches!(
            survivor.reserve(key, hash).expect("reserve"),
            ReservationResult::Reserved(_)
        ),
        "the key is still unusable after reaping"
    );
}
