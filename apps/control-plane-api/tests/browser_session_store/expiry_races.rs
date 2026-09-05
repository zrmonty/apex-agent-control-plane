use super::{regression_support::*, *};

#[derive(Clone, Copy)]
enum Mutation {
    TakeLogin,
    Touch,
    ClaimRefresh,
    FinishRefresh,
}

fn rejects_expired_waiter(mutation: Mutation, rollback: bool) {
    let db = Database::new();
    let key = digest(61);
    let browser = digest(62);
    let mut setup = PostgresSessionStore::connect(&db.url).unwrap();
    let absolute_expiry = if matches!(mutation, Mutation::TakeLogin) {
        let expiry = now() + 300;
        setup.create_login(login(key, browser, expiry)).unwrap();
        expiry
    } else {
        setup.create_session(session(key, 15)).unwrap();
        let stored = if matches!(mutation, Mutation::FinishRefresh) {
            setup.claim_refresh(key, 0).unwrap().unwrap()
        } else {
            setup.load(key).unwrap().unwrap()
        };
        stored.identity.absolute_expires_at
    };
    drop(setup);
    // Build the provider result before entering the narrow clock window.
    let replacement = refreshed(key, 1, absolute_expiry);
    let worker = StoreWorker::new(&db, false);
    let mut observer = observer(&db);
    let mut blocker = db.client();
    let blocker_pid: i32 = blocker
        .query_one("SELECT pg_backend_pid()", &[])
        .unwrap()
        .get(0);
    let expiry = expiry_window(&mut observer);
    let (table, column, deadline_column) = match mutation {
        Mutation::TakeLogin => ("apex_browser_login_attempts", "state_digest", "expires_at"),
        Mutation::Touch | Mutation::ClaimRefresh => {
            ("apex_browser_sessions", "session_digest", "idle_expires_at")
        }
        Mutation::FinishRefresh => (
            "apex_browser_sessions",
            "session_digest",
            "refresh_deadline",
        ),
    };
    observer
        .execute(
            &format!("UPDATE {table} SET {deadline_column}=$2 WHERE {column}=$1"),
            &[&key.as_bytes().as_slice(), &expiry],
        )
        .unwrap();
    let before: String = observer
        .query_one(
            &format!("SELECT to_jsonb(t)::text FROM {table} t WHERE {column}=$1"),
            &[&key.as_bytes().as_slice()],
        )
        .unwrap()
        .get(0);
    let mut tx = blocker.transaction().unwrap();
    if rollback {
        // Exercise an aborted UPDATE, not merely a released SELECT lock.
        tx.execute(
            &format!("UPDATE {table} SET issuer=issuer WHERE {column}=$1"),
            &[&key.as_bytes().as_slice()],
        )
        .unwrap();
    } else {
        tx.query_one(
            &format!("SELECT {column} FROM {table} WHERE {column}=$1 FOR UPDATE"),
            &[&key.as_bytes().as_slice()],
        )
        .unwrap();
    }
    let result = worker.submit(move |store| match mutation {
        Mutation::TakeLogin => store.take_login(key, browser).map(|row| row.is_some()),
        Mutation::Touch => store.touch(key, 0, 600),
        Mutation::ClaimRefresh => store.claim_refresh(key, 0).map(|row| row.is_some()),
        Mutation::FinishRefresh => store.finish_refresh(replacement),
    });
    wait_for_blocker(&mut observer, &worker.application, blocker_pid);
    cross_expiry(&mut observer, expiry);
    if rollback {
        tx.rollback().unwrap();
    } else {
        tx.commit().unwrap();
    }
    // An Unavailable/lock timeout is not the required semantic refusal.
    assert_eq!(
        receive(result),
        Ok(false),
        "expired operation must return no claim/change"
    );
    let after: String = observer
        .query_one(
            &format!("SELECT to_jsonb(t)::text FROM {table} t WHERE {column}=$1"),
            &[&key.as_bytes().as_slice()],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        before, after,
        "expiry refusal must not consume or revive the record"
    );
}

#[test]
fn login_expiry_is_rechecked_after_lock_release() {
    rejects_expired_waiter(Mutation::TakeLogin, false);
}
#[test]
fn login_expiry_is_rechecked_after_blocker_rollback() {
    rejects_expired_waiter(Mutation::TakeLogin, true);
}
#[test]
fn touch_expiry_is_rechecked_after_lock_release() {
    rejects_expired_waiter(Mutation::Touch, false);
}
#[test]
fn touch_expiry_is_rechecked_after_blocker_rollback() {
    rejects_expired_waiter(Mutation::Touch, true);
}
#[test]
fn refresh_claim_expiry_is_rechecked_after_lock_release() {
    rejects_expired_waiter(Mutation::ClaimRefresh, false);
}
#[test]
fn refresh_claim_expiry_is_rechecked_after_blocker_rollback() {
    rejects_expired_waiter(Mutation::ClaimRefresh, true);
}
#[test]
fn refresh_commit_expiry_is_rechecked_after_lock_release() {
    rejects_expired_waiter(Mutation::FinishRefresh, false);
}
#[test]
fn refresh_commit_expiry_is_rechecked_after_blocker_rollback() {
    rejects_expired_waiter(Mutation::FinishRefresh, true);
}
