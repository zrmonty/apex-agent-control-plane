/// Concurrent `connect()` from many replicas must all succeed.
///
/// Both stores run `CREATE TABLE IF NOT EXISTS` on every connect, and
/// `IF NOT EXISTS` is not race-safe: concurrent creators both pass the catalog
/// check and the loser dies with a `pg_type_typname_nsp_index` unique
/// violation, which this layer can only report as
/// INVALID_OUTBOX_CONFIGURATION. That points the operator at a configuration
/// that is not wrong, and the replica fails to start. Reproduces on any
/// simultaneous start: rolling deploy, scale-up, restart storm.
#[test]
fn postgres_outbox_concurrent_schema_creation_does_not_fail_a_replica() {
    let Some(url) = url() else {
        eprintln!("skip postgres outbox: set APEX_POSTGRES_URL");
        return;
    };
    const REPLICAS: usize = 16;

    // The race only exists while the tables are being *created*. Against a
    // database where a previous run already created them, every `IF NOT
    // EXISTS` short-circuits and the test would pass without exercising
    // anything. Drop first so this is a real cold start every time.
    {
        let mut admin =
            crate::postgres_transport::connect_postgres(&url).expect("admin connection");
        admin
            .batch_execute(
                "DROP TABLE IF EXISTS apex_event_outbox CASCADE;
                 DROP TABLE IF EXISTS apex_ingest_idempotency CASCADE;",
            )
            .expect("drop schema");
    }

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(REPLICAS));
    let mut handles = Vec::new();
    for _ in 0..REPLICAS {
        let url = url.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            PostgresOutbox::connect(&url, 64)
                .map(|_| ())
                .map_err(|error| error.code.as_str().to_owned())
        }));
    }
    let failures: Vec<String> = handles
        .into_iter()
        .filter_map(|handle| handle.join().expect("replica thread").err())
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {REPLICAS} replicas failed to start on a concurrent schema \
         creation: {failures:?}",
        failures.len()
    );
}

/// Losing PostgreSQL mid-run must fail closed, not fake a success.
///
/// Opt-in via APEX_POSTGRES_KILL_CONTAINER because it stops and starts a
/// database container. The property is the one that matters for durability
/// acknowledgements: while the authority is unreachable, `enqueue` must return
/// an error and must never report Enqueued/AlreadyComplete for something that
/// was not written. Recovery must then work without operator intervention.
#[test]
fn postgres_outbox_fails_closed_while_the_database_is_down() {
    let Some(url) = url() else {
        eprintln!("skip postgres outbox: set APEX_POSTGRES_URL");
        return;
    };
    let Ok(container) = std::env::var("APEX_POSTGRES_KILL_CONTAINER") else {
        eprintln!("skip: set APEX_POSTGRES_KILL_CONTAINER to stop/start the database");
        return;
    };
    let docker = |args: &[&str]| {
        std::process::Command::new("docker")
            .args(args)
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    };

    let mut outbox = PostgresOutbox::connect(&url, 100_000).expect("connect");
    let before = unique_event_id(0xd8);
    outbox
        .enqueue(&valid_outbox_event(&before))
        .expect("enqueue while the database is up");

    assert!(
        docker(&["stop", "-t", "2", &container]),
        "could not stop {container}"
    );

    let during = unique_event_id(0xd9);
    let result = outbox.enqueue(&valid_outbox_event(&during));
    assert!(
        result.is_err(),
        "enqueue returned {result:?} while PostgreSQL was stopped; a durable \
         write was reported for something the authority never saw"
    );
    // A dead connection must not report work as done either.
    assert!(
        outbox.pending().is_empty(),
        "pending() returned rows from an unreachable database"
    );

    assert!(
        docker(&["start", &container]),
        "could not start {container}"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    let mut recovered = None;
    while std::time::Instant::now() < deadline {
        if let Ok(store) = PostgresOutbox::connect(&url, 100_000) {
            recovered = Some(store);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    let mut recovered = recovered.expect("the store never reconnected after PostgreSQL restarted");

    // The pre-outage row must still be there: it was acknowledged, so it must
    // have survived. The during-outage row must NOT be, because it was refused.
    let claimed: Vec<String> = recovered
        .pending()
        .into_iter()
        .map(|event| event.event_id.as_str().to_owned())
        .collect();
    assert!(
        claimed.contains(&before),
        "an acknowledged pre-outage row did not survive the restart"
    );
    assert!(
        !claimed.contains(&during),
        "a refused during-outage row was durable anyway"
    );
}

/// Two replay workers must not both claim the same pending row.
///
/// `pending()` was a bare SELECT, so every replica read every pending row on
/// every cycle and fanned it out again. That only stayed invisible because the
/// sinks happen to dedupe on `event_id`. The claim must partition the work.
#[test]
fn postgres_outbox_pending_is_claimed_not_merely_listed() {
    let Some(url) = url() else {
        eprintln!("skip postgres outbox: set APEX_POSTGRES_URL");
        return;
    };
    let mut writer = PostgresOutbox::connect(&url, 100_000).expect("connect");
    let ids: Vec<String> = (0..6).map(|index| unique_event_id(0xd2 + index)).collect();
    for id in &ids {
        writer.enqueue(&valid_outbox_event(id)).expect("enqueue");
    }

    // Two independent replicas draining concurrently.
    let mut first = PostgresOutbox::connect(&url, 100_000).expect("connect");
    let mut second = PostgresOutbox::connect(&url, 100_000).expect("connect");
    let claimed_first: Vec<String> = first
        .pending()
        .into_iter()
        .map(|event| event.event_id.as_str().to_owned())
        .filter(|id| ids.contains(id))
        .collect();
    let claimed_second: Vec<String> = second
        .pending()
        .into_iter()
        .map(|event| event.event_id.as_str().to_owned())
        .filter(|id| ids.contains(id))
        .collect();

    assert!(
        !claimed_first.is_empty(),
        "the first worker claimed nothing; the rows were never enqueued"
    );
    for id in &claimed_first {
        assert!(
            !claimed_second.contains(id),
            "event {id} was claimed by BOTH replay workers; each would fan it \
             out independently and exactly-once would rest entirely on every \
             sink deduplicating forever"
        );
    }
}
