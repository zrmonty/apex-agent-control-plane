use super::support::*;
use apex_control_plane_api::{
    ControlOutboxBackend, GatewayShutdown, PostgresProxyStore, ProxyEvidenceRelayStatus,
    RecoveringPostgresOutbox, spawn_proxy_evidence_relay, submit_command,
};
use apex_durability::IngestRequest;
use apex_durability::PostgresClientOps;
use std::sync::{Arc, mpsc};
use std::time::Duration;

#[test]
fn worker_connection_keeps_schema_and_sets_lock_and_statement_deadlines() {
    let database = Database::new();
    let mut client = apex_durability::connect_postgres_for_worker(&database.url).unwrap();
    let statement: String = client
        .query_one("SHOW statement_timeout", &[])
        .unwrap()
        .get(0);
    let lock: String = client.query_one("SHOW lock_timeout", &[]).unwrap().get(0);
    assert_eq!(statement, "5s");
    assert_eq!(lock, "2s");
    let schema: String = client
        .query_one("SELECT current_schema()", &[])
        .unwrap()
        .get(0);
    assert!(schema.starts_with("working_proxy_recovery_"));
}

#[test]
fn shutdown_completes_while_an_outbox_row_remains_locked() {
    let database = Database::new();
    let input = submission();
    let store = Arc::new(PostgresProxyStore::connect(&database.url).unwrap());
    store.submit_proxy_operation(&input).unwrap();
    let application = format!("owned_bounded_outbox_{}", uuid::Uuid::now_v7().simple());
    let outbox = Arc::new(ControlOutboxBackend::new(Box::new(
        RecoveringPostgresOutbox::connect(
            &format!("{}&application_name={application}", database.url),
            100,
        )
        .unwrap(),
    )));
    submit_command(
        &outbox,
        &IngestRequest::from_validated_transport(input.evidence.clone()).unwrap(),
    )
    .unwrap();
    let mut blocking_client = database.client();
    let mut transaction = blocking_client.transaction().unwrap();
    transaction
        .query_one(
            "SELECT event_id FROM apex_event_outbox WHERE event_id=$1 FOR UPDATE",
            &[&input.evidence.event_id.parse::<uuid::Uuid>().unwrap()],
        )
        .unwrap();
    let mut observer = database.client();
    let shutdown = GatewayShutdown::default();
    let signal = shutdown.clone();
    let (observed_tx, observed_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    // Wait for the actual outbox session to block, not an arbitrary sleep.
    let observation = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let blocked = loop {
            let rows = observer.query("SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'",
                &[&application]).unwrap();
            if !rows.is_empty() {
                break true;
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        signal.request();
        observed_tx.send(blocked).unwrap();
        let _ = release_rx.recv_timeout(Duration::from_secs(10));
    });
    let status = Arc::new(ProxyEvidenceRelayStatus::default());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut handle = {
        let _entered = runtime.enter();
        spawn_proxy_evidence_relay(Arc::clone(&store), Arc::clone(&outbox), status, shutdown)
    };
    // Drive the relay while observing the real row-lock wait and shutdown.
    let completed =
        runtime.block_on(async { tokio::time::timeout(Duration::from_secs(7), &mut handle).await });
    // Release the owned lock even when the regression fails; no detached job.
    transaction.rollback().unwrap();
    let _ = release_tx.send(());
    observation.join().unwrap();
    assert!(
        observed_rx.recv().unwrap(),
        "test never reached the outbox lock boundary"
    );
    if completed.is_err() {
        runtime.block_on(handle).unwrap();
    }
    assert!(
        completed.is_ok(),
        "shutdown waited indefinitely for an outbox row lock"
    );
    let pending: i64 = database
        .client()
        .query_one(
            "SELECT count(*) FROM mcp_proxy_evidence_intents WHERE enqueued_at_micros IS NULL",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        pending, 1,
        "blocked enqueue must retain its immutable intent"
    );
}
