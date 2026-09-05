//! Independent observation/injection with transport-bounded blocking work.
//! The caller's two-second watchdog is distinct from the worker transport's
//! five-second startup/SQL deadline, which closes and joins its socket driver.
use super::fixture::{WATCHDOG, within};
use apex_durability::{PostgresClientOps, connect_postgres_for_worker};
use std::time::Instant;

pub async fn run<T: Send + 'static>(
    url: String,
    operation: impl FnOnce(&mut dyn PostgresClientOps) -> T + Send + 'static,
) -> T {
    // Include blocking-pool queue time. A late startup/setup result must not
    // authorize another SQL operation after this caller has already expired.
    let deadline = Instant::now() + WATCHDOG;
    within(tokio::task::spawn_blocking(move || {
        check_deadline(deadline);
        // Construct/use/drop on this blocking thread. The existing transport
        // arms its deadline before connecting (including PostgreSQL startup),
        // and again before every SQL operation. On I/O expiry it cancels AND
        // joins the socket-owning driver, so this closure can actually return.
        let mut client = connect_postgres_for_worker(&url)
            .unwrap_or_else(|_| panic!("independent PostgreSQL observation connection failed"));
        check_deadline(deadline);
        client
            .batch_execute("SET statement_timeout='1s'; SET lock_timeout='1s'")
            .unwrap_or_else(|_| panic!("independent PostgreSQL observation setup failed"));
        check_deadline(deadline);
        // Each caller performs one query/execute through PostgresClientOps,
        // retaining independent SQL and the worker's transport deadline.
        let result = operation(&mut client);
        check_deadline(deadline);
        result
    }))
    .await
    .expect("independent PostgreSQL observation worker failed")
}

fn check_deadline(deadline: Instant) {
    assert!(
        Instant::now() < deadline,
        "independent PostgreSQL observation caller expired"
    );
}
