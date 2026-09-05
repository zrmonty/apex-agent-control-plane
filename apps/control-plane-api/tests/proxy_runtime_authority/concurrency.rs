//! Two actual PG connections: expire while blocked, require rollback, recover.
use crate::{
    callback::request,
    material::Materials,
    operation::Fixture,
    pki::{self, Pki},
    transport,
};
use apex_durability::PostgresClientOps;
use std::{
    sync::mpsc,
    time::{Duration, Instant},
};
use tokio::sync::oneshot;
use tonic::Code;

pub(super) struct Release(pub(super) Option<mpsc::SyncSender<()>>);
impl Release {
    pub(super) fn now(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.try_send(());
        }
    }
}
impl Drop for Release {
    fn drop(&mut self) {
        self.now();
    }
}

pub(super) fn wait_for_query(fixture: &Fixture, name: &str, blocked: bool, fragment: &str) -> bool {
    let until = Instant::now() + Duration::from_secs(3);
    let mut client = crate::observer::connect(&fixture.database.url);
    while Instant::now() < until {
        let matched: bool = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1
             AND position($2 in query)>0 AND
             CASE WHEN $3 THEN cardinality(pg_blocking_pids(pid))>0 ELSE state='idle' END)",
                &[&name, &fragment, &blocked],
            )
            .unwrap()
            .get(0);
        if matched {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

#[test]
fn expired_inflight_and_queued_requests_rollback_before_a_healthy_explicit_followup() {
    let fixture = Fixture::new(true);
    fixture.positive();
    let before = fixture.bytes();
    let pki = Pki::require();
    let materials = Materials::new(&fixture, &pki);
    let name = format!("authority_cancel_{}", uuid::Uuid::now_v7().simple());
    let mut owner = materials.owner(&format!("{}&application_name={name}", fixture.database.url));
    let service = owner.start().unwrap();
    #[cfg(feature = "test-support")]
    let witness = owner.observations();
    let query = request(&fixture, &pki);
    let (hold, holding) = mpsc::sync_channel(1);
    let (held, held_observed) = oneshot::channel();
    let (blocked, blocked_observed) = oneshot::channel();
    let (release, released) = mpsc::sync_channel(1);
    let (cleaned, cleanup_observed) = oneshot::channel();
    let released_on_drop = Release(Some(release));
    std::thread::scope(|scope| {
        let fixture = &fixture;
        let blocking = scope.spawn(move || {
            // Test commands and connection stay entirely on this standard thread.
            holding
                .recv_timeout(Duration::from_secs(8))
                .expect("healthy callback before lock");
            let mut client = crate::observer::connect(&fixture.database.url);
            let mut tx = client.transaction().unwrap();
            tx.query_one(
                "SELECT proxy_id FROM mcp_proxies WHERE proxy_id=$1 FOR UPDATE",
                &[fixture.input.proxy_id.as_uuid()],
            )
            .unwrap();
            let _ = held.send(());
            let reached = wait_for_query(fixture, &name, true, "FROM mcp_proxies");
            let _ = blocked.send(reached);
            let requested = released.recv_timeout(Duration::from_secs(5));
            tx.rollback().unwrap(); // Release on every observed path, before assertions.
            let rolled_back = wait_for_query(fixture, &name, false, "ROLLBACK");
            let _ = cleaned.send(rolled_back);
            assert!(requested.is_ok(), "test must explicitly release its lock");
            assert!(
                reached,
                "authority query must reach the actual second-connection lock"
            );
        });
        transport::exercise(service, &pki, move |endpoint| async move {
            let mut release = released_on_drop;
            let pki = Pki::require();
            let mut client = transport::client(&pki, &endpoint, pki::AGENT).await;
            transport::within(client.check_runtime_authority(query.clone()))
                .await
                .expect("healthy control");
            #[cfg(feature = "test-support")]
            assert_eq!(crate::observer::counts(&witness, 3, 1).await, [1; 4]);
            hold.try_send(()).unwrap();
            transport::within(held_observed).await.unwrap();
            let started = Instant::now();
            let mut timed = tonic::Request::new(query.clone());
            timed.set_timeout(Duration::from_millis(400));
            let mut first_client = client.clone();
            let mut first = transport::Task(tokio::spawn(async move {
                first_client.check_runtime_authority(timed).await
            }));
            assert!(
                transport::within(blocked_observed).await.unwrap(),
                "real PG query is blocked"
            );
            let mut queued = tonic::Request::new(query.clone());
            queued.set_timeout(Duration::from_millis(100));
            let mut queued_client = client.clone();
            let mut queued = transport::Task(tokio::spawn(async move {
                queued_client.check_runtime_authority(queued).await
            }));
            #[cfg(feature = "test-support")]
            assert_eq!(crate::observer::counts(&witness, 0, 3).await, [3, 2, 2, 1]);
            let queued = transport::within(&mut queued.0).await.unwrap();
            let first = transport::within(&mut first.0).await.unwrap();
            for result in [first, queued] {
                let error = result.expect_err("expired requests never produce snapshots");
                assert!(matches!(
                    error.code(),
                    Code::DeadlineExceeded | Code::Cancelled
                ));
            }
            // Independent elapsed budget, not only a late/early timer wake.
            let remaining = Duration::from_millis(550).saturating_sub(started.elapsed());
            tokio::time::sleep(remaining).await;
            release.now();
            assert!(
                transport::within(cleanup_observed).await.unwrap(),
                "actual rollback observed before the independent queue boundary"
            );
            #[cfg(feature = "test-support")]
            assert_eq!(
                crate::observer::counts(&witness, 3, 3).await,
                [3, 3, 2, 3],
                "both jobs settled, but expired queued work never reached the real store"
            );
            transport::within(client.check_runtime_authority(query))
                .await
                .expect("explicit healthy request after actual cleanup");
        });
        blocking
            .join()
            .expect("owned blocking fixture thread joined");
    });
    assert!(owner.shutdown().cleanup_complete);
    assert_eq!(fixture.bytes(), before);
}
