//! Revocation must defeat a valid query already blocked on a real database lock.
use crate::{
    callback::request,
    concurrency::{Release, wait_for_query},
    material::Materials,
    operation::Fixture,
    pki::{self, Pki},
    refresh, transport,
};
use apex_durability::PostgresClientOps;
use std::{sync::mpsc, time::Duration};
use tokio::sync::oneshot;

async fn observe_revocation(
    client: &mut apex_control_plane_api::proto::runtime_authority_service_client::RuntimeAuthorityServiceClient<tonic::transport::Channel>,
    query: &apex_control_plane_api::proto::CheckRuntimeAuthorityRequest,
) {
    let until = std::time::Instant::now() + Duration::from_millis(1500);
    loop {
        let mut probe = tonic::Request::new(query.clone());
        // A probe racing publication must not wait behind the held database
        // query for its lock timeout. Only this fixture accepts probe timeouts.
        probe.set_timeout(Duration::from_millis(100));
        let error = transport::within(client.check_runtime_authority(probe))
            .await
            .expect_err("held query or revoked enrollment cannot serve this probe");
        if error.code() == tonic::Code::PermissionDenied
            && error.message() == "RUNTIME_AUTHORITY_ENROLLMENT_DENIED"
        {
            return;
        }
        assert!(matches!(
            error.code(),
            tonic::Code::DeadlineExceeded
                | tonic::Code::Cancelled
                | tonic::Code::Unavailable
                | tonic::Code::FailedPrecondition
        ));
        assert!(
            std::time::Instant::now() < until,
            "revocation must be observed before PG lock timeout"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[test]
fn policy_replacement_during_real_pg_query_refuses_old_generation_and_recovers() {
    let fixture = Fixture::new(true);
    fixture.positive();
    let before = fixture.bytes();
    let pki = Pki::require();
    let mut materials = Materials::new(&fixture, &pki);
    let name = format!("authority_policy_{}", uuid::Uuid::now_v7().simple());
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
            holding.recv_timeout(Duration::from_secs(8)).unwrap();
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
            let requested = released.recv_timeout(Duration::from_secs(4));
            // Observe the real named query again AFTER publication is reported,
            // immediately before we release the owned lock. Earlier ROLLBACK or
            // a server timeout must not substitute for this intentional release.
            let still_blocked = wait_for_query(fixture, &name, true, "FROM mcp_proxies");
            tx.rollback().unwrap();
            let _ = cleaned.send(wait_for_query(fixture, &name, false, "ROLLBACK"));
            assert!(
                reached && requested.is_ok() && still_blocked,
                "owned policy-race lock exercised/released"
            );
        });
        transport::exercise(service, &pki, move |endpoint| async move {
            let mut release = released_on_drop;
            let pki = Pki::require();
            let mut client = transport::client(&pki, &endpoint, pki::AGENT).await;
            transport::within(client.check_runtime_authority(query.clone()))
                .await
                .unwrap();
            hold.try_send(()).unwrap();
            transport::within(held_observed).await.unwrap();
            let mut first_client = client.clone();
            let first_query = query.clone();
            let mut first = transport::Task(tokio::spawn(async move {
                first_client.check_runtime_authority(first_query).await
            }));
            assert!(transport::within(blocked_observed).await.unwrap());
            materials.enrollment["version"] = "live-enrollment-2".into();
            materials.enrollment["installations"][0]["revoked"] = true.into();
            materials.write();
            // Same established TLS channel: this refusal proves the reader has
            // published the replacement before the old database query is released.
            observe_revocation(&mut client, &query).await;
            assert!(
                !first.0.is_finished(),
                "original request remains in flight before lock release"
            );
            #[cfg(feature = "test-support")]
            assert_eq!(
                witness.counts()[2],
                2,
                "only healthy control and original held query dispatched"
            );
            release.now();
            let error = transport::within(&mut first.0).await.unwrap().unwrap_err();
            assert_eq!(error.code(), tonic::Code::FailedPrecondition);
            assert_eq!(error.message(), "RUNTIME_AUTHORITY_POLICY_CHANGED");
            assert!(error.details().is_empty());
            assert!(transport::within(cleanup_observed).await.unwrap());
            materials.enrollment["version"] = "live-enrollment-3".into();
            materials.enrollment["installations"][0]["revoked"] = false.into();
            materials.write();
            refresh::wait_for_version(&mut client, &query, "live-enrollment-3").await;
        });
        blocking.join().unwrap();
    });
    assert!(owner.shutdown().cleanup_complete);
    assert_eq!(fixture.bytes(), before);
}
