//! Physical SQL witness: revoke only after the authenticated callback entered INSERT.
use super::*;

pub(super) async fn during_insert(
    f: &fixture::Fixture,
    owner: &RuntimeAuthorityOwner,
    client: &mut proto::runtime_deployment_registry_client::RuntimeDeploymentRegistryClient<
        tonic::transport::Channel,
    >,
    original: &proto::RegisterRuntimeDeploymentRequest,
) {
    let mut candidate = original.clone();
    let launch = candidate
        .attestation
        .as_mut()
        .unwrap()
        .launch
        .as_mut()
        .unwrap();
    launch.process_instance_id = Uuid::now_v7().to_string();
    fixture_data::seal(launch);
    let id = Uuid::parse_str(&launch.process_instance_id).unwrap();
    let key = i64::from_be_bytes(id.as_bytes()[8..16].try_into().unwrap());
    let mut blocker = tokio::task::block_in_place(|| {
        let mut db = f.client();
        db.query_one("SELECT pg_advisory_lock($1)", &[&key])
            .unwrap();
        // The sequence is an independent nontransactional entry witness. It
        // cannot be rolled back with the INSERT that is under test.
        db.batch_execute(&format!("CREATE SEQUENCE registration_entered; CREATE FUNCTION registration_hold() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('registration_entered'); PERFORM pg_advisory_xact_lock({key}); RETURN NEW; END $$; CREATE TRIGGER registration_hold BEFORE INSERT ON mcp_proxy_deployment_attestations FOR EACH ROW EXECUTE FUNCTION registration_hold();")).unwrap();
        db
    });
    let mut pending_client = client.clone();
    let pending = tokio::spawn(async move { pending_client.register_deployment(candidate).await });
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        let entered = tokio::task::block_in_place(|| {
            blocker
                .query_one("SELECT is_called FROM registration_entered", &[])
                .unwrap()
                .get::<_, bool>(0)
        });
        if entered {
            break;
        }
        assert!(
            Instant::now() < until,
            "must reach physical INSERT before revocation"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    owner.request_shutdown();
    tokio::task::block_in_place(|| {
        assert!(
            blocker
                .query_one("SELECT pg_advisory_unlock($1)", &[&key])
                .unwrap()
                .get::<_, bool>(0)
        );
    });
    let error = tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::PermissionDenied);
    assert_eq!(error.message(), "MANAGED_AUTHORITY_REFUSED");
    tokio::task::block_in_place(|| {
        for table in ["mcp_proxy_deployments", "mcp_proxy_deployment_attestations"] {
            assert_eq!(
                blocker
                    .query_one(
                        &format!("SELECT count(*) FROM {table} WHERE instance_id=$1"),
                        &[&id]
                    )
                    .unwrap()
                    .get::<_, i64>(0),
                0,
                "revocation must roll back candidate and provenance, not merely hide its reply"
            );
        }
        blocker.batch_execute("DROP TRIGGER registration_hold ON mcp_proxy_deployment_attestations; DROP FUNCTION registration_hold(); DROP SEQUENCE registration_entered;").unwrap();
        drop(blocker);
    });
}
