use crate::{material::Materials, operation::Fixture, pki::Pki};
use apex_control_plane_api::{
    RuntimeAuthorityError,
    proto::{self, runtime_authority_service_server::RuntimeAuthorityService},
};
use apex_durability::PostgresClientOps;
use std::time::{Duration, Instant};

fn url(fixture: &Fixture) -> (String, String) {
    let name = format!("authority_owned_{}", uuid::Uuid::now_v7().simple());
    (
        format!("{}&application_name={name}", fixture.database.url),
        name,
    )
}

fn connections(fixture: &Fixture, name: &str) -> i64 {
    crate::observer::connect(&fixture.database.url)
        .query_one(
            "SELECT count(*) FROM pg_stat_activity WHERE application_name=$1",
            &[&name],
        )
        .unwrap()
        .get(0)
}

#[test]
fn owner_starts_one_real_pg_connection_and_final_unpolled_facade_drop_cleans_it() {
    let fixture = Fixture::new(true);
    fixture.positive();
    let materials = Materials::new(&fixture, &Pki::require());
    let (url, name) = url(&fixture);
    let mut owner = materials.owner(&url);
    assert_eq!(connections(&fixture, &name), 0);
    let result = owner.start();
    if result.is_err() {
        let _ = owner.shutdown(); // Keep cleanup ownership even during semantic RED.
    }
    let service = result.expect("valid protected metadata plus actual PostgreSQL must start");
    assert_eq!(connections(&fixture, &name), 1);
    assert!(
        matches!(owner.start(), Err(RuntimeAuthorityError::Unavailable)),
        "never spawn replacement workers"
    );
    assert_eq!(connections(&fixture, &name), 1);
    // Creating then dropping an unpolled handler future must not retain a
    // facade reference forever; final facade Drop must signal the workers.
    let unpolled = service.check_runtime_authority(tonic::Request::new(
        proto::CheckRuntimeAuthorityRequest::default(),
    ));
    drop(unpolled);
    drop(service);
    let until = Instant::now() + Duration::from_secs(3);
    while connections(&fixture, &name) != 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    let independently_closed = connections(&fixture, &name) == 0;
    let cleanup = owner.shutdown();
    assert!(
        independently_closed,
        "final facade drop, not explicit owner stop, closes PG"
    );
    assert!(cleanup.reader_complete && cleanup.postgres_complete && cleanup.cleanup_complete);
    assert_eq!(
        owner.shutdown(),
        cleanup,
        "actual observed cleanup is idempotent"
    );
    fixture.positive();
}

#[test]
fn missing_initial_file_refuses_and_partial_owner_cleanup_is_observed() {
    let fixture = Fixture::new(true);
    fixture.positive();
    let materials = Materials::new(&fixture, &Pki::require());
    materials.remove_enrollment();
    let (url, name) = url(&fixture);
    let mut owner = materials.owner(&url);
    let result = owner.start();
    let cleanup = owner.shutdown();
    assert!(matches!(result, Err(RuntimeAuthorityError::Unavailable)));
    assert!(
        cleanup.cleanup_complete,
        "observe actual partial-start worker cleanup"
    );
    assert_eq!(connections(&fixture, &name), 0);
}

#[test]
fn valid_files_with_failed_pg_connect_do_not_fabricate_a_service_or_lose_reader() {
    let fixture = Fixture::new(true);
    let materials = Materials::new(&fixture, &Pki::require());
    let mut owner =
        materials.owner("postgresql://test:test@127.0.0.1:1/unavailable?sslmode=disable");
    let result = owner.start();
    let cleanup = owner.shutdown();
    assert!(matches!(result, Err(RuntimeAuthorityError::Unavailable)));
    assert!(cleanup.cleanup_complete);
    assert!(
        matches!(owner.start(), Err(RuntimeAuthorityError::Unavailable)),
        "a failed owner is not restarted"
    );
}

#[test]
fn start_refuses_entered_tokio_without_starting_pg_and_owner_is_retained() {
    let fixture = Fixture::new(true);
    let materials = Materials::new(&fixture, &Pki::require());
    let (url, name) = url(&fixture);
    let mut owner = materials.owner(&url);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(async { owner.start() });
    assert!(matches!(result, Err(RuntimeAuthorityError::Unavailable)));
    assert_eq!(connections(&fixture, &name), 0);
    drop(runtime);
    assert!(owner.shutdown().cleanup_complete);
}
