use super::support::*;
use apex_proxy_runtime_agent::proto::RuntimeMaterialRole as Role;
use std::{fs, os::unix::fs::MetadataExt};

// Catches missing writes, semantic validation added at the wrong boundary,
// incorrect UID/GID/modes, generated replacement IDs and deletion on drop.
#[test]
fn stages_opaque_owner_bytes_and_seals_exact_caller_instance_without_drop_cleanup() {
    let fixture = Fixture::new();
    let owner = fixture.owner();
    let staged = owner
        .stage(&target(), INSTANCE, REVISION, LAUNCH, &[health()])
        .unwrap();
    assert_eq!(staged.instance_id(), "0191b7f1-7f2c-7c13-9a61-2f29f2be1004");
    assert_eq!(
        staged.directory(),
        fixture
            .state
            .join("apex-runtime-0191b7f1-7f2c-7c13-9a61-2f29f2be1004")
    );
    let directory = staged.directory().to_owned();
    let metadata = fs::symlink_metadata(&directory).unwrap();
    assert!(metadata.file_type().is_dir());
    assert_eq!(metadata.mode() & 0o7777, 0o500);
    assert_eq!((metadata.uid(), metadata.gid()), (10001, 10001));
    assert_file(
        &directory.join("runtime-revision.json"),
        b"synthetic revision bytes, not a published manifest",
    );
    assert_file(
        &directory.join("launch-context.json"),
        b"synthetic launch bytes, not an authorized launch",
    );
    assert_file(
        &directory.join("health-token"),
        b"0123456789abcdefghijklmnopqrstuvwxyzABCDEF8",
    );
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 3);
    drop(staged);
    drop(owner);
    assert_file(
        &directory.join("health-token"),
        b"0123456789abcdefghijklmnopqrstuvwxyzABCDEF8",
    );
}

// Catches incorrect/extra role paths and accidental reuse of one role's bytes.
#[test]
fn every_role_has_its_fixed_filename_and_independent_bytes() {
    let fixture = Fixture::new();
    let roles: [(Role, &str, &str, &[u8]); 12] = [
        (
            Role::GovernanceCa,
            "gca",
            "governance-ca",
            b"governance CA bytes",
        ),
        (
            Role::GovernanceCert,
            "gcert",
            "governance-cert",
            b"governance cert bytes",
        ),
        (
            Role::GovernanceKey,
            "gkey",
            "governance-key",
            b"governance key bytes",
        ),
        (
            Role::GovernanceToken,
            "gtoken",
            "governance-token",
            b"governance token bytes",
        ),
        (Role::EvidenceCa, "eca", "evidence-ca", b"evidence CA bytes"),
        (
            Role::EvidenceCert,
            "ecert",
            "evidence-cert",
            b"evidence cert bytes",
        ),
        (
            Role::EvidenceKey,
            "ekey",
            "evidence-key",
            b"evidence key bytes",
        ),
        (
            Role::EvidenceToken,
            "etoken",
            "evidence-token",
            b"evidence token bytes",
        ),
        (
            Role::InboundJwks,
            "jwks",
            "inbound-jwks",
            b"opaque JWKS fixture",
        ),
        (Role::WorkloadCa, "wca", "workload-ca", b"workload CA bytes"),
        (
            Role::WorkloadCert,
            "wcert",
            "workload-cert",
            b"workload cert bytes",
        ),
        (
            Role::WorkloadKey,
            "wkey",
            "workload-key",
            b"workload key bytes",
        ),
    ];
    let mut materials = vec![health()];
    for (role, source, _, bytes) in roles {
        fixture.write(source, bytes);
        materials.push(material(role, source));
    }
    let staged = fixture
        .owner()
        .stage(&target(), INSTANCE, REVISION, LAUNCH, &materials)
        .unwrap();
    for (_, _, filename, expected) in roles {
        assert_file(&staged.directory().join(filename), expected);
    }
    assert_eq!(fs::read_dir(staged.directory()).unwrap().count(), 15);
}

// Catches cross-proxy leakage or collapsing stages onto a shared directory.
#[test]
fn two_proxy_deployments_keep_distinct_material_and_instance_directories() {
    let fixture = Fixture::new();
    fixture.write(
        "second-health",
        b"ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210zyxwvu0",
    );
    let owner = fixture.owner();
    let first = owner
        .stage(&target(), INSTANCE, REVISION, LAUNCH, &[health()])
        .unwrap();
    let mut second_target = target();
    second_target.proxy_id = OTHER.into();
    let mut second_material = material(Role::HealthToken, "second-health");
    second_material.proxy_id = OTHER.into();
    second_material.reference = format!("secret://acme/prod/{OTHER}/second-health");
    let second = owner
        .stage(&second_target, OTHER, REVISION, LAUNCH, &[second_material])
        .unwrap();
    assert_ne!(first.directory(), second.directory());
    assert_eq!(first.instance_id(), INSTANCE);
    assert_eq!(second.instance_id(), OTHER);
    assert_file(
        &first.directory().join("health-token"),
        b"0123456789abcdefghijklmnopqrstuvwxyzABCDEF8",
    );
    assert_file(
        &second.directory().join("health-token"),
        b"ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210zyxwvu0",
    );
}

// Catches off-by-one upper limits and lossy/integer-precision target handling.
#[test]
fn accepts_exact_byte_limits_and_signed_sql_maximum() {
    let fixture = Fixture::new();
    fixture.write("large", &vec![b'K'; 65_536]);
    let mut target = target();
    target.generation = 9_223_372_036_854_775_807;
    target.fencing_token = 9_223_372_036_854_775_807;
    let staged = fixture
        .owner()
        .stage(
            &target,
            INSTANCE,
            &vec![b'R'; 262_144],
            &vec![b'L'; 16_384],
            &[health(), material(Role::WorkloadKey, "large")],
        )
        .unwrap();
    assert_file(
        &staged.directory().join("workload-key"),
        &vec![b'K'; 65_536],
    );
    assert_file(
        &staged.directory().join("runtime-revision.json"),
        &vec![b'R'; 262_144],
    );
    assert_file(
        &staged.directory().join("launch-context.json"),
        &vec![b'L'; 16_384],
    );
}

// Catches Debug implementations that accidentally expose staged secret buffers.
#[test]
fn successful_objects_and_material_debug_do_not_disclose_secret_canary() {
    let fixture = Fixture::new();
    fixture.write("canary", CANARY);
    let owner = fixture.owner();
    let staged = owner
        .stage(
            &target(),
            INSTANCE,
            REVISION,
            LAUNCH,
            &[health(), material(Role::WorkloadKey, "canary")],
        )
        .unwrap();
    assert_no_canary(&owner);
    assert_no_canary(&staged);
    let mut input = health();
    input.reference = std::str::from_utf8(CANARY).unwrap().into();
    input.source_name = input.reference.clone();
    assert_no_canary(&input);
}

// Catches replacing the caller's ID after launch construction. This synthetic
// object tests byte preservation only, not full launch/publication validity.
#[test]
fn caller_can_bind_the_exact_staging_instance_into_launch_bytes() {
    let fixture = Fixture::new();
    let launch = br#"{"process_instance_id":"0191b7f1-7f2c-7c13-9a61-2f29f2be1004"}"#;
    let staged = fixture
        .owner()
        .stage(&target(), INSTANCE, REVISION, launch, &[health()])
        .unwrap();
    assert_eq!(staged.instance_id(), "0191b7f1-7f2c-7c13-9a61-2f29f2be1004");
    assert_file(
        &staged.directory().join("launch-context.json"),
        br#"{"process_instance_id":"0191b7f1-7f2c-7c13-9a61-2f29f2be1004"}"#,
    );
}

// Catches rejecting legitimate private read-only source files, the lower byte
// bound, or inclusive reference/version limits.
#[test]
fn accepts_read_only_sources_single_byte_inputs_and_full_length_metadata() {
    let fixture = Fixture::new();
    fixture.write("key", b"K");
    mode(&fixture.source.join("key"), 0o400);
    mode(&fixture.source.join("health-source"), 0o400);
    let mut key = material(Role::WorkloadKey, "key");
    key.reference = "r".repeat(256);
    key.version = "v".repeat(128);
    let staged = fixture
        .owner()
        .stage(&target(), INSTANCE, b"R", b"L", &[health(), key])
        .unwrap();
    assert_file(&staged.directory().join("workload-key"), b"K");
    assert_file(&staged.directory().join("runtime-revision.json"), b"R");
    assert_file(&staged.directory().join("launch-context.json"), b"L");
}
