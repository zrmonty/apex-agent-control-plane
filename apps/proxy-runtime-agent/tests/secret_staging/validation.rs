use super::support::*;
use apex_proxy_runtime_agent::{proto::RuntimeMaterialRole as Role, secrets::StagingError};
use std::{error::Error, fs, os::unix::fs::MetadataExt};

// Catches validating just one scope field, or reading an earlier material before
// discovering that a later deployment-owned entry is outside the target scope.
#[test]
fn all_material_scopes_are_checked_before_any_source_read() {
    for field in ["workspace", "namespace", "proxy"] {
        let fixture = Fixture::new();
        let path = fixture.source.join("health-source");
        mark_unread(&path);
        let mut foreign = material(Role::WorkloadKey, "missing-source");
        match field {
            "workspace" => foreign.workspace_id = "other".into(),
            "namespace" => foreign.namespace_id = "other".into(),
            "proxy" => foreign.proxy_id = OTHER.into(),
            _ => unreachable!(),
        }
        fixture.refuse(&[health(), foreign], StagingError::ScopeMismatch);
        assert_eq!(fs::metadata(path).unwrap().atime(), 0);
        assert!(fixture.state_names().is_empty());
    }
}

// Catches treating an otherwise valid reference as authority for another proxy.
#[test]
fn reference_owned_by_one_proxy_cannot_be_staged_for_another() {
    let fixture = Fixture::new();
    let mut foreign_target = target();
    foreign_target.proxy_id = OTHER.into();
    let result = fixture
        .owner()
        .stage(&foreign_target, INSTANCE, REVISION, LAUNCH, &[health()]);
    assert_eq!(result.unwrap_err(), StagingError::ScopeMismatch);
    assert!(fixture.state_names().is_empty());
}

// Catches missing target validation and accepting unsigned values beyond SQL i64.
#[test]
fn invalid_target_is_refused_before_source_access_or_staging() {
    let fixture = Fixture::new();
    let owner = fixture.owner();
    let mut invalid = Vec::new();
    for field in ["workspace", "namespace", "proxy", "revision"] {
        let mut value = target();
        match field {
            "workspace" => value.workspace_id = "../acme".into(),
            "namespace" => value.namespace_id = "".into(),
            "proxy" => value.proxy_id = "not-a-uuid".into(),
            "revision" => value.revision_id = "0191B7F1-7F2C-7C13-9A61-2F29F2BE1002".into(),
            _ => unreachable!(),
        }
        invalid.push(value);
    }
    for value in [0, 9_223_372_036_854_775_808, u64::MAX] {
        let mut generation = target();
        generation.generation = value;
        invalid.push(generation);
        let mut fence = target();
        fence.fencing_token = value;
        invalid.push(fence);
    }
    for target in invalid {
        let result = owner.stage(&target, INSTANCE, REVISION, LAUNCH, &[health()]);
        assert_eq!(result.unwrap_err(), StagingError::InvalidTarget);
    }
    assert!(fixture.state_names().is_empty());
}

// Catches generation of a replacement ID, acceptance of UUIDv4, noncanonical IDs
// or using caller input as a path before validating it.
#[test]
fn instance_must_be_canonical_uuid_v7_before_creating_a_directory() {
    let fixture = Fixture::new();
    let owner = fixture.owner();
    for instance in [
        "",
        "../escape",
        "/absolute",
        "--flag",
        "0191B7F1-7F2C-7C13-9A61-2F29F2BE1004",
        "0191b7f1-7f2c-4c13-9a61-2f29f2be1004",
        "0191b7f1-7f2c-7c13-1a61-2f29f2be1004",
        "0191b7f17f2c7c139a612f29f2be1004",
    ] {
        let result = owner.stage(&target(), instance, REVISION, LAUNCH, &[health()]);
        assert_eq!(result.unwrap_err(), StagingError::InvalidInput);
    }
    assert!(fixture.state_names().is_empty());
}

// Catches unchecked manifest/launch allocations, empty inputs and off-by-one caps.
#[test]
fn revision_and_launch_bytes_have_independent_nonempty_bounds() {
    let fixture = Fixture::new();
    let owner = fixture.owner();
    for (revision, launch) in [
        (vec![], LAUNCH.to_vec()),
        (REVISION.to_vec(), vec![]),
        (vec![b'R'; 262_145], LAUNCH.to_vec()),
        (REVISION.to_vec(), vec![b'L'; 16_385]),
    ] {
        let result = owner.stage(&target(), INSTANCE, &revision, &launch, &[health()]);
        assert_eq!(result.unwrap_err(), StagingError::InvalidInput);
    }
    assert!(fixture.state_names().is_empty());
}

// Catches ambiguous overwriting by role/reference and staging without health.
#[test]
fn material_set_requires_health_and_unique_roles_and_references_with_a_cap() {
    let fixture = Fixture::new();
    fixture.write("key", CANARY);
    let key = material(Role::WorkloadKey, "key");
    let mut same_reference = key.clone();
    same_reference.reference = health().reference;
    let mut second_health = health();
    second_health.reference = "second-health-reference".into();
    let unspecified = material(Role::Unspecified, "key");
    for materials in [
        vec![],
        vec![key],
        vec![health(), second_health],
        vec![health(), same_reference],
        vec![health(), unspecified],
        vec![health(); 14],
    ] {
        fixture.refuse(&materials, StagingError::InvalidInput);
    }
    assert!(fixture.state_names().is_empty());
}

// Catches unbounded/path-like deployment references, versions and source names.
#[test]
fn malformed_material_identifiers_cannot_reach_source_paths() {
    let fixture = Fixture::new();
    for source in [
        "",
        ".",
        "..",
        "a..b",
        "../health-source",
        "nested/health-source",
        "nested\\health-source",
        "/health-source",
        "--flag",
        "a\0b",
        "a b",
        "é",
    ] {
        let mut entry = health();
        entry.source_name = source.into();
        fixture.refuse(&[entry], StagingError::InvalidInput);
    }
    let mut long_source = health();
    long_source.source_name = "a".repeat(257);
    fixture.refuse(&[long_source], StagingError::InvalidInput);
    for reference in [
        "".into(),
        "../secret".into(),
        "/secret".into(),
        "secret://../secret".into(),
        "secret://".into(),
        "bad reference".into(),
        "a".repeat(257),
    ] {
        let mut entry = health();
        entry.reference = reference;
        fixture.refuse(&[entry], StagingError::InvalidInput);
    }
    for version in [
        "".into(),
        "../v1".into(),
        "v/1".into(),
        "v 1".into(),
        "v".repeat(129),
    ] {
        let mut entry = health();
        entry.version = version;
        fixture.refuse(&[entry], StagingError::InvalidInput);
    }
    assert!(fixture.state_names().is_empty());
}

// Catches whitespace trimming, padding, weak tokens and nonzero unused bits.
#[test]
fn health_token_requires_43_canonical_base64url_characters_with_zero_padding_bits() {
    for bytes in [
        vec![],
        vec![b'A'; 42],
        vec![b'A'; 44],
        vec![b'='; 43],
        vec![b'+'; 43],
        vec![b'/'; 43],
        vec![b' '; 43],
        vec![0xff; 43],
        [vec![b'A'; 42], vec![b'\n']].concat(),
        [vec![b'A'; 42], vec![b'B']].concat(),
        [vec![b'A'; 42], vec![b'-']].concat(),
        [vec![b'A'; 42], vec![b'_']].concat(),
    ] {
        let fixture = Fixture::new();
        fixture.write("invalid-health", &bytes);
        fixture.refuse(
            &[material(Role::HealthToken, "invalid-health")],
            StagingError::InvalidSource,
        );
    }
}

// Catches propagating IO errors or secret contents in Display/Debug/source chains.
#[test]
fn refusals_expose_static_codes_without_secret_canaries_or_error_sources() {
    let fixture = Fixture::new();
    fixture.write("bad-health", CANARY);
    let error = fixture
        .owner()
        .stage(
            &target(),
            INSTANCE,
            REVISION,
            LAUNCH,
            &[material(Role::HealthToken, "bad-health")],
        )
        .unwrap_err();
    assert_eq!(error, StagingError::InvalidSource);
    assert_no_canary(&error);
    assert!(
        !error
            .to_string()
            .contains(std::str::from_utf8(CANARY).unwrap())
    );
    assert!(error.source().is_none());
}
