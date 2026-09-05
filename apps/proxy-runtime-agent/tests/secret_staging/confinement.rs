use super::support::*;
use apex_proxy_runtime_agent::{
    proto::RuntimeMaterialRole as Role,
    secrets::{StagingError, StagingOwner},
};
use std::{
    fs,
    os::unix::{
        fs::{MetadataExt, chown, symlink},
        net::UnixListener,
    },
    path::Path,
};

fn refused_roots(state: &Path, source: &Path) {
    assert_eq!(
        StagingOwner::open(state, source).unwrap_err(),
        StagingError::InvalidRoot
    );
}

// Catches creating missing roots, relative resolution and overlapping roots.
#[test]
fn roots_must_already_exist_be_absolute_and_neither_equal_nor_nested() {
    let fixture = Fixture::new();
    refused_roots(Path::new("relative"), &fixture.source);
    refused_roots(&fixture.state, Path::new("relative"));
    refused_roots(&fixture.root.join("absent"), &fixture.source);
    refused_roots(&fixture.state, &fixture.root.join("absent"));
    refused_roots(&fixture.state, &fixture.state);
    let nested = fixture.state.join("nested");
    private_dir(&nested);
    refused_roots(&fixture.state, &nested);
    refused_roots(&nested, &fixture.state);
    assert!(!fixture.root.join("absent").exists());
}

// Catches checking NOFOLLOW only at the final component of a root path.
#[test]
fn symlinks_in_final_or_intermediate_state_and_source_components_are_refused() {
    let fixture = Fixture::new();
    let state_link = fixture.root.join("state-link");
    let source_link = fixture.root.join("source-link");
    symlink(&fixture.state, &state_link).unwrap();
    symlink(&fixture.source, &source_link).unwrap();
    refused_roots(&state_link, &fixture.source);
    refused_roots(&fixture.state, &source_link);
    let ancestor_link = fixture.root.join("ancestor-link");
    symlink(&fixture.root, &ancestor_link).unwrap();
    refused_roots(&ancestor_link.join("state"), &fixture.source);
    refused_roots(&fixture.state, &ancestor_link.join("source"));
    assert!(fixture.state_names().is_empty());
}

// Catches accepting group-readable final roots or writable ancestors, including
// owner checks applied only to the final root.
#[test]
fn root_modes_and_ancestor_ownership_are_checked_independently() {
    let fixture = Fixture::new();
    for permissions in [0o750, 0o755, 0o770, 0o707] {
        mode(&fixture.state, permissions);
        refused_roots(&fixture.state, &fixture.source);
        mode(&fixture.state, 0o700);
        mode(&fixture.source, permissions);
        refused_roots(&fixture.state, &fixture.source);
        mode(&fixture.source, 0o700);
    }
    for permissions in [0o720, 0o702, 0o777, 0o1777] {
        mode(&fixture.root, permissions);
        refused_roots(&fixture.state, &fixture.source);
    }
    mode(&fixture.root, 0o700);
    for path in [&fixture.state, &fixture.source, &fixture.root] {
        chown(path, Some(10002), Some(10002)).unwrap();
        refused_roots(&fixture.state, &fixture.source);
        chown(path, Some(0), Some(0)).unwrap();
    }
}

// Catches following source links (even links within the trusted source root),
// or reading the target through a directory/special file.
#[test]
fn source_symlinks_directories_and_unix_sockets_are_refused() {
    let fixture = Fixture::new();
    fixture.write("key", CANARY);
    symlink(fixture.source.join("key"), fixture.source.join("key-link")).unwrap();
    symlink(
        fixture.source.join("absent"),
        fixture.source.join("dangling"),
    )
    .unwrap();
    private_dir(&fixture.source.join("directory"));
    let _socket = UnixListener::bind(fixture.source.join("socket")).unwrap();
    for source in ["key-link", "dangling", "directory", "socket"] {
        fixture.refuse(
            &[health(), material(Role::WorkloadKey, source)],
            StagingError::InvalidSource,
        );
    }
    assert!(fs::read(fixture.source.join("key")).unwrap() == CANARY);
}

// Catches a blocking source open on FIFO: nonregular input must promptly refuse.
// Main must run the Linux suite with an external timeout to catch a blocking bug.
#[test]
fn fifo_source_is_refused_without_waiting_for_a_writer() {
    let fixture = Fixture::new();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        fixture.source.join("fifo"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    fixture.refuse(
        &[health(), material(Role::WorkloadKey, "fifo")],
        StagingError::InvalidSource,
    );
}

// Catches allowing shared inodes, externally owned files or nonprivate modes.
#[test]
fn source_hardlinks_wrong_owner_and_group_or_other_access_are_refused() {
    let fixture = Fixture::new();
    fixture.write("key", CANARY);
    let key = fixture.source.join("key");
    fs::hard_link(&key, fixture.root.join("outside-link")).unwrap();
    fixture.refuse(
        &[health(), material(Role::WorkloadKey, "key")],
        StagingError::InvalidSource,
    );
    fs::remove_file(fixture.root.join("outside-link")).unwrap();
    chown(&key, Some(10002), Some(10002)).unwrap();
    fixture.refuse(
        &[health(), material(Role::WorkloadKey, "key")],
        StagingError::InvalidSource,
    );
    chown(&key, Some(0), Some(0)).unwrap();
    for permissions in [0o640, 0o604, 0o620, 0o602, 0o644, 0o666] {
        mode(&key, permissions);
        fixture.refuse(
            &[health(), material(Role::WorkloadKey, "key")],
            StagingError::InvalidSource,
        );
    }
    assert!(fs::read(&key).unwrap() == CANARY);
}

// Catches unbounded reads, empty non-health material or accepting absent files.
#[test]
fn source_must_exist_and_contain_between_one_and_65536_bytes() {
    let fixture = Fixture::new();
    fixture.write("empty", b"");
    fixture.write("oversized", &vec![b'K'; 65_537]);
    for source in ["absent", "empty", "oversized"] {
        fixture.refuse(
            &[health(), material(Role::WorkloadKey, source)],
            StagingError::InvalidSource,
        );
    }
}

// Catches reusing, truncating, chmod/chown-ing or deleting a colliding directory.
#[test]
fn existing_caller_instance_directory_is_refused_and_never_overwritten() {
    let fixture = Fixture::new();
    let existing = fixture
        .state
        .join("apex-runtime-0191b7f1-7f2c-7c13-9a61-2f29f2be1004");
    private_dir(&existing);
    fs::write(existing.join("health-token"), b"existing-sentinel").unwrap();
    let before = fs::metadata(&existing).unwrap();
    let result = fixture
        .owner()
        .stage(&target(), INSTANCE, REVISION, LAUNCH, &[health()]);
    assert_eq!(result.unwrap_err(), StagingError::AlreadyExists);
    let after = fs::metadata(&existing).unwrap();
    assert_eq!(
        (before.ino(), before.uid(), before.gid(), before.mode()),
        (after.ino(), after.uid(), after.gid(), after.mode())
    );
    assert_eq!(
        fs::read(existing.join("health-token")).unwrap(),
        b"existing-sentinel"
    );
    assert_eq!(fs::read_dir(existing).unwrap().count(), 1);
}

// Catches following a symlink/file at the exact output name or cleaning its target.
#[test]
fn existing_symlink_and_regular_file_at_instance_path_are_preserved() {
    for link in [false, true] {
        let fixture = Fixture::new();
        let outside = fixture.root.join("outside");
        private_dir(&outside);
        fs::write(outside.join("health-token"), b"outside-sentinel").unwrap();
        let destination = fixture.state.join(format!("apex-runtime-{INSTANCE}"));
        if link {
            symlink(&outside, &destination).unwrap();
        } else {
            fs::write(&destination, b"file-sentinel").unwrap();
        }
        let result = fixture
            .owner()
            .stage(&target(), INSTANCE, REVISION, LAUNCH, &[health()]);
        assert_eq!(result.unwrap_err(), StagingError::AlreadyExists);
        assert_eq!(
            fs::read(outside.join("health-token")).unwrap(),
            b"outside-sentinel"
        );
        if link {
            assert_eq!(fs::read_link(destination).unwrap(), outside);
        } else {
            assert_eq!(fs::read(destination).unwrap(), b"file-sentinel");
        }
    }
}

// Catches treating duplicate stages as permission to reopen or replace live files.
#[test]
fn repeated_instance_refuses_while_preserving_the_first_stage() {
    let fixture = Fixture::new();
    let owner = fixture.owner();
    let first = owner
        .stage(&target(), INSTANCE, REVISION, LAUNCH, &[health()])
        .unwrap();
    let result = owner.stage(
        &target(),
        INSTANCE,
        b"replacement",
        b"replacement",
        &[health()],
    );
    assert_eq!(result.unwrap_err(), StagingError::AlreadyExists);
    assert_file(
        &first.directory().join("runtime-revision.json"),
        b"synthetic revision bytes, not a published manifest",
    );
    assert_file(
        &first.directory().join("launch-context.json"),
        b"synthetic launch bytes, not an authorized launch",
    );
}

// Catches reopening a source through its old path instead of the held root FD.
#[test]
fn replacing_source_root_path_does_not_redirect_material_reads() {
    let fixture = Fixture::new();
    let owner = fixture.owner();
    let held_source = fixture.root.join("held-source");
    fs::rename(&fixture.source, &held_source).unwrap();
    private_dir(&fixture.source);
    fixture.write(
        "health-source",
        b"ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210zyxwvu0",
    );
    let staged = owner
        .stage(&target(), INSTANCE, REVISION, LAUNCH, &[health()])
        .unwrap();
    assert_file(
        &staged.directory().join("health-token"),
        b"0123456789abcdefghijklmnopqrstuvwxyzABCDEF8",
    );
}

// A successful returned path must still name the held state directory.
#[test]
fn replacing_state_root_refuses_without_writing_either_directory() {
    let fixture = Fixture::new();
    let owner = fixture.owner();
    let held_state = fixture.root.join("held-state");
    fs::rename(&fixture.state, &held_state).unwrap();
    private_dir(&fixture.state);
    let result = owner.stage(&target(), INSTANCE, REVISION, LAUNCH, &[health()]);
    assert_eq!(result.unwrap_err(), StagingError::InvalidRoot);
    assert_eq!(fs::read_dir(&held_state).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&fixture.state).unwrap().count(), 0);
}
