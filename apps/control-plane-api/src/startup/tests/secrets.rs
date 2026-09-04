// Startup tests for secrets.

#[test]
fn bounded_reads_reject_empty_and_oversized_secret_material() {
    let root = scratch("bounded");
    let file = root.join("material");

    fs::write(&file, b"pem-bytes").unwrap();
    assert_eq!(read_bounded(&file, 32, "material").unwrap(), b"pem-bytes");

    fs::write(&file, b"").unwrap();
    assert!(read_bounded(&file, 32, "material").is_err());

    fs::write(&file, vec![b'a'; 33]).unwrap();
    assert!(read_bounded(&file, 32, "material").is_err());
    // Exactly at the limit is still accepted.
    assert!(read_bounded(&file, 33, "material").is_ok());

    assert!(read_bounded(&root.join("missing"), 32, "material").is_err());
}

#[test]
fn credential_table_reader_allows_multiline_entries_but_not_binary() {
    let root = scratch("table");
    let file = root.join("tokens");

    // One entry per line is the shape a human maintains, and
    // `parse_operator_token_table` trims each `;`-separated entry, so the
    // reader must not reject the newlines the way a single-token reader would.
    let table = "operator-token-aaaaaaaa|acme/prod;\noperator-token-bbbbbbbb|*;\n";
    fs::write(&file, table).unwrap();
    let raw = read_credential_table(&file, 4096, "tokens").unwrap();
    assert_eq!(raw, table);
    let resolver = apex_control_plane_api::parse_operator_token_table(&raw).unwrap();
    // Round-trips into a usable table, not just a readable string.
    drop(resolver);

    fs::write(&file, b"token|acme/prod\x00").unwrap();
    assert!(read_credential_table(&file, 4096, "tokens").is_err());
    fs::write(&file, "token|acme/pröd").unwrap();
    assert!(read_credential_table(&file, 4096, "tokens").is_err());
    fs::write(&file, "   \n\t  ").unwrap();
    assert!(read_credential_table(&file, 4096, "tokens").is_err());
}

#[test]
fn trusted_secret_path_confines_material_to_the_trusted_base() {
    let root = scratch("trusted");
    let base = root.join("base");
    fs::create_dir_all(&base).unwrap();
    let inside = base.join("server.pem");
    fs::write(&inside, b"pem").unwrap();

    assert!(trusted_secret_path(&inside, &base, 4096, false, "cert").is_ok());

    // Outside the base, an empty file, an oversized file, a directory, and a
    // missing base are each refused.
    let outside = root.join("elsewhere.pem");
    fs::write(&outside, b"pem").unwrap();
    assert!(trusted_secret_path(&outside, &base, 4096, false, "cert").is_err());

    let empty = base.join("empty.pem");
    fs::write(&empty, b"").unwrap();
    assert!(trusted_secret_path(&empty, &base, 4096, false, "cert").is_err());
    assert!(trusted_secret_path(&inside, &base, 2, false, "cert").is_err());
    assert!(trusted_secret_path(&base, &base, 4096, false, "cert").is_err());
    assert!(trusted_secret_path(&inside, &root.join("absent"), 4096, false, "cert").is_err());
    assert!(trusted_secret_path(&base.join("missing.pem"), &base, 4096, false, "cert").is_err());
}

#[test]
fn trusted_secret_path_defers_to_the_platform_private_key_permission_check() {
    let root = scratch("private");
    let key = root.join("server.key");
    fs::write(&key, b"private-key-material").unwrap();
    let canonical = key.canonicalize().unwrap();

    // Whatever this platform's default permissions/ACL happen to be, the
    // `private` branch must agree exactly with the shared permissions
    // primitive rather than silently ignoring it in either direction. Same
    // assertion `event-ingest`'s startup tests make about its own copy.
    let restricted = apex_durability::permissions::private_key_permissions_restricted(&canonical);
    assert_eq!(
        trusted_secret_path(&key, &root, 4096, true, "key").is_ok(),
        restricted
    );
    assert!(trusted_secret_path(&key, &root, 4096, false, "key").is_ok());
}

#[test]
fn trusted_secret_path_refuses_a_symlinked_secret() {
    let root = scratch("symlink");
    let target = root.join("real.pem");
    fs::write(&target, b"pem").unwrap();
    let link = root.join("link.pem");
    if !create_symlink(&target, &link) {
        // Unprivileged Windows without Developer Mode cannot create symlinks;
        // the check itself is platform-independent, so skip rather than
        // assert on the host's privilege level.
        eprintln!("skip symlink case: this host does not permit symlink creation");
        return;
    }
    assert!(trusted_secret_path(&link, &root, 4096, false, "cert").is_err());
}
