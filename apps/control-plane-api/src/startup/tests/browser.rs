#[test]
fn browser_invalid_startup_policy_fails_before_secret_or_storage_access() {
    // Child-only environment: the test process never mutates global env or
    // resolves the intentionally nonexistent config/database/secret paths.
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        "startup::tests::browser_policy_child",
        "--nocapture",
    ]);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("APEX_") {
            command.env_remove(name);
        }
    }
    command
        .env("APEX_BROWSER_POLICY_TEST_CHILD", "1")
        .env("APEX_CONTROL_BROWSER_BIND_ADDR", "0.0.0.0:8088")
        .env(
            "APEX_CONTROL_BROWSER_CONFIG_FILE",
            "must-not-be-opened.json",
        )
        .env(
            "APEX_CONTROL_POSTGRES_URL",
            "postgresql://127.0.0.1:1/no_connection_expected",
        )
        .env(
            "APEX_CONTROL_KEYCLOAK_ISSUER",
            "https://127.0.0.1:1/realms/apex",
        );
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = OwnedChild(command.spawn().unwrap());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "owned startup policy child timed out"
        );
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "startup did not reject browser policy before opening dependencies"
            );
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn browser_policy_child() {
    if std::env::var("APEX_BROWSER_POLICY_TEST_CHILD").as_deref() != Ok("1") {
        return;
    }
    let error = super::service::run().expect_err("invalid browser listener started");
    assert!(
        error.to_string().contains("browser") || error.to_string().contains("APEX_CONTROL_BROWSER"),
        "browser policy must be checked before other configuration"
    );
    println!("BROWSER_POLICY_DENIED");
}
