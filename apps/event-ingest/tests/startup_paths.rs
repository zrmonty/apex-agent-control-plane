use std::process::Command;

fn run_with_env(extra: &[(&str, &str)]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_apex-event-ingest"));
    command.env_clear();
    for (key, value) in extra {
        command.env(key, value);
    }
    command.output().expect("gateway process should start")
}

#[test]
fn startup_rejects_missing_trusted_base_before_network_access() {
    let output = run_with_env(&[]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("APEX_TRUSTED_SECRET_BASE"));
}

#[test]
fn startup_reports_missing_nats_url_after_trusted_base() {
    let output = run_with_env(&[("APEX_TRUSTED_SECRET_BASE", ".")]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("APEX_NATS_URL"));
}

#[test]
fn startup_rejects_invalid_retry_budget_before_network_access() {
    let output = run_with_env(&[
        ("APEX_TRUSTED_SECRET_BASE", "."),
        ("APEX_RETRY_ATTEMPTS", "0"),
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("APEX_RETRY_ATTEMPTS"));
}

#[test]
fn startup_reports_each_required_nats_configuration_field() {
    let cases = [
        ("APEX_NATS_URL", "APEX_NATS_URL"),
        ("APEX_NATS_CA_FILE", "APEX_NATS_CA_FILE"),
        ("APEX_NATS_CLIENT_CERT_FILE", "APEX_NATS_CLIENT_CERT_FILE"),
        ("APEX_NATS_CLIENT_KEY_FILE", "APEX_NATS_CLIENT_KEY_FILE"),
    ];
    for (field, expected) in cases {
        let mut values = vec![
            ("APEX_TRUSTED_SECRET_BASE", "."),
            ("APEX_NATS_URL", "tls://127.0.0.1:1"),
            ("APEX_NATS_CA_FILE", "ca.pem"),
            ("APEX_NATS_CLIENT_CERT_FILE", "cert.pem"),
            ("APEX_NATS_CLIENT_KEY_FILE", "key.pem"),
        ];
        values.retain(|(key, _)| *key != field);
        let output = run_with_env(&values);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(expected));
    }
}
