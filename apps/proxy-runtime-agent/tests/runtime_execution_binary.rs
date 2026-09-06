//! Compiled agent process, real TLS callback fixture. This is NOT a PG/root acceptance.
#[cfg(target_os = "linux")]
#[path = "runtime_execution_binary/linux.rs"]
mod linux;

#[test]
fn binary_rejects_ambiguous_cli_and_unsupported_host() {
    for args in [
        vec![],
        vec!["--config-dir", "relative"],
        vec!["--config-dir", "/absolute", "extra"],
        vec!["--config-dir", "/a", "--config-dir", "/b"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_apex-proxy-runtime-agent"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("RUNTIME_USAGE")
        );
    }
    #[cfg(not(target_os = "linux"))]
    {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_apex-proxy-runtime-agent"))
            .args(["--config-dir", "C:/fixed"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("RUNTIME_PRODUCTION_REQUIRES_LINUX")
        );
    }
}

// Existing real-TLS callback fixture only; no injected production executor.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "runtime_peer_pair/pki.rs"]
mod pki;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "runtime_authority_client/server.rs"]
mod server;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "runtime_authority_client/support.rs"]
mod support;
