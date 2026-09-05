//! Real HTTP observations; seeded credentials are not a real IdP login proof.
use super::{
    fixture::{Fixture, Http},
    support,
};
use apex_control_plane_api::browser::telemetry::BrowserTelemetry;
use reqwest::Method;
use serde_json::{Value, json};
use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Capture {
    fn records(&self, secrets: &[&str]) -> Vec<Value> {
        let bytes = self.0.lock().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        for secret in secrets {
            assert!(!text.contains(secret), "observation leaked a canary");
        }
        text.lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

#[test]
fn failing_observation_output_does_not_change_rpc_but_surfaces_production_loss_counters() {
    struct Failing;
    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("private-destination-error"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let fixture = Fixture::new();
    let (telemetry, owner) = BrowserTelemetry::with_writer(Failing).unwrap();
    let metrics = apex_control_plane_api::GatewayRuntimeMetrics::default()
        .with_browser_observations(telemetry.clone());
    fixture.runtime.block_on(async {
        let http = Http::start_with_telemetry(fixture.sessions.clone(), telemetry).await;
        let (token, csrf) = http.seed("browser-tls-component", support::TOKEN).await;
        let response = http
            .request(
                Method::POST,
                "/api/apex/v1/McpProxyService/ListProxies",
                &token,
            )
            .header("origin", "https://console.example")
            .header("x-apex-csrf", csrf.expose_secret())
            .json(&json!({"workspaceId":"work","namespaceId":"ns"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(http.peer.state.rpc_calls(), 1);
        http.shutdown().await;
    });
    assert!(owner.shutdown(Duration::from_secs(1)).complete);
    let text = metrics.browser_observation_prometheus();
    assert!(text.contains("apex_browser_observation_exporter_errors_total 1\n"));
    assert!(text.contains("apex_browser_observation_dropped_records_total 1\n"));
    assert!(text.contains("apex_browser_observation_exported_records_total 0\n"));
    assert!(!text.contains("private-destination-error"));
    let status = metrics.status_line(false);
    assert!(status.contains("browser_dropped_records=1"));
    assert!(status.contains("browser_exporter_errors=1"));
}

#[test]
fn management_observation_contains_real_stages_integer_timing_and_no_credentials() {
    let fixture = Fixture::new();
    let capture = Capture::default();
    let (telemetry, owner) = BrowserTelemetry::with_writer(capture.clone()).unwrap();
    let counters = telemetry.clone();
    let secrets = fixture.runtime.block_on(async {
        let http = Http::start_with_telemetry(fixture.sessions.clone(), telemetry).await;
        let (token, csrf) = http.seed("browser-tls-component", support::TOKEN).await;
        let response = http
            .request(
                Method::POST,
                "/api/apex/v1/McpProxyService/ListProxies",
                &token,
            )
            .header("origin", "https://console.example")
            .header("x-apex-csrf", csrf.expose_secret())
            .json(&json!({"workspaceId":"work","namespaceId":"ns"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(http.peer.state.rpc_calls(), 1);
        let secrets = [
            token.expose_secret().to_owned(),
            csrf.expose_secret().to_owned(),
        ];
        http.shutdown().await;
        secrets
    });
    assert!(owner.shutdown(Duration::from_secs(1)).complete);
    let records = capture.records(&[
        &secrets[0],
        &secrets[1],
        support::TOKEN,
        "hostile-browser-secret-canary",
        "fixture-refresh-secret-canary",
        "browser-tls-component",
    ]);
    assert_eq!(
        records.len(),
        1,
        "each handler response owns exactly one observation"
    );
    let record = &records[0];
    assert_eq!(record["action"], "management");
    assert_eq!(record["status"], "ok");
    assert_eq!(record["completion"], "handler_response_ready");
    assert_eq!(record["partial"], false);
    let id = uuid::Uuid::parse_str(record["requestId"].as_str().unwrap()).unwrap();
    assert_eq!(id.get_version_num(), 7);
    let stages = record["stages"].as_array().unwrap();
    for expected in [
        "ingress",
        "session_load",
        "crypto",
        "csrf",
        "decode",
        "auth",
        "session_touch",
        "management",
    ] {
        assert!(
            stages.iter().any(|stage| stage["stage"] == expected),
            "missing actual stage {expected}"
        );
    }
    for stage in stages {
        let timing = &stage["timing"];
        assert_eq!(stage["outcome"], "completed");
        assert!(
            timing["startedAtUnixUs"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                > 0
        );
        let us = timing["durationUs"]
            .as_str()
            .unwrap_or("0")
            .parse::<u64>()
            .unwrap();
        let ns = timing["durationNs"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert_eq!(us, ns / 1_000);
        assert_eq!(timing["otelTraceId"], record["otelTraceId"]);
        assert_eq!(timing["parentSpanId"], record["rootSpanId"]);
        assert_eq!(timing["processInstanceId"], record["processInstanceId"]);
    }
    assert_eq!(counters.counters().exported_records, 1);
    assert_eq!(counters.counters().dropped_records, 0);
}

#[test]
fn denied_and_unknown_requests_are_observed_without_url_query_or_header_leak() {
    let fixture = Fixture::new();
    let capture = Capture::default();
    let (telemetry, owner) = BrowserTelemetry::with_writer(capture.clone()).unwrap();
    fixture.runtime.block_on(async {
        let http = Http::start_with_telemetry(fixture.sessions.clone(), telemetry).await;
        for (path, status) in [
            ("/api/session?code=query-secret-canary", 401),
            ("/unknown-secret-canary", 404),
        ] {
            let response = http
                .client
                .get(format!("{}{path}", http.origin))
                .header("authorization", "Bearer header-secret-canary")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), status);
        }
        assert_eq!(http.peer.state.rpc_calls(), 0);
        http.shutdown().await;
    });
    assert!(owner.shutdown(Duration::from_secs(1)).complete);
    let records = capture.records(&[
        "query-secret-canary",
        "unknown-secret-canary",
        "header-secret-canary",
    ]);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["action"], "session");
    assert_eq!(records[0]["status"], "unauthorized");
    assert_eq!(records[1]["action"], "rejected");
    assert_eq!(records[1]["status"], "not_found");
}

#[test]
fn session_login_callback_refresh_and_logout_observe_only_their_actual_boundaries() {
    let fixture = Fixture::new();
    let capture = Capture::default();
    let (telemetry, owner) = BrowserTelemetry::with_writer(capture.clone()).unwrap();
    fixture.runtime.block_on(async {
        let http = Http::start_with_telemetry(fixture.sessions.clone(), telemetry).await;
        let (token, csrf) = http.seed("browser-tls-component", support::TOKEN).await;
        assert_eq!(
            http.request(Method::GET, "/api/session", &token)
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(
            http.client
                .get(format!("{}/auth/login", http.origin))
                .send()
                .await
                .unwrap()
                .status(),
            503
        );
        let (state, browser) = http.seed_login().await;
        let mut callback_url = url::Url::parse(&format!("{}/auth/callback", http.origin)).unwrap();
        callback_url
            .query_pairs_mut()
            .append_pair("state", state.expose_secret())
            .append_pair("code", "callback-secret-canary");
        let callback = http
            .client
            .get(callback_url)
            .header(
                "cookie",
                format!("__Host-apex_login={}", browser.expose_secret()),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(callback.status(), 503);
        let (short, _) = http
            .seed_with_lifetime("browser-tls-component", support::TOKEN, 10)
            .await;
        assert_eq!(
            http.request(Method::GET, "/api/session", &short)
                .send()
                .await
                .unwrap()
                .status(),
            503
        );
        let logout = http
            .request(Method::POST, "/auth/logout", &token)
            .header("origin", "https://console.example")
            .header("x-apex-csrf", csrf.expose_secret())
            .send()
            .await
            .unwrap();
        assert_eq!(logout.status(), 204);
        http.shutdown().await;
    });
    assert!(owner.shutdown(Duration::from_secs(1)).complete);
    let records = capture.records(&[
        "callback-secret-canary",
        support::TOKEN,
        "fixture-refresh-secret-canary",
        "hostile-browser-secret-canary",
    ]);
    assert_eq!(records.len(), 5);
    for (index, action, status, expected) in [
        (
            0,
            "session",
            "ok",
            &[
                "session_load",
                "crypto",
                "auth",
                "session_touch",
                "serialization",
            ][..],
        ),
        (1, "login", "unavailable", &["login_admission", "provider"]),
        (
            2,
            "callback",
            "unavailable",
            &["decode", "session_commit", "crypto", "provider"],
        ),
        (
            3,
            "session",
            "unavailable",
            &["session_load", "refresh_claim", "crypto", "provider"],
        ),
        (
            4,
            "logout",
            "ok",
            &["session_load", "csrf", "crypto", "local_revoke", "provider"],
        ),
    ] {
        let record = &records[index];
        assert_eq!(record["action"], action);
        assert_eq!(record["status"], status);
        let stages = record["stages"].as_array().unwrap();
        for name in expected {
            assert!(
                stages.iter().any(|stage| stage["stage"] == *name),
                "{action} missing {name}"
            );
        }
        if index != 0 {
            assert!(
                stages
                    .iter()
                    .any(|stage| stage["stage"] == "provider" && stage["outcome"] == "error")
            );
        }
    }
}
