use super::decode_health_stdout;
use crate::proto;

mod adversarial;
mod binding;
mod fixture;
mod samples;

#[test]
fn consumes_original_ready_report_without_rounding_or_restamping() {
    let launch = fixture::launch();
    let decoded = decode_health_stdout(&fixture::stdout(&fixture::report(&launch)), &launch)
        .expect("valid ready output must pass the refusal stub");
    let report = decoded.as_report();
    assert!(report.live && report.ready);
    assert_eq!(report.target, launch.target);
    assert_eq!(report.observed_at_unix_us, 9_007_199_254_740_993);
    assert_eq!(report.checks.len(), 9);
    assert_eq!(report.stages.len(), 9);
    assert_eq!(report.stages[0].duration_ns, Some(7001));
    assert_eq!(report.stages[0].duration_us, 7);
}

#[test]
fn preserves_submicrosecond_remainders_and_all_uint64_extrema() {
    let mut launch = fixture::launch();
    launch.target.as_mut().unwrap().generation = u64::MAX;
    launch.target.as_mut().unwrap().fencing_token = u64::MAX;
    for (ns, us) in [
        (1001, 1),
        (7001, 7),
        (999001, 999),
        (999, 0),
        (0, 0),
        (9_007_199_254_740_993_123, 9_007_199_254_740_993),
        (u64::MAX, 18_446_744_073_709_551),
    ] {
        for uncertainty in [None, Some(0), Some(u64::MAX)] {
            let mut report = fixture::report(&launch);
            report.observed_at_unix_us = u64::MAX;
            let stage = &mut report.stages[0];
            stage.duration_ns = Some(ns);
            stage.duration_us = us;
            stage.started_at_unix_us = u64::MAX;
            stage.clock_resolution_ns = u64::MAX;
            stage.clock_uncertainty_us = uncertainty;
            stage.clock_source = "\\".repeat(128);
            let decoded = decode_health_stdout(&fixture::stdout(&report), &launch).unwrap();
            assert_eq!(decoded.as_report(), &report);
        }
    }
    let mut report = fixture::report(&launch);
    report.observed_at_unix_us = 1;
    // Stages may have later wall anchors; only the physical caller owns freshness.
    assert!(decode_health_stdout(&fixture::stdout(&report), &launch).is_ok());
}

#[test]
fn accepts_reordered_complete_checks_and_stages() {
    let launch = fixture::launch();
    let mut report = fixture::report(&launch);
    report.checks.reverse();
    report.stages.rotate_left(3);
    assert_eq!(
        decode_health_stdout(&fixture::stdout(&report), &launch)
            .unwrap()
            .as_report(),
        &report
    );
}

/// Main can supply the actual TS codec output plus LF and its original launch.
/// The typed fixture envelope preserves stdout UTF-8; no report reserialization.
#[test]
#[ignore = "explicit TS-to-Rust parity; requires APEX_HEALTH_REPORT_FIXTURE_PATH"]
fn consumes_typescript_health_stdout() {
    use std::io::Read;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        launch: proto::RuntimeLaunchContext,
        stdout: String,
    }
    let path = std::env::var_os("APEX_HEALTH_REPORT_FIXTURE_PATH")
        .expect("explicit fixture path required");
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .expect("fixture file")
        .take(32_769)
        .read_to_end(&mut bytes)
        .expect("fixture read");
    assert!(bytes.len() <= 32_768, "fixture envelope oversized");
    let Fixture { launch, stdout } = serde_json::from_slice(&bytes).expect("typed TS fixture");
    let decoded =
        decode_health_stdout(stdout.as_bytes(), &launch).expect("actual TS stdout must decode");
    assert_eq!(decoded.as_report(), &expected_typescript_report(&launch));
}

// Independent oracle for Main's fixed TS exporter matrix. Only identity and
// hashes come from the expected launch; nothing is derived by decoding stdout.
fn expected_typescript_report(launch: &proto::RuntimeLaunchContext) -> proto::ReadinessReport {
    use proto::ReadinessCheckId as Id;
    let samples = [
        (Id::Config, "readiness.config", 1001, 1, None),
        (Id::Launch, "readiness.launch", 7001, 7, Some(0)),
        (
            Id::Material,
            "readiness.material",
            999001,
            999,
            Some(u64::MAX),
        ),
        (Id::InboundAuth, "readiness.inbound_auth", 999, 0, None),
        (
            Id::UpstreamCatalog,
            "readiness.upstream_catalog",
            0,
            0,
            Some(0),
        ),
        (
            Id::Governance,
            "readiness.governance",
            9_007_199_254_740_993_123,
            9_007_199_254_740_993,
            Some(u64::MAX),
        ),
        (
            Id::EvidenceAdmission,
            "readiness.evidence_admission",
            u64::MAX,
            18_446_744_073_709_551,
            None,
        ),
        (Id::Network, "readiness.network", 1000, 1, Some(0)),
        (
            Id::Admission,
            "readiness.admission",
            7000,
            7,
            Some(u64::MAX),
        ),
    ];
    proto::ReadinessReport {
        live: true,
        ready: true,
        target: launch.target.clone(),
        observed_at_unix_us: u64::MAX,
        config_hash: launch.config_hash.clone(),
        runtime_manifest_hash: launch.runtime_manifest_hash.clone(),
        process_instance_id: launch.process_instance_id.clone(),
        launch_context_hash: launch.launch_context_hash.clone(),
        checks: samples
            .iter()
            .map(|(id, ..)| proto::ReadinessCheck {
                id: (*id).into(),
                status: proto::ReadinessCheckStatus::Pass.into(),
                reason: proto::ReadinessReason::Ok.into(),
            })
            .collect(),
        stages: samples
            .iter()
            .enumerate()
            .map(
                |(index, (_, name, ns, us, uncertainty))| proto::ProxyStageTiming {
                    name: (*name).into(),
                    started_at_unix_us: 9_007_199_254_740_993 + u64::try_from(index).unwrap(),
                    duration_ns: Some(*ns),
                    duration_us: *us,
                    otel_trace_id: String::new(),
                    span_id: String::new(),
                    parent_span_id: String::new(),
                    process_instance_id: launch.process_instance_id.clone(),
                    clock_source: "component-clock".into(),
                    clock_resolution_ns: 1000,
                    clock_uncertainty_us: *uncertainty,
                },
            )
            .collect(),
    }
}
