use super::fixture;
use crate::{proto, readiness_report::decode_health_sample_stdout};

fn encoded(valid_for_ns: u64) -> (proto::RuntimeLaunchContext, Vec<u8>) {
    let launch = fixture::launch();
    let value = proto::RuntimeHealthSample {
        schema_version: 1,
        report: Some(fixture::report(&launch)),
        valid_for_ns,
    };
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    (launch, bytes)
}

#[test]
fn original_report_and_sub_microsecond_remaining_lifetime_are_preserved() {
    for validity in [1, 6999, 10_000_000_000] {
        let (launch, bytes) = encoded(validity);
        let sample = decode_health_sample_stdout(&bytes, &launch).unwrap();
        assert_eq!(sample.valid_for_ns(), validity);
        assert_eq!(sample.report(), &fixture::report(&launch));
        assert_eq!(sample.report().observed_at_unix_us, 9_007_199_254_740_993);
        assert_eq!(sample.report().stages[0].duration_ns, Some(7001));
        assert_eq!(sample.report().stages[0].duration_us, 7);
        assert_eq!(
            format!("{sample:?}"),
            "HealthSample { [redacted; data only] }"
        );
    }
}

#[test]
fn sample_bounds_original_nested_report_bytes_independently_of_envelope() {
    let launch = fixture::launch();
    let report = fixture::report(&launch);
    let report_json = serde_json::to_string(&report).unwrap();
    assert_nested_report_boundary(&launch, &report, &report_json);
}

#[test]
fn sample_counts_original_json_escape_bytes_before_decoding_report() {
    let launch = fixture::launch();
    let report = fixture::report(&launch);
    let report_json = serde_json::to_string(&report).unwrap();
    let escaped = report_json.replace("test-monotonic", r"\u0074est-monotonic");
    assert!(escaped.len() > report_json.len());
    assert_nested_report_boundary(&launch, &report, &escaped);
}

fn assert_nested_report_boundary(
    launch: &proto::RuntimeLaunchContext,
    report: &proto::ReadinessReport,
    report_json: &str,
) {
    for size in [8192, 8193] {
        let padding = " ".repeat(size - report_json.len());
        let original_report = format!("{{{padding}{}", &report_json[1..]);
        assert_eq!(original_report.len(), size);
        let stdout = format!(
            "{{\"schemaVersion\":1,\"report\":{original_report},\"validForNs\":\"6999\"}}\n"
        );
        assert!(stdout.len() < 16385);
        let decoded = decode_health_sample_stdout(stdout.as_bytes(), launch);
        if size == 8192 {
            let sample = decoded.expect("exactly 8192 original report bytes must be accepted");
            assert_eq!(sample.report(), report);
            assert_eq!(sample.valid_for_ns(), 6999);
        } else {
            let error = decoded.expect_err("8193 original report bytes must be refused");
            assert_eq!(error.to_string(), "readiness report rejected");
            assert_eq!(format!("{error:?}"), "ReadinessReportError");
        }
    }
}

#[test]
fn sample_refuses_invalid_duration_framing_and_bindings() {
    let (launch, bytes) = encoded(6999);
    let text = String::from_utf8(bytes).unwrap();
    let mut failures = vec![
        text.replace("\"6999\"", "\"0\""),
        text.replace("\"6999\"", "\"06999\""),
        text.replace("\"6999\"", "6999"),
        text.replace("\"6999\"", "null"),
        text.replace("\"6999\"", "\"+6999\""),
        text.replace("\"6999\"", "\"6.999e3\""),
        text.replace("\"6999\"", "\"6999 \""),
        text.replace("\"6999\"", "\"10000000001\""),
        text.replace("\"6999\"", "\"18446744073709551616\""),
        text.replace("\"schemaVersion\":1", "\"schemaVersion\":2"),
        text.replace("\"schemaVersion\":1", "\"schemaVersion\":\"1\""),
        text.replacen('{', "{\"schemaVersion\":1,", 1),
        text.replacen('{', "{\"schema\\u0056ersion\":1,", 1),
        text.replacen('{', "{\"validForNs\":\"6999\",", 1),
        text.replacen('{', "{\"valid_for_ns\":\"6999\",", 1),
        text.replacen('{', "{\"report\":null,", 1),
        text.replacen('{', "{\"rep\\u006frt\":null,", 1),
        text.replace("\"report\":{", "\"report\":{\"live\":true,"),
        text.replace("\"report\":{", "\"report\":{\"l\\u0069ve\":true,"),
        text.replace("\"observedAtUnixUs\"", "\"observed_at_unix_us\""),
        text.replace("\"live\":true", "\"live\":null"),
        "{\"schemaVersion\":1,\"report\":null,\"validForNs\":\"6999\"}\n".into(),
        "{\"schemaVersion\":1,\"report\":[],\"validForNs\":\"6999\"}\n".into(),
        text.replacen('{', "{\"foreign\":\"SAMPLE_CANARY\",", 1),
        text.replace("\"ready\":true", "\"ready\":false"),
        text.replace(
            "\"generation\":\"9007199254740993\"",
            "\"generation\":\"9007199254740994\"",
        ),
        format!("{text}{text}"),
        format!(" {text}"),
        text.replace('\n', "\r\n"),
        text.trim_end().to_owned(),
        "x".repeat(16386),
        "[1,{},\"6999\"]\n".into(),
    ];
    failures.push(String::from_utf8(fixture::stdout(&fixture::report(&launch))).unwrap());
    let report_json = serde_json::to_string(&fixture::report(&launch)).unwrap();
    for key in ["report", r"rep\u006frt"] {
        failures.push(text.replacen('{', &format!("{{\"{key}\":{report_json},"), 1));
    }
    for input in failures {
        let error = decode_health_sample_stdout(input.as_bytes(), &launch).unwrap_err();
        assert_eq!(error.to_string(), "readiness report rejected");
        assert!(!format!("{error:?}").contains("SAMPLE_CANARY"));
    }
}

#[test]
#[ignore = "explicit fixed TypeScript process parity; requires APEX_HEALTH_SAMPLE_FIXTURE_PATH"]
fn consumes_fixed_typescript_process_sample() {
    #[derive(serde::Deserialize)]
    struct Fixture {
        launch: proto::RuntimeLaunchContext,
        original_stdout: String,
        stdout: String,
    }
    let path = std::env::var("APEX_HEALTH_SAMPLE_FIXTURE_PATH").expect("explicit sample fixture");
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let expected: proto::ReadinessReport = serde_json::from_str(&fixture.original_stdout).unwrap();
    let sample = decode_health_sample_stdout(fixture.stdout.as_bytes(), &fixture.launch).unwrap();
    assert_eq!(sample.report(), &expected);
    assert_eq!(sample.valid_for_ns(), 6999);
    assert_eq!(sample.report().observed_at_unix_us, u64::MAX);
    assert_eq!(sample.report().stages[6].duration_ns, Some(u64::MAX));
    assert_eq!(sample.report().stages[1].clock_uncertainty_us, Some(0));
    assert_eq!(
        sample.report().stages[2].clock_uncertainty_us,
        Some(u64::MAX)
    );
}
