mod export;
mod lifecycle;
mod support;

use super::*;
use serde_json::Value;
use std::sync::atomic::Ordering;
use support::*;

#[test]
fn measured_stages_preserve_microseconds_nanoseconds_and_large_integer_json() {
    for (ns, us) in [(1_000, "1"), (7_000, "7"), (999_000, "999"), (700, "0")] {
        let harness = Harness::new();
        let trace = harness.telemetry.begin(Action::Session);
        let result = runtime().block_on(trace.stage(Stage::SessionLoad, async {
            harness.probe.advance(ns);
            Ok::<_, ()>(17)
        }));
        assert_eq!(result, Ok(17));
        let record = json(trace.finish(Status::Ok));
        let timing = &record["stages"][0]["timing"];
        assert_eq!(timing["name"], "bff.session_load");
        assert_eq!(timing["startedAtUnixUs"], EPOCH_US.to_string());
        // Generated Protobuf JSON may omit an implicit scalar zero. Decode it
        // through the same generated contract; never substitute a JSON number.
        if us == "0" {
            assert!(timing.get("durationUs").is_none_or(|value| value == "0"));
        } else {
            assert_eq!(timing["durationUs"], us);
        }
        let decoded: crate::proto::ProxyStageTiming =
            serde_json::from_value(timing.clone()).expect("generated timing round trip");
        assert_eq!(decoded.duration_us, us.parse::<u64>().unwrap());
        assert_eq!(timing["durationNs"], ns.to_string());
        assert_eq!(timing["clockResolutionNs"], "100");
        assert_eq!(timing["clockUncertaintyUs"], "1");
        assert_eq!(timing["clockSource"], SOURCE);
        assert_eq!(record["completion"], "handler_response_ready");
        assert_eq!(record["partial"], false);
        assert!(harness.close().complete);
    }
}

#[test]
fn cloned_telemetry_shares_process_mapping_but_request_and_w3c_ids_are_distinct() {
    let harness = Harness::new();
    let first = json(harness.telemetry.begin(Action::Login).finish(Status::Ok));
    let second = json(
        harness
            .telemetry
            .clone()
            .begin(Action::Login)
            .finish(Status::Ok),
    );
    for record in [&first, &second] {
        let request_id = record["requestId"].as_str().expect("request identifier");
        let request = uuid::Uuid::parse_str(request_id).expect("generated UUID");
        assert_eq!(request.get_version_num(), 7);
        assert_eq!(request.to_string(), request_id);
        assert_nonzero_hex(&record["otelTraceId"], 32);
        assert_nonzero_hex(&record["rootSpanId"], 16);
        assert!(record["otelTraceId"].as_str() != Some(request.simple().to_string().as_str()));
        assert!(
            !record["processInstanceId"]
                .as_str()
                .expect("process identifier")
                .is_empty()
        );
    }
    assert_ne!(first["requestId"], second["requestId"]);
    assert_ne!(first["otelTraceId"], second["otelTraceId"]);
    assert_ne!(first["rootSpanId"], second["rootSpanId"]);
    assert_eq!(first["processInstanceId"], second["processInstanceId"]);
    assert_eq!(harness.probe.wall_reads.load(Ordering::SeqCst), 1);
    assert!(harness.close().complete);
}

#[test]
fn wall_regression_cannot_reanchor_the_shared_clock_or_claim_utc_accuracy() {
    let harness = Harness::new();
    let trace = harness.telemetry.begin(Action::Session);
    trace
        .stage_sync(Stage::Auth, || {
            harness.probe.wall_us.store(0, Ordering::SeqCst);
            harness.probe.advance(7_000);
            Ok::<_, ()>(())
        })
        .unwrap();
    trace
        .stage_sync(Stage::SessionTouch, || {
            harness.probe.advance(1_000);
            Ok::<_, ()>(())
        })
        .unwrap();
    let record = json(trace.finish(Status::Ok));
    assert_eq!(record["stages"][0]["timing"]["durationUs"], "7");
    assert_eq!(
        record["stages"][1]["timing"]["startedAtUnixUs"],
        (EPOCH_US + 7).to_string()
    );
    assert_eq!(harness.probe.wall_reads.load(Ordering::SeqCst), 1);
    assert_eq!(record["stages"][0]["timing"]["clockSource"], SOURCE);
    assert!(harness.close().complete);
}

#[test]
fn unknown_source_uncertainty_is_not_fabricated_as_zero() {
    let harness = Harness::with_uncertainty(None);
    let trace = harness.telemetry.begin(Action::Session);
    trace.stage_sync(Stage::Auth, || Ok::<_, ()>(())).unwrap();
    let record = json(trace.finish(Status::Ok));
    let timing = &record["stages"][0]["timing"];
    assert!(timing.is_object(), "measured stage missing");
    assert!(timing.get("clockUncertaintyUs").is_none_or(Value::is_null));
    assert!(harness.close().complete);
}

#[test]
fn explicit_extension_contexts_keep_overlapping_requests_and_stages_isolated() {
    fn extension_type<T: Clone + Send + Sync + 'static>() {}
    extension_type::<RequestContext>();
    let harness = Harness::new();
    let first = harness.telemetry.begin(Action::Login);
    let second = harness.telemetry.begin(Action::Management);
    let first_context = first.context();
    let second_context = second.context();
    runtime().block_on(async {
        let (left, right) = tokio::join!(
            first_context.stage(Stage::LoginAdmission, async {
                tokio::task::yield_now().await;
                harness.probe.advance(1_000);
                Ok::<_, ()>(11)
            }),
            second_context.stage(Stage::Management, async {
                harness.probe.advance(7_000);
                tokio::task::yield_now().await;
                Ok::<_, ()>(22)
            }),
        );
        assert_eq!(left, Ok(11));
        assert_eq!(right, Ok(22));
    });
    for (record, expected_stage) in [
        (json(first.finish(Status::Ok)), "login_admission"),
        (json(second.finish(Status::Ok)), "management"),
    ] {
        let stages = record["stages"].as_array().expect("bounded stages");
        assert_eq!(stages.len(), 1);
        assert_eq!(stages[0]["stage"], expected_stage);
        assert_eq!(stages[0]["timing"]["otelTraceId"], record["otelTraceId"]);
        assert_eq!(stages[0]["timing"]["parentSpanId"], record["rootSpanId"]);
        assert_eq!(
            stages[0]["timing"]["processInstanceId"],
            record["processInstanceId"]
        );
        assert_nonzero_hex(&stages[0]["timing"]["spanId"], 16);
        assert_ne!(stages[0]["timing"]["spanId"], record["rootSpanId"]);
    }
    assert!(harness.close().complete);
}

#[test]
fn sync_and_async_operations_return_original_values_without_recording_sensitive_data() {
    // Intentionally no Debug/Display impl: recording must not inspect results.
    struct Canary(String);
    let harness = Harness::new();
    let trace = harness.telemetry.begin(Action::Management);
    let canary = "synthetic-credential-canary-do-not-print";
    let value = Box::new(Canary(canary.into()));
    let address = (&*value) as *const Canary;
    let success = trace.stage_sync(Stage::Crypto, || Ok::<_, ()>(value));
    assert!(
        success
            .as_ref()
            .is_ok_and(|value| std::ptr::eq(&**value, address))
    );
    assert!(success.as_ref().is_ok_and(|value| value.0 == canary));
    let error = Box::new(Canary(canary.into()));
    let address = (&*error) as *const Canary;
    let failure = runtime().block_on(trace.stage(Stage::Auth, async { Err::<(), _>(error) }));
    assert!(
        failure
            .as_ref()
            .is_err_and(|error| std::ptr::eq(&**error, address))
    );
    let record = trace.finish(Status::Forbidden);
    let bytes = serde_json::to_vec(&record).expect("redacted serialization");
    assert!(
        !bytes
            .windows(canary.len())
            .any(|window| window == canary.as_bytes())
    );
    let record = json(record);
    assert_eq!(record["stages"][0]["outcome"], "completed");
    assert_eq!(record["stages"][1]["outcome"], "error");
    assert_eq!(record["status"], "forbidden");
    assert_eq!(record["partial"], false);
    assert!(harness.close().complete);
}

fn assert_nonzero_hex(value: &Value, length: usize) {
    let value = value.as_str().expect("generated hexadecimal identifier");
    assert_eq!(value.len(), length);
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert!(value.bytes().any(|byte| byte != b'0'));
}
