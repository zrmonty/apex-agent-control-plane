use super::super::*;
use super::support::*;
use std::{
    future::{Future, pending, poll_fn},
    sync::{atomic::Ordering, mpsc},
    task::Poll,
    time::Duration,
};

#[test]
fn cancelling_before_first_poll_marks_partial_without_inventing_elapsed_time() {
    let harness = Harness::new();
    let trace = harness.telemetry.begin(Action::Callback);
    let future = trace.stage(Stage::Provider, async { Ok::<_, ()>(()) });
    drop(future);
    let record = json(trace.finish(Status::Timeout));
    assert_eq!(record["partial"], true);
    assert_eq!(record["stages"][0]["outcome"], "cancelled");
    assert!(record["stages"][0]["timing"].is_null());
    assert_eq!(record["status"], "timeout");
    assert!(harness.close().complete);
}

#[test]
fn cancelling_a_polled_stage_records_only_the_observed_abort_interval() {
    let harness = Harness::new();
    let trace = harness.telemetry.begin(Action::Callback);
    let mut future = Box::pin(trace.stage(Stage::Provider, pending::<Result<(), ()>>()));
    runtime().block_on(poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    }));
    harness.probe.advance(7_000);
    drop(future);
    let record = json(trace.finish(Status::Timeout));
    assert_eq!(record["partial"], true);
    assert_eq!(record["stages"][0]["outcome"], "cancelled");
    assert_eq!(record["stages"][0]["timing"]["durationUs"], "7");
    assert!(harness.close().complete);
}

#[test]
fn owning_guard_drop_emits_one_partial_record_even_when_extension_handles_survive() {
    let harness = Harness::new();
    let capture = harness.capture.clone();
    let trace = harness.telemetry.begin(Action::Logout);
    let context = trace.context();
    context
        .stage_sync(Stage::LocalRevoke, || Ok::<_, ()>(()))
        .unwrap();
    let pending = context.stage(Stage::Provider, pending::<Result<(), ()>>());
    drop(trace);
    // Late future/extension destruction must not emit a second final record.
    drop(pending);
    let result = context.stage_sync(Stage::SessionTouch, || Ok::<_, ()>(23));
    assert_eq!(result, Ok(23));
    drop(context);
    assert!(harness.close().complete);
    let records = capture.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["status"], "cancelled");
    assert_eq!(records[0]["completion"], "aborted");
    assert_eq!(records[0]["partial"], true);
}

#[test]
fn explicit_finish_then_export_does_not_also_emit_an_abort_record() {
    let harness = Harness::new();
    let capture = harness.capture.clone();
    let trace = harness.telemetry.begin(Action::Session);
    let context = trace.context();
    context
        .stage_sync(Stage::SessionTouch, || Ok::<_, ()>(()))
        .unwrap();
    let record = trace.finish(Status::Ok);
    assert_eq!(harness.telemetry.export(&record), ExportDisposition::Queued);
    drop(context);
    assert!(harness.close().complete);
    let records = capture.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["completion"], "handler_response_ready");
    assert_eq!(records[0]["partial"], false);
}

#[test]
fn stage_and_record_limits_are_hard_bounds_with_visible_loss() {
    let harness = Harness::new();
    let trace = harness.telemetry.begin(Action::Management);
    for _ in 0..35 {
        assert_eq!(
            trace.stage_sync(Stage::Management, || Ok::<_, ()>(5)),
            Ok(5)
        );
    }
    let record = trace.finish(Status::Ok);
    let bytes = serde_json::to_vec(&record).expect("bounded redacted record");
    assert!(bytes.len() <= MAX_RECORD_BYTES);
    let record = json(record);
    assert_eq!(record["stages"].as_array().expect("stage array").len(), 32);
    assert_eq!(record["partial"], true);
    assert_eq!(record["droppedStages"], "3");
    assert_eq!(harness.telemetry.counters().dropped_stages, 3);
    assert!(harness.close().complete);
}

#[test]
fn clock_failure_is_visible_but_never_changes_operation_result_or_authority() {
    let harness = Harness::new();
    let trace = harness.telemetry.begin(Action::Management);
    harness.probe.fail.store(true, Ordering::SeqCst);
    let sync = trace.stage_sync(Stage::Auth, || Err::<(), _>(41));
    let asynchronous =
        runtime().block_on(trace.stage(Stage::Management, async { Ok::<_, ()>(42) }));
    assert_eq!(sync, Err(41));
    assert_eq!(asynchronous, Ok(42));
    let record = json(trace.finish(Status::Forbidden));
    assert_eq!(record["status"], "forbidden");
    assert_eq!(record["partial"], true);
    let stages = record["stages"].as_array().expect("stage array");
    assert_eq!(stages.len(), 2);
    assert!(stages.iter().all(|stage| stage["timing"].is_null()));
    assert!(harness.telemetry.counters().clock_errors > 0);
    assert_ne!(record["clockFailures"], "0");
    assert!(harness.close().complete);
}

#[test]
fn request_state_is_not_locked_while_polling_or_calling_a_sync_operation() {
    let (done, result) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let harness = Harness::new();
        let trace = harness.telemetry.begin(Action::Session);
        let context = trace.context();
        runtime()
            .block_on(trace.stage(Stage::Ingress, async {
                context.stage_sync(Stage::SessionLoad, || Ok::<_, ()>(()))
            }))
            .unwrap();
        let record = json(trace.finish(Status::Ok));
        let count = record["stages"].as_array().expect("stage array").len();
        let report = harness.close();
        done.send((count, report.complete)).unwrap();
    });
    let (count, complete) = result
        .recv_timeout(Duration::from_secs(2))
        .expect("nested operation must not block on a request-state lock");
    worker.join().expect("observation test worker");
    assert_eq!(count, 2);
    assert!(complete);
}

#[test]
fn all_approved_bff_stages_have_fixed_names_and_distinct_spans() {
    let harness = Harness::new();
    let trace = harness.telemetry.begin(Action::Callback);
    for stage in [
        Stage::Ingress,
        Stage::LoginAdmission,
        Stage::SessionLoad,
        Stage::SessionTouch,
        Stage::SessionCommit,
        Stage::RefreshClaim,
        Stage::RefreshCommit,
        Stage::LocalRevoke,
        Stage::Provider,
        Stage::Auth,
        Stage::Csrf,
        Stage::Crypto,
        Stage::Decode,
        Stage::Management,
        Stage::Serialization,
    ] {
        trace.stage_sync(stage, || Ok::<_, ()>(())).unwrap();
    }
    let record = json(trace.finish(Status::Ok));
    let stages = record["stages"].as_array().expect("stage array");
    assert_eq!(stages.len(), 15);
    let mut ids = std::collections::HashSet::new();
    for stage in stages {
        let name = stage["timing"]["name"].as_str().expect("fixed stage name");
        assert!(name.starts_with("bff."));
        assert!(ids.insert(stage["timing"]["spanId"].as_str().expect("span id")));
    }
    assert!(harness.close().complete);
}
