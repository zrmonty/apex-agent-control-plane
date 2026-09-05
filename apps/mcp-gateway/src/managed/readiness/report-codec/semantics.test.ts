import assert from "node:assert/strict";
import test from "node:test";
import { clone } from "@bufbuild/protobuf";
import { ReadinessReportSchema, ReadinessCheckStatus as Status, ReadinessReason as Reason } from "@apex/contracts";
import { completed, fixture, rejectsBoth, text } from "./test-support.js";

test("both directions require exactly nine unique known mandatory check IDs", async () => {
  const f = fixture();
  for (const kind of ["missing", "extra", "duplicate", "zero", "unknown"]) {
    const report = clone(ReadinessReportSchema, f.report);
    if (kind === "missing") report.checks.pop();
    if (kind === "extra") report.checks.push(report.checks[0]);
    if (kind === "duplicate") report.checks[1].id = report.checks[0].id;
    if (kind === "zero") report.checks[0].id = 0;
    if (kind === "unknown") report.checks[0].id = 999 as never;
    rejectsBoth(f.codec, report);
  }
  const reordered = clone(ReadinessReportSchema, f.report); reordered.checks.reverse();
  assert.deepEqual(f.codec.decode(f.codec.encode(reordered)), reordered);
  await f.monitor.close();
});

test("status and reason must form the selected PASS PENDING or FAIL pair for every owner", async () => {
  const f = fixture();
  for (let index = 0; index < 9; index++) {
    for (const [status, reason] of [[Status.PASS, Reason.UNAVAILABLE], [Status.PENDING, Reason.OK],
      [Status.FAIL, Reason.OK], [0, Reason.UNAVAILABLE], [999, Reason.UNAVAILABLE], [Status.FAIL, 0], [Status.FAIL, 999]]) {
      const report = clone(ReadinessReportSchema, f.report);
      Object.assign(report.checks[index], { status, reason }); rejectsBoth(f.codec, report);
    }
    for (const reason of [Reason.INVALID, Reason.UNAVAILABLE, Reason.TIMEOUT, Reason.CANCELLED,
      Reason.STALE, Reason.MISMATCH, Reason.SHUTTING_DOWN]) {
      const report = clone(ReadinessReportSchema, f.report);
      Object.assign(report.checks[index], { status: Status.FAIL, reason });
      assert.deepEqual(f.codec.decode(f.codec.encode(report)), report);
    }
  }
  await f.monitor.close();
});

test("ready requires live observed complete successful evidence and is never synthesized from all PASS", async () => {
  const f = await completed();
  assert.equal(f.codec.decode(f.codec.encode(f.report)).ready, true);
  for (const kind of ["not-live", "no-observation", "no-stages", "partial-stages", "failed", "pending"]) {
    const report = clone(ReadinessReportSchema, f.report);
    if (kind === "not-live") report.live = false;
    if (kind === "no-observation") report.observedAtUnixUs = 0n;
    if (kind === "no-stages") report.stages = [];
    if (kind === "partial-stages") report.stages.pop();
    if (kind === "failed" || kind === "pending") Object.assign(report.checks[0], {
      status: kind === "failed" ? Status.FAIL : Status.PENDING, reason: Reason.UNAVAILABLE });
    rejectsBoth(f.codec, report);
  }
  for (const live of [true, false]) {
    const report = clone(ReadinessReportSchema, f.report); report.ready = false; report.live = live;
    assert.equal(f.codec.decode(f.codec.encode(report)).ready, false);
    report.observedAtUnixUs = 0n; report.stages = [];
    assert.equal(f.codec.decode(f.codec.encode(report)).ready, false);
  }
  await f.monitor.close();
});

test("only fixed unique readiness stages are representable and a missing observation has no stages", async () => {
  const f = await completed();
  for (const kind of ["unknown", "duplicate", "extra", "zero-observation"]) {
    const report = clone(ReadinessReportSchema, f.report); report.ready = false;
    if (kind === "unknown") report.stages[0].name = "REPORT_CANARY";
    if (kind === "duplicate") report.stages[0].name = report.stages[1].name;
    if (kind === "extra") report.stages.push(report.stages[0]);
    if (kind === "zero-observation") report.observedAtUnixUs = 0n;
    rejectsBoth(f.codec, report);
  }
  for (let count = 0; count <= 9; count++) {
    const report = clone(ReadinessReportSchema, f.report); report.ready = false;
    report.stages = report.stages.slice(0, count).reverse();
    assert.deepEqual(f.codec.decode(text(report)), report);
  }
  await f.monitor.close();
});
