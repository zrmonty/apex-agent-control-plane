import assert from "node:assert/strict";
import test from "node:test";
import { ReadinessReason, ReadinessReportSchema, encodeJson } from "@apex/contracts";
import { ReadinessMonitor } from "../readiness.js";
import { controlled, setup, flush } from "./test-support.js";

test("scheduler failure is static terminal refusal, never an unbounded or successful sweep", async () => {
  const f = setup();
  const monitor = new ReadinessMonitor({ ...f.options, scheduler: { after() { throw new Error("SENSITIVE-timer"); } } });
  const report = await monitor.checkStartup();
  assert.equal(report.ready, false);
  assert.equal(report.live, false);
  assert.equal(f.stats.fatal, 1);
  assert.equal(f.stats.starts, 0);
  await monitor.close();
});

test("cancel errors do not echo or release permits, and a late cleanup observation cannot avoid fatal", async () => {
  const f = controlled();
  const owners = f.options.owners.map(owner => ({ ...owner, start: (binding: Parameters<typeof owner.start>[0]) => {
    const handle = owner.start(binding);
    return { completion: handle.completion, cancel: () => { handle.cancel(); throw new Error("SENSITIVE-cancel"); } };
  } }));
  const monitor = new ReadinessMonitor({ ...f.options, owners }), running = monitor.checkStartup();
  f.time.advance(2000000000n);
  const report = await running;
  assert.equal(f.stats.cancels, 4);
  assert.equal(f.active, 4);
  assert.ok(!JSON.stringify(encodeJson(ReadinessReportSchema, report as never)).includes("SENSITIVE"));
  f.time.advance(5000000000n, false); // No timer polling: the completion itself must enforce the bound.
  f.release(1); await flush();
  assert.equal(f.stats.fatal, 1);
  assert.equal(monitor.snapshot().ready, false);
  for (const id of [...f.pending.keys()]) f.release(id);
  await flush(); await monitor.close();
  assert.equal(f.stats.cancels, 4);
  assert.equal(f.time.scheduled, 0);
});

test("component limits can only shorten the selected deadline and cleanup ceilings", () => {
  const f = setup();
  for (const limits of [{ deadlineMs: 2001 }, { cleanupMs: 5001 }, { deadlineMs: 0 }, { cleanupMs: -1 },
    { deadlineMs: 1.5 }, { cleanupMs: Infinity }]) {
    assert.throws(() => new ReadinessMonitor({ ...f.options, limits }), /readiness configuration rejected safely/);
  }
});

test("unknown clock uncertainty stays absent and a subsequent backwards clock invalidates cached evidence", async () => {
  const f = setup();
  let backwards = false;
  const monitor = new ReadinessMonitor({ ...f.options, clock: { now: () => {
    const { uncertaintyUs: _, ...sample } = f.time.clock.now();
    return { ...sample, monotonicNs: sample.monotonicNs - (backwards ? 1n : 0n) };
  } } });
  const first = await monitor.checkStartup();
  assert.equal(first.ready, true);
  assert.ok(first.stages.every(stage => stage.clockUncertaintyUs === undefined));
  backwards = true;
  const report = monitor.snapshot();
  assert.equal(report.ready, false);
  assert.ok(report.checks.every(check => check.reason === ReadinessReason.INVALID));
  assert.equal(report.observedAtUnixUs, first.observedAtUnixUs);
  await monitor.close();
});

test("a clock failure with active I/O still cancels and enforces bounded cleanup without fake samples", async () => {
  const f = controlled();
  let broken = false;
  const monitor = new ReadinessMonitor({ ...f.options, clock: { now() {
    if (broken) throw new Error("SENSITIVE-clock");
    return f.time.clock.now();
  } } });
  const running = monitor.checkStartup(); broken = true;
  f.release(1); await flush();
  assert.equal((await running).ready, false);
  assert.equal(f.stats.cancels, 3);
  f.time.advance(5000000000n);
  assert.equal(f.stats.fatal, 1);
  for (const id of [...f.pending.keys()]) f.release(id);
  await flush(); await monitor.close();
});
