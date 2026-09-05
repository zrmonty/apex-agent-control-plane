import assert from "node:assert/strict";
import test from "node:test";
import { ReadinessReportSchema, ReadinessReason, encodeJson } from "@apex/contracts";
import { ReadinessMonitor } from "../readiness.js";
import { controlled, setup, flush, pass } from "./test-support.js";

test("per-check 1 7 and 999us stages subtract bigint nanoseconds before division with original clock metadata", async () => {
  const f = controlled(); f.time.advance(699n);
  const monitor = new ReadinessMonitor(f.options), running = monitor.checkStartup();
  f.time.advance(1001n); f.release(1); await flush();
  f.time.advance(6000n); f.release(2); await flush();
  f.time.advance(992000n); f.release(3); await flush();
  while (f.pending.size) { for (const id of [...f.pending.keys()]) f.release(id); await flush(); }
  const report = await running;
  assert.equal(report.stages.length, 9);
  assert.deepEqual(report.stages.slice(0, 3).map(stage => stage.durationUs), [1n, 7n, 999n]);
  assert.deepEqual(report.stages.slice(0, 3).map(stage => stage.durationNs), [1001n, 7001n, 999001n]);
  assert.deepEqual(report.stages.slice(0, 3).map(stage => stage.name), ["readiness.config", "readiness.launch", "readiness.material"]);
  assert.equal(report.stages[0].startedAtUnixUs, 9007199254740993n);
  assert.equal(report.stages[0].clockResolutionNs, 1000n);
  assert.equal(report.stages[0].clockUncertaintyUs, 7n);
  assert.equal(report.stages[0].clockSource, "component-clock");
  assert.equal(report.stages[0].processInstanceId, f.launch.processInstanceId);
  const json = JSON.stringify(encodeJson(ReadinessReportSchema, report as never));
  assert.ok(json.includes('"startedAtUnixUs":"9007199254740993"'));
  assert.ok(Buffer.byteLength(json) <= 8192);
  await monitor.close();
});

test("snapshot expires at exact ten-second local age despite wall jumps and never restamps evidence", async () => {
  const f = setup(), monitor = new ReadinessMonitor(f.options);
  const first = await monitor.checkStartup();
  f.time.wall += 1000000000000000n;
  f.time.advance(9999999999n);
  assert.equal(monitor.snapshot().ready, true);
  f.time.wall = 0n; f.time.advance(1n);
  const stale = monitor.snapshot();
  assert.equal(stale.ready, false);
  assert.ok(stale.checks.every(check => check.reason === ReadinessReason.STALE));
  assert.equal(stale.observedAtUnixUs, first.observedAtUnixUs);
  assert.equal(f.stats.starts, 9);
  await monitor.close();
});

test("earliest owner lease shortens the cache and must still be future at publication", async () => {
  const f = setup(), expiry = f.time.ns + 1000000n;
  const owners = f.owners.map(owner => ({ ...owner, start: () => ({ completion: Promise.resolve(pass(owner.id, expiry)), cancel: () => {} }) }));
  const monitor = new ReadinessMonitor({ ...f.options, owners });
  const first = await monitor.checkStartup();
  f.time.advance(999999n); assert.equal(monitor.snapshot().ready, true);
  f.time.advance(1n); assert.equal(monitor.snapshot().ready, false);
  assert.equal(monitor.snapshot().observedAtUnixUs, first.observedAtUnixUs);
  await monitor.close();

  const g = controlled(), other = new ReadinessMonitor(g.options), running = other.checkStartup();
  g.release(1, pass(1, g.time.ns + 500000000n)); await flush();
  g.time.advance(500000000n);
  while (g.pending.size) { for (const id of [...g.pending.keys()]) g.release(id); await flush(); }
  assert.equal((await running).ready, false, "an earlier PASS expired before final publication");
  await other.close();
});

test("a completion first observed at the deadline cannot win because its timer has not polled", async () => {
  const f = controlled(), monitor = new ReadinessMonitor(f.options), running = monitor.checkStartup();
  f.time.advance(2000000000n, false);
  f.release(1); await flush();
  assert.equal(f.stats.cancels, 3);
  assert.equal((await running).ready, false);
  assert.equal(f.stats.starts, 4);
  for (const id of [...f.pending.keys()]) f.release(id);
  await flush(); await monitor.close();
});

test("clock exceptions invalid ranges and active metadata are static non-ready failures without invented fresh samples", async () => {
  const f = setup();
  let canary = 0;
  const base = f.time.clock.now();
  const active = Object.defineProperty({ ...base }, "unixUs", { get() { canary++; return 123n; } });
  for (const sample of [null, { ...base, unixUs: 0n }, { ...base, unixUs: 1n << 64n },
    { ...base, monotonicNs: -1n }, { ...base, resolutionNs: 0n }, { ...base, uncertaintyUs: -1n },
    { ...base, source: "" }, { ...base, source: "SENSITIVE".repeat(50) }, active]) {
    const monitor = new ReadinessMonitor({ ...f.options, clock: { now: () => sample as never } });
    const report = await monitor.checkStartup();
    assert.equal(report.ready, false);
    assert.ok(report.checks.every(check => check.reason === ReadinessReason.INVALID));
    assert.equal(report.observedAtUnixUs, 0n, "no observation has completed");
    await monitor.close();
  }
  const monitor = new ReadinessMonitor({ ...f.options, clock: { now() { throw new Error("SENSITIVE-clock"); } } });
  assert.equal((await monitor.checkStartup()).ready, false);
  await monitor.close();
  assert.equal(canary, 0);
  assert.equal(f.stats.starts, 0);
});

test("snapshot samples freshness after the trusted current-binding callback returns late", async () => {
  const f = setup();
  let late = false;
  const monitor = new ReadinessMonitor({ ...f.options, isCurrent: () => {
    if (late) { late = false; f.time.advance(10000000000n, false); }
    return true;
  } });
  const first = await monitor.checkStartup();
  late = true;
  const report = monitor.snapshot();
  assert.equal(report.ready, false);
  assert.equal(report.observedAtUnixUs, first.observedAtUnixUs);
  assert.equal(f.stats.starts, 9);
  await monitor.close();
});

test("a slow final owner cannot extend an earlier check beyond its ten-second local evidence age", async () => {
  const f = controlled(), monitor = new ReadinessMonitor(f.options), running = monitor.checkStartup();
  f.release(1); await flush();
  f.time.advance(1000000000n);
  while (f.pending.size) { for (const id of [...f.pending.keys()]) f.release(id); await flush(); }
  const first = await running;
  assert.equal(first.ready, true);
  f.time.advance(9000000000n);
  const report = monitor.snapshot();
  assert.equal(report.ready, false);
  assert.equal(report.observedAtUnixUs, first.observedAtUnixUs);
  await monitor.close();
});
