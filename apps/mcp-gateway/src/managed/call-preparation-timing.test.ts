import assert from "node:assert/strict";
import { test } from "node:test";
import { CompiledCallPreparer } from "./call-preparation.js";
import { fixture } from "./call-preparation/fixture.js";
import { createClock, type ClockSnapshot } from "../telemetry/clock.js";
const refused = /^Error: managed call preparation refused safely$/;
const input = { portfolioId: "p" };

for (const micros of [1n, 7n, 999n]) test(`original ${micros}us snapshot remains exact above 2^53`, () => {
  const f = fixture(), start = { ...f.original, monotonicNs: f.original.monotonicNs + micros * 1000n,
    unixUs: f.original.unixUs + micros };
  const end = { ...start, monotonicNs: start.monotonicNs + 7000n, unixUs: start.unixUs + 7n };
  f.sample(end);
  const result = new CompiledCallPreparer(f.options).prepare(f.identity, "portfolio.read", input, start, f.deadline);
  assert.deepEqual(result.originalSnapshot, start); assert.notEqual(result.originalSnapshot, start);
  assert.equal(result.startedAtMonotonicNs, start.monotonicNs);
  assert.equal(result.trace.startedAtUnixUs, start.unixUs);
  assert.equal(result.trace.clockResolutionNs, 1n); assert.equal(result.trace.clockUncertaintyUs, 7n);
  assert.equal(result.trace.clockSource, start.source);
  assert.equal(result.deadlineMonotonicNs, f.deadline);
  assert(!("durationUs" in result.trace)); assert(!("endedAtUnixUs" in result.trace));
});
test("same stable clock accepts submicrosecond anchor quantization without numeric conversion", () => {
  const f = fixture(); let ns = 0n;
  const clock = createClock({ monotonicNowNs: () => ns, source: "fixture phase",
    wallNow: () => ({ unixUs: 9007199254740993n, resolutionNs: 1n, uncertaintyUs: 0n }) });
  const preparer = new CompiledCallPreparer({ ...f.options, clock });
  ns = 999n; const start = clock.now(); ns = 1001n;
  const result = preparer.prepare(f.identity, "portfolio.read", input, start, 2000n);
  assert.equal(result.originalSnapshot.unixUs, 9007199254740993n);
  assert.equal(result.startedAtMonotonicNs, 999n);
});
test("one nanosecond before deadline allowed, exact deadline expired, no original budget reset", () => {
  const f = fixture(), deadline = f.original.monotonicNs + 7000n;
  f.sample({ ...f.original, monotonicNs: deadline - 1n, unixUs: f.original.unixUs + 6n });
  const p = new CompiledCallPreparer(f.options);
  assert.equal(p.prepare(f.identity, "portfolio.read", input, f.original, deadline).deadlineMonotonicNs, deadline);
  f.sample({ ...f.original, monotonicNs: deadline, unixUs: f.original.unixUs + 7n });
  assert.throws(() => p.prepare(f.identity, "portfolio.read", input, f.original, deadline), refused);
});
for (const delta of [0n, -1n, 120000000001n]) test(`invalid original budget ${delta}ns refuses`, () => {
  const f = fixture(), p = new CompiledCallPreparer(f.options);
  assert.throws(() => p.prepare(f.identity, "portfolio.read", input, f.original, f.original.monotonicNs + delta), refused);
});
for (const change of [{ monotonicNs: -1n }, { monotonicNs: 1 }, { unixUs: 1 }, { unixUs: -1n },
  { resolutionNs: 0n }, { uncertaintyUs: -1n }, { uncertaintyUs: 1 }, { source: "" }, { source: "clock\n" },
  { source: "x".repeat(129) }, { unknown: 1 }]) test(`invalid original clock ${Object.keys(change)[0]} ${String(Object.values(change)[0]).slice(0, 12)}`, () => {
  const f = fixture(), p = new CompiledCallPreparer(f.options);
  assert.throws(() => p.prepare(f.identity, "portfolio.read", input, { ...f.original, ...change } as ClockSnapshot, f.deadline), refused);
});
test("backward monotonic clock and unstable source/precision/wall mapping refuse", () => {
  for (const change of [{ monotonicNs: 9007199254740992n }, { source: "other" }, { resolutionNs: 1000n },
    { uncertaintyUs: 8n }, { unixUs: 9007199254740994n }, { unixUs: 9007199254740992n }]) {
    const f = fixture(), p = new CompiledCallPreparer(f.options); f.sample({ ...f.original, ...change });
    assert.throws(() => p.prepare(f.identity, "portfolio.read", input, f.original, f.deadline), refused);
  }
});
test("late post-serialization clock sample refuses; callbacks cannot get a fresh budget", () => {
  const f = fixture(); let samples = 0;
  const p = new CompiledCallPreparer({ ...f.options, clock: { now() {
    return ++samples === 1 ? { ...f.original } : { ...f.original, monotonicNs: f.deadline, unixUs: f.original.unixUs + 120000000n };
  } } });
  assert.throws(() => p.prepare(f.identity, "portfolio.read", input, f.original, f.deadline), refused);
});
test("clock consistency extends across calls and earlier caller origins are retained", () => {
  const f = fixture(), p = new CompiledCallPreparer(f.options);
  f.sample({ ...f.original, monotonicNs: f.original.monotonicNs + 7000n, unixUs: f.original.unixUs + 7n });
  p.prepare(f.identity, "portfolio.read", input, f.original, f.deadline);
  f.sample({ ...f.original, monotonicNs: f.original.monotonicNs + 6000n, unixUs: f.original.unixUs + 6n });
  assert.throws(() => p.prepare(f.identity, "portfolio.read", input, f.original, f.deadline), refused);
});
test("absent clock uncertainty remains absent rather than fabricated zero", () => {
  const f = fixture(), start = { ...f.original }; delete start.uncertaintyUs; f.sample(start);
  const result = new CompiledCallPreparer(f.options).prepare(f.identity, "portfolio.read", input, start, f.deadline);
  assert.deepEqual(result.originalSnapshot, start); assert.equal(result.trace.clockUncertaintyUs, undefined);
});
