import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import process from "node:process";
import test from "node:test";

import { createClock, durationUs, type Clock, type WallClockSample } from "./clock.js";

function wallSample(unixUs: bigint): WallClockSample {
  return { unixUs, resolutionNs: 1_000n, uncertaintyUs: 1n };
}

function monotonicSamples(...values: bigint[]): () => bigint {
  const samples = values.values();
  return () => {
    const sample = samples.next();
    assert.equal(sample.done, false, "unexpected monotonic clock read");
    return sample.value!;
  };
}

test("preserves 1, 7 and 999 microsecond elapsed durations", () => {
  assert.equal(durationUs(1_000_000n, 1_001_000n), 1n);
  assert.equal(durationUs(1_000_000n, 1_007_000n), 7n);
  assert.equal(durationUs(1_000_000n, 1_999_000n), 999n);
});

test("subtracts before truncating sub-microsecond remainders", () => {
  assert.equal(durationUs(0n, 0n), 0n);
  assert.equal(durationUs(999n, 1_000n), 0n);
  assert.equal(durationUs(999n, 1_998n), 0n);
  assert.equal(durationUs(999n, 2_000n), 1n);
});

test("preserves samples and microsecond durations above Number's safe integer range", () => {
  assert.equal(durationUs(9_007_199_254_740_993n, 9_007_199_254_747_993n), 7n);
  assert.equal(durationUs(999n, 9_007_199_254_740_994_999n), 9_007_199_254_740_994n);
});

for (const [startNs, endNs] of [[-1n, 0n], [0n, -1n], [-2n, -1n], [1_001n, 1_000n]]) {
  test(`rejects invalid monotonic interval ${startNs}..${endNs}`, () => {
    assert.throws(() => durationUs(startNs, endNs), RangeError);
  });
}

test("maps 1, 7 and 999 microseconds onto an injected non-millisecond anchor", () => {
  const clock: Clock = createClock({
    monotonicNowNs: monotonicSamples(
      1_000_000n, 1_000_000n, 1_001_000n, 1_007_000n, 1_999_000n, 1_999_999n,
    ),
    wallNow: () => wallSample(1_700_000_000_000_125n),
    source: "injected microsecond wall clock",
  });

  assert.deepEqual(clock.now(), {
    monotonicNs: 1_001_000n,
    unixUs: 1_700_000_000_000_126n,
    resolutionNs: 1_000n,
    uncertaintyUs: 1n,
    source: "injected microsecond wall clock",
  });
  assert.equal(clock.now().unixUs, 1_700_000_000_000_132n);
  assert.equal(clock.now().unixUs, 1_700_000_000_001_124n);
  const subMicrosecond = clock.now();
  assert.equal(subMicrosecond.monotonicNs, 1_999_999n);
  assert.equal(subMicrosecond.unixUs, 1_700_000_000_001_124n);
});

test("uses the measured anchor midpoint and rounds sampling uncertainty up", () => {
  let monotonicNs = 10_000n;
  const clock = createClock({
    monotonicNowNs: () => monotonicNs,
    wallNow: () => {
      monotonicNs = 15_001n;
      return { unixUs: 1_700_000_000_000_123n, resolutionNs: 2_500n, uncertaintyUs: 17n };
    },
    source: "injected bracketed wall clock",
  });

  const snapshot = clock.now();
  assert.equal(snapshot.unixUs, 1_700_000_000_000_125n);
  assert.equal(snapshot.resolutionNs, 2_500n);
  assert.equal(snapshot.uncertaintyUs, 20n);
});

test("keeps the epoch mapping monotonic across backwards and forwards wall jumps", () => {
  let unixUs = 1_700_000_000_000_000n;
  const clock = createClock({
    monotonicNowNs: monotonicSamples(0n, 0n, 0n, 1_000n, 7_000n, 999_000n),
    wallNow: () => wallSample(unixUs),
    source: "injected jumping wall clock",
  });

  assert.equal(clock.now().unixUs, 1_700_000_000_000_000n);
  unixUs -= 60_000_000n;
  assert.equal(clock.now().unixUs, 1_700_000_000_000_001n);
  unixUs += 120_000_000n;
  assert.equal(clock.now().unixUs, 1_700_000_000_000_007n);
  assert.equal(clock.now().unixUs, 1_700_000_000_000_999n);
});

test("maps large monotonic and epoch values with exact integer arithmetic", () => {
  const clock = createClock({
    monotonicNowNs: monotonicSamples(
      9_007_199_254_740_993n, 9_007_199_254_740_993n,
      9_007_199_254_741_993n, 9_007_199_254_747_993n, 9_007_199_255_739_993n,
    ),
    wallNow: () => wallSample(9_007_199_254_740_993_123n),
    source: "injected large epoch",
  });

  assert.equal(clock.now().unixUs, 9_007_199_254_740_993_124n);
  assert.equal(clock.now().unixUs, 9_007_199_254_740_993_130n);
  assert.equal(clock.now().unixUs, 9_007_199_254_740_994_122n);
});

test("rejects a regressing sample even when it is still after the anchor", () => {
  const clock = createClock({
    monotonicNowNs: monotonicSamples(0n, 0n, 7_000n, 6_999n, 7_000n),
    wallNow: () => wallSample(1_700_000_000_000_000n),
    source: "injected monotonic regression",
  });

  assert.equal(clock.now().unixUs, 1_700_000_000_000_007n);
  assert.throws(() => clock.now(), RangeError);
  assert.equal(clock.now().unixUs, 1_700_000_000_000_007n);
});

test("rejects a first sample before anchor acquisition finished", () => {
  const clock = createClock({
    monotonicNowNs: monotonicSamples(0n, 2_000n, 1_999n),
    wallNow: () => wallSample(1_700_000_000_000_000n),
    source: "injected first-sample regression",
  });
  assert.throws(() => clock.now(), RangeError);
});

for (const [beforeNs, afterNs] of [[-1n, 1n], [0n, -1n], [2n, 1n]]) {
  test(`rejects invalid anchor samples ${beforeNs}..${afterNs}`, () => {
    assert.throws(() => createClock({
      monotonicNowNs: monotonicSamples(beforeNs, afterNs),
      wallNow: () => wallSample(1_700_000_000_000_000n),
      source: "injected invalid anchor",
    }), RangeError);
  });
}

test("production preserves a non-millisecond wall anchor without adding epoch doubles", (t) => {
  let monotonicNs = 1_000_000n;
  let wallMs = 1_700_000_000_000;
  t.mock.method(process.hrtime, "bigint", () => monotonicNs);
  t.mock.method(Date, "now", () => wallMs);
  t.mock.getter(performance, "timeOrigin", () => 1_700_000_000_000.125);
  t.mock.method(performance, "now", () => 0.9999);
  try {
    const clock: Clock = createClock();
    monotonicNs += 7_000n;
    wallMs -= 60_000;
    const snapshot = clock.now();
    assert.equal(snapshot.monotonicNs, 1_007_000n);
    // 125 us + 999.9 us + 7 us, truncated after combining the wall components.
    assert.equal(snapshot.unixUs, 1_700_000_000_001_131n);
    assert.equal(snapshot.resolutionNs, 1_000n);
    assert.equal(snapshot.uncertaintyUs, 3n);
    assert.match(snapshot.source, /process\.hrtime\.bigint/);
    assert.match(snapshot.source, /performance\.timeOrigin/);
    assert.match(snapshot.source, /performance\.now/);
  } finally {
    t.mock.restoreAll();
  }
});

test("production combines fractional carry before truncating to microseconds", (t) => {
  t.mock.method(process.hrtime, "bigint", () => 0n);
  // Exact binary fractions: 125.9765625 us + 0.9765625 us = 126.953125 us.
  t.mock.getter(performance, "timeOrigin", () => 1_700_000_000_000.1259765625);
  t.mock.method(performance, "now", () => 0.0009765625);
  assert.equal(createClock().now().unixUs, 1_700_000_000_000_126n);
});

test("production converts a large epoch before combining the elapsed fraction", (t) => {
  t.mock.method(process.hrtime, "bigint", () => 0n);
  t.mock.getter(performance, "timeOrigin", () => Number.MAX_SAFE_INTEGER);
  t.mock.method(performance, "now", () => 0.125);
  assert.equal(createClock().now().unixUs, 9_007_199_254_740_991_125n);
});

for (const component of ["origin", "elapsed"]) {
  test(`production discloses coarse double quantization in ${component}`, (t) => {
    t.mock.method(process.hrtime, "bigint", () => 0n);
    t.mock.getter(performance, "timeOrigin", () => component === "origin" ? 2 ** 44 : 0);
    t.mock.method(performance, "now", () => component === "elapsed" ? 2 ** 44 : 0);
    const snapshot = createClock().now();
    // At 2^44 milliseconds, double spacing is 3,906.25 ns (ceil -> 3,907).
    assert.equal(snapshot.resolutionNs, 3_907n);
    assert.equal(snapshot.uncertaintyUs, 10n);
    assert.equal(snapshot.unixUs, 17_592_186_044_416_000n);
  });
}

test("production brackets the wall sample and keeps its mapping after wall jumps", (t) => {
  let monotonicNs = 10_000n;
  let originMs = 1_700_000_000_000.125;
  let elapsedMs = 0.5;
  t.mock.method(process.hrtime, "bigint", () => monotonicNs);
  t.mock.getter(performance, "timeOrigin", () => originMs);
  t.mock.method(performance, "now", () => {
    monotonicNs = 15_001n;
    return elapsedMs;
  });
  const clock = createClock();
  const snapshot = clock.now();
  assert.equal(snapshot.monotonicNs, 15_001n);
  assert.equal(snapshot.unixUs, 1_700_000_000_000_627n);
  assert.equal(snapshot.uncertaintyUs, 6n);
  originMs -= 60_000;
  elapsedMs += 120_000;
  monotonicNs += 7_000n;
  assert.equal(clock.now().unixUs, 1_700_000_000_000_634n);
});

test("retains a zero-uncertainty exact injected epoch and its declared resolution", () => {
  const clock = createClock({
    monotonicNowNs: monotonicSamples(0n, 0n, 0n),
    wallNow: () => ({ unixUs: 0n, resolutionNs: 1n, uncertaintyUs: 0n }),
    source: "exact injected source",
  });
  assert.deepEqual(clock.now(), {
    monotonicNs: 0n, unixUs: 0n, resolutionNs: 1n, uncertaintyUs: 0n,
    source: "exact injected source",
  });
});

for (const wallMs of [-1, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1]) {
  test(`rejects invalid or inexact performance milliseconds: ${wallMs}`, (t) => {
    t.mock.getter(performance, "timeOrigin", () => wallMs);
    assert.throws(() => createClock(), RangeError);
    t.mock.getter(performance, "timeOrigin", () => 1_700_000_000_000);
    t.mock.method(performance, "now", () => wallMs);
    assert.throws(() => createClock(), RangeError);
  });
}

const invalidWallSamples: [string, unknown][] = [
  ["missing sample", undefined],
  ["null sample", null],
  ["negative epoch", { ...wallSample(0n), unixUs: -1n }],
  ["number epoch", { ...wallSample(0n), unixUs: 0 }],
  ["string epoch", { ...wallSample(0n), unixUs: "0" }],
  ["missing epoch", { ...wallSample(0n), unixUs: undefined }],
  ["zero resolution", { ...wallSample(0n), resolutionNs: 0n }],
  ["negative resolution", { ...wallSample(0n), resolutionNs: -1n }],
  ["number resolution", { ...wallSample(0n), resolutionNs: 1_000 }],
  ["missing resolution", { ...wallSample(0n), resolutionNs: undefined }],
  ["negative uncertainty", { ...wallSample(0n), uncertaintyUs: -1n }],
  ["number uncertainty", { ...wallSample(0n), uncertaintyUs: 1 }],
  ["missing uncertainty", { ...wallSample(0n), uncertaintyUs: undefined }],
];

for (const [description, sample] of invalidWallSamples) {
  test(`rejects invalid wall source: ${description}`, () => {
    assert.throws(() => createClock({
      monotonicNowNs: monotonicSamples(0n, 0n),
      wallNow: () => sample as WallClockSample,
      source: "invalid wall source",
    }), RangeError);
  });
}

for (const source of ["", "   ", undefined, 42]) {
  test(`rejects a missing or invalid source label: ${String(source)}`, () => {
    assert.throws(() => createClock({
      monotonicNowNs: monotonicSamples(0n, 0n),
      wallNow: () => wallSample(0n),
      source: source as string,
    }), RangeError);
  });
}

test("rejects non-bigint monotonic source samples", () => {
  assert.throws(() => createClock({
    monotonicNowNs: () => 0 as unknown as bigint,
    wallNow: () => wallSample(0n),
    source: "invalid monotonic source",
  }), RangeError);
  assert.throws(() => durationUs(0 as unknown as bigint, 1n), RangeError);
});
