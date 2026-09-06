import assert from "node:assert/strict";
import test from "node:test";
import { startOwnedStage } from "./job.js";
import { ownerFixture, tick, isStatic } from "./fixture.js";

for (const [phase, sample] of [["before parsing", 6], ["after real parsing", 7], ["after material capture", 8]] as const) {
  for (const delta of [0n, 1000n, 7000n, 999000n]) {
    test(`original deadline ${phase} +${delta}ns fails and wipes`, async () => {
      const f = ownerFixture(); let calls = 0;
      f.time.now = () => ++calls >= sample ? 5000000000n + delta : 0n;
      const h = startOwnedStage(f, f.load, f.time, f.gate); f.result.resolve(f.material); f.closed.resolve();
      await assert.rejects(h.result, isStatic); await h.closed;
      assert.equal(calls, sample); assert.equal(f.counts.disposals, 1);
    });
  }
}
test("one nanosecond inside original deadline can publish", async () => {
  const f = ownerFixture(), h = startOwnedStage(f, f.load, f.time, f.gate); await tick();
  f.time.time = 4999999999n; f.result.resolve(f.material); f.closed.resolve();
  await h.result; h.cancel(); await h.closed;
});
test("ENV/setup time is not reset at loader entry, including held result", async () => {
  const f = ownerFixture(); let calls = 0;
  f.time.now = () => { if (++calls === 2) f.time.time = 4999000000n; return f.time.time; };
  const h = startOwnedStage(f, f.load, f.time, f.gate); await tick(); assert.equal(f.counts.loads, 1);
  f.time.advance(1); await assert.rejects(h.result, isStatic); assert.equal(f.counts.cancels, 1);
  assert.throws(() => f.options().monotonicNowNs!(), isStatic);
  let closed = false; void h.closed.then(() => { closed = true; }); await tick(); assert.equal(closed, false);
  f.result.resolve(f.material); f.closed.resolve(); await h.closed; assert.equal(f.counts.disposals, 1);
});
test("expiry before dispatch performs no loader I/O", async () => {
  const f = ownerFixture(), h = startOwnedStage(f, f.load, f.time, f.gate); f.time.time = 5000000000n;
  await assert.rejects(h.result, isStatic); await h.closed; assert.equal(f.counts.loads, 0);
});
for (const bad of [-1n, 1, undefined, "5000000000"]) {
  test(`invalid original clock ${String(bad)} refuses before I/O`, async () => {
    const f = ownerFixture(); f.time.now = () => bad as bigint;
    const h = startOwnedStage(f, f.load, f.time, f.gate);
    await assert.rejects(h.result, isStatic); await h.closed; assert.equal(f.counts.loads, 0);
  });
}
test("regressing clock and clock-callback cancellation after parse fail closed", async () => {
  for (const cancel of [false, true]) {
    const f = ownerFixture(); let calls = 0;
    f.time.now = () => {
      if (++calls === 7) { if (cancel) h.cancel(); else return 0n; }
      return 1n;
    };
    const h = startOwnedStage(f, f.load, f.time, f.gate); f.result.resolve(f.material); f.closed.resolve();
    await assert.rejects(h.result, isStatic); await h.closed; assert.equal(f.counts.disposals, 1);
  }
});
