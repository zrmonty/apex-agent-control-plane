import assert from "node:assert/strict";
import test from "node:test";
import { callHarness, turns } from "./call-owner-testing.js";

const safe = /managed call refused safely/;
test("failed completion stays visible and explicit retry preserves exact identity", async () => {
  const h = callHarness({ failCompletion: true }); const call = h.start(); await call.result; await call.closed;
  assert.equal(h.active, 0); const pending = h.owner.pending(); assert.equal(pending.length, 1);
  assert.equal(pending[0].state, "completion_pending"); assert.equal(pending[0].callId, h.submitted.callId);
  h.allowCompletion(); const retry = h.owner.retryCompletion(h.submitted.callId);
  assert.equal(await retry.result, true); await retry.closed; assert.deepEqual(h.owner.pending(), []);
  assert.equal(h.effects.filter(e => e === "upstream").length, 1); assert.equal(h.effects.filter(e => e === "complete").length, 2);
});

test("authorization closure is required before upstream work", async () => {
  const h = callHarness({ holdAuth: true }); const call = h.start(); await turns();
  assert.equal(h.active, 1); assert.deepEqual(h.effects, ["authorize"]);
  h.authClosed.resolve(); await call.result; await call.closed; assert.equal(h.active, 0);
});

test("successful result and cancellation cannot release a held upstream group", async () => {
  const h = callHarness({ holdUpstream: true }); const call = h.start(); await turns();
  h.upstreamResult.resolve({ content: [] }); await call.result;
  call.cancel(); await turns(); assert.equal(h.active, 1); assert.ok(!h.effects.includes("complete"));
  let closed = false; void call.closed.then(() => { closed = true; }); await turns(); assert.equal(closed, false);
  h.upstreamClosed.resolve(); await call.closed; assert.equal(h.active, 0); assert.equal(h.effects.filter(e => e === "complete").length, 1);
});

for (const change of ["revoke", "epoch", "expiry"] as const) {
  test(`${change} after authorization but before its physical closure dispatches no upstream`, async () => {
    const h = callHarness({ holdAuth: true }); const call = h.start(); const rejected = assert.rejects(call.result, safe); await turns();
    if (change === "revoke") h.revoke(); else if (change === "epoch") h.epoch(24n); else h.time(8000n);
    h.authClosed.resolve(); await rejected; await call.closed;
    assert.ok(!h.effects.includes("upstream")); assert.equal(h.effects.filter(e => e === "complete").length, 1);
  });
}

test("unknown authorization outcome remains bounded and never fabricates completion", async () => {
  const h = callHarness({ unknownAuth: true }); const call = h.start(); await assert.rejects(call.result, safe); await call.closed;
  assert.equal(h.active, 0); assert.deepEqual(h.owner.pending(), [{ callId: h.submitted.callId, state: "unknown_reservation" }]);
  assert.ok(!h.effects.includes("upstream")); assert.ok(!h.effects.includes("complete"));
  assert.throws(() => h.owner.retryCompletion(h.submitted.callId), safe);
  assert.deepEqual(await h.owner.close(), h.owner.pending());
});

test("PREPARE and malformed argument hash cannot reach authorization", async () => {
  const prepare = callHarness({ prepare: true }); const call = prepare.start(); await assert.rejects(call.result, safe); await call.closed;
  assert.deepEqual(prepare.effects, []); assert.equal(prepare.active, 0);
  const wrong = callHarness(); wrong.body.portfolioId = "changed"; assert.throws(() => wrong.start(), safe); assert.deepEqual(wrong.effects, []);
});

test("denial dispatches no upstream and makes no completion reservation", async () => {
  const h = callHarness({ denied: true }); const call = h.start(); assert.equal((await call.result).decision.outcome, "denied"); await call.closed;
  assert.deepEqual(h.effects, ["authorize", "release"]); assert.deepEqual(h.owner.pending(), []);
});

test("root stop rejects future calls and waits held physical work", async () => {
  const h = callHarness({ holdUpstream: true }); const call = h.start(); const rejected = assert.rejects(call.result, safe); await turns();
  let closed = false; const stopping = h.owner.close().then(value => { closed = true; return value; });
  await rejected; await turns(); assert.equal(closed, false); assert.equal(h.active, 1); assert.throws(() => h.start(), safe);
  h.upstreamResult.reject(new Error("cancelled")); h.upstreamClosed.resolve(); assert.deepEqual(await stopping, []); await call.closed;
});

test("completed receipt still owns its physical RPC until closed, including root stop", async () => {
  const h = callHarness({ holdCompletion: true }); const call = h.start(); await call.result; await turns();
  assert.equal(h.active, 0); assert.equal(h.owner.pending()[0].state, "completing");
  let closed = false; const closing = h.owner.close().then(value => { closed = true; return value; });
  await turns(); assert.equal(closed, false); assert.ok(h.effects.includes("cancel-completion"));
  h.completionClosed.resolve(); await call.closed; assert.deepEqual(await closing, []);
});

test("unknown reservations retain the bounded 128-record capacity without invented release", async () => {
  const h = callHarness({ unknownAuth: true });
  for (let index = 0; index < 128; index++) {
    h.submitted.callId = `018f3d4a-8b9c-7d0e-8f12-${index.toString(16).padStart(12, "0")}`;
    const call = h.start(); await assert.rejects(call.result, safe); await call.closed;
  }
  assert.equal(h.owner.pending().length, 128); assert.equal(h.active, 0);
  h.submitted.callId = "018f3d4a-8b9c-7d0e-8f12-ffffffffffff";
  assert.throws(() => h.start(), safe); assert.equal(h.effects.filter(e => e === "authorize").length, 128);
  assert.ok(!h.effects.includes("complete"));
});

test("pending completion exact identity blocks duplicate business and concurrent cleanup retry", async () => {
  const h = callHarness({ failCompletion: true, holdCompletion: true });
  const call = h.start(); await call.result; await call.closed;
  assert.throws(() => h.start(), safe);
  h.allowCompletion(); const retry = h.owner.retryCompletion(h.submitted.callId);
  assert.throws(() => h.owner.retryCompletion(h.submitted.callId), safe);
  await turns(); let closed = false; void retry.closed.then(() => { closed = true; }); await turns(); assert.equal(closed, false);
  h.completionClosed.resolve(); assert.equal(await retry.result, true); await retry.closed;
});

test("changed binding or active input descriptors refuse before side effects", () => {
  const h = callHarness(); h.submitted.binding!.target!.generation++;
  assert.throws(() => h.start(), safe); assert.deepEqual(h.effects, []);
  const active = callHarness(); let reads = 0;
  Object.defineProperty(active.body, "portfolioId", { enumerable: true, get() { reads++; return "p-1"; } });
  assert.throws(() => active.start(), safe); assert.equal(reads, 0); assert.deepEqual(active.effects, []);
});

test("exact completion retry remains possible after new-call stop", async () => {
  const h = callHarness({ failCompletion: true }); const call = h.start(); await call.result; await call.closed;
  assert.equal((await h.owner.close()).length, 1); h.allowCompletion();
  const retry = h.owner.retryCompletion(h.submitted.callId); assert.equal(await retry.result, true); await retry.closed;
  assert.deepEqual(h.owner.pending(), []); assert.throws(() => h.start(), safe);
});
