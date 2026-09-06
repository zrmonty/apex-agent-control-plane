import assert from "node:assert/strict";
import test from "node:test";
import { create } from "@bufbuild/protobuf";
import { GovernanceOutcome, ManagedCallAuthorizationDecisionSchema } from "@apex/contracts";
import { observationFixture } from "./call-observation/testing.js";
import { callHarness, turns } from "./call-owner-testing.js";

test("observations preserve exact 1/7/999us boundaries above Number precision and held closure", async t => {
  const h = observationFixture(t), call = h.start(), start = h.started;
  assert.equal(typeof call.observation, "function", "owned calls must expose local observations");
  assert.deepEqual(call.observation(), { callId: h.submitted.callId, traceId: "1".repeat(32), spanId: "2".repeat(16),
    startedAtMonotonicNs: start, authorization: { startedAtMonotonicNs: start, state: "pending" } });
  h.time(start + 1_000n); h.authorize(); await turns();
  assert.equal(call.observation().authorization!.resultAtMonotonicNs, start + 1_000n);
  assert.equal(call.observation().authorization!.closedAtMonotonicNs, undefined);
  assert.equal(call.observation().upstream, undefined);
  h.time(start + 7_000n); h.authClosed.resolve(); await turns();
  assert.equal(call.observation().authorization!.closedAtMonotonicNs, start + 7_000n);
  assert.equal(call.observation().upstream!.startedAtMonotonicNs, start + 7_000n);
  assert.equal(call.observation().dispatchedAtMonotonicNs, start + 7_000n);
  h.time(start + 999_000n); h.upstreamResult.resolve({ secret: "private output" }); await call.result; await turns();
  assert.equal(call.observation().upstream!.resultAtMonotonicNs, start + 999_000n);
  assert.equal(call.observation().upstream!.closedAtMonotonicNs, undefined);
  assert.equal(call.observation().cleanup!.startedAtMonotonicNs, start + 999_000n);
  assert.equal(call.observation().closedAtMonotonicNs, undefined);
  assert.equal(h.active, 1);
  h.time(start + 1_000_000n); h.upstreamClosed.resolve(); await turns();
  assert.equal(call.observation().upstream!.closedAtMonotonicNs, start + 1_000_000n);
  h.time(start + 1_007_000n); h.complete(); await turns();
  assert.equal(call.observation().cleanup!.resultAtMonotonicNs, start + 1_007_000n);
  assert.equal(call.observation().cleanup!.closedAtMonotonicNs, undefined);
  h.time(start + 1_999_000n); h.completionClosed.resolve(); await call.closed;
  assert.deepEqual(call.observation().cleanup, { startedAtMonotonicNs: start + 999_000n,
    resultAtMonotonicNs: start + 1_007_000n, closedAtMonotonicNs: start + 1_999_000n, state: "ok" });
  assert.equal(call.observation().closedAtMonotonicNs, start + 1_999_000n);
});

test("known authorization survives upstream failure without retaining output or error text", async t => {
  const h = observationFixture(t), call = h.start();
  assert.equal(typeof call.observation, "function");
  h.authorize(); h.authClosed.resolve(); await turns();
  h.upstreamResult.reject(new Error("private upstream diagnostic")); await assert.rejects(call.result, /managed call refused safely/);
  assert.equal(call.observation().decision?.outcome, "allowed");
  assert.equal(call.observation().upstream!.state, "error");
  h.upstreamClosed.resolve(); await turns(); h.complete(); h.completionClosed.resolve(); await call.closed;
  const text = JSON.stringify(call.observation(), (_key, value) => typeof value === "bigint" ? String(value) : value);
  assert.ok(!text.includes("private")); assert.ok(!text.includes("output"));
});

test("unknown and unreached authorization never manufacture decisions or upstream stages", async () => {
  for (const options of [{ unknownAuth: true }, { prepare: true }]) {
    const h = callHarness(options), call = h.start(); await assert.rejects(call.result); await call.closed;
    assert.equal(typeof call.observation, "function");
    assert.equal(call.observation().decision, undefined); assert.equal(call.observation().upstream, undefined);
    assert.equal(call.observation().dispatchedAtMonotonicNs, undefined);
    if (options.prepare) assert.equal(call.observation().authorization, undefined);
    else assert.equal(call.observation().authorization!.state, "error");
  }
});

test("denied decisions have authorization timing but no upstream or dispatch timing", async t => {
  const h = observationFixture(t), call = h.start();
  assert.equal(typeof call.observation, "function");
  h.authorize(create(ManagedCallAuthorizationDecisionSchema, { decision: {
    outcome: GovernanceOutcome.DENIED, policyId: "portfolio-policy", reasonCode: "policy.denied" }, policyRevision: 1n }));
  h.authClosed.resolve(); assert.equal((await call.result).decision.outcome, "denied"); await call.closed;
  assert.equal(call.observation().decision?.outcome, "denied");
  assert.equal(call.observation().authorization!.state, "ok");
  assert.equal(call.observation().upstream, undefined); assert.equal(call.observation().dispatchedAtMonotonicNs, undefined);
});

test("session creation is not dispatch and late cancelled success cannot change observed state", async t => {
  const h = observationFixture(t, false), call = h.start();
  assert.equal(typeof call.observation, "function");
  h.authorize(); h.authClosed.resolve(); await turns();
  assert.ok(h.gate); assert.equal(call.observation().upstream!.state, "pending");
  assert.equal(call.observation().dispatchedAtMonotonicNs, undefined);
  call.cancel(); assert.throws(() => h.gate!.beforeWrite(), /managed call refused safely/);
  assert.equal(call.observation().upstream!.resultAtMonotonicNs, undefined);
  h.upstreamResult.resolve({ content: [] }); await assert.rejects(call.result); await turns();
  assert.equal(call.observation().upstream!.state, "cancelled");
  assert.equal(call.observation().dispatchedAtMonotonicNs, undefined);
  assert.equal(call.observation().upstream!.closedAtMonotonicNs, undefined);
});

test("snapshots are fresh deeply frozen and reading performs no clock or authority work", async t => {
  const h = observationFixture(t), call = h.start();
  assert.equal(typeof call.observation, "function");
  h.authorize(); await turns();
  const first = call.observation(), reads = h.clockReads, effects = [...h.effects];
  h.failClock();
  const second = call.observation(); assert.notEqual(first, second);
  assert.notEqual(first.decision, second.decision); assert.deepEqual(first, second);
  assert.equal(h.clockReads, reads); assert.deepEqual(h.effects, effects);
  assert.ok(Object.isFrozen(first)); assert.ok(Object.isFrozen(first.authorization));
  assert.ok(Object.isFrozen(first.decision!.fieldRestrictions));
  if (first.decision!.outcome === "allowed") assert.ok(Object.isFrozen(first.decision!.submittedRequest.trace));
  assert.equal(Reflect.set(first.authorization!, "state", "error"), false);
});

test("an upstream result observed at overall expiry is error, not successful stage completion", async t => {
  const h = observationFixture(t), call = h.start();
  h.authorize(); h.authClosed.resolve(); await turns();
  h.time(h.started + 30_000_000_000n); h.upstreamResult.resolve({ content: [] });
  await assert.rejects(call.result, /managed call refused safely/);
  assert.equal(call.observation().upstream!.state, "error");
  assert.equal(call.observation().upstream!.resultAtMonotonicNs, h.started + 30_000_000_000n);
  assert.equal(call.observation().upstream!.closedAtMonotonicNs, undefined);
});

test("known decision is copied before external mutation and survives until physical cleanup", async t => {
  const h = observationFixture(t), original = h.business.startAuthorization.bind(h.business);
  let mutable: import("./authority/business-types.js").BusinessDecision | undefined;
  t.mock.method(h.business, "startAuthorization", (...args: Parameters<typeof original>) => {
    const exchange = original(...args);
    return { ...exchange, result: exchange.result.then(decision => { mutable = structuredClone(decision); return mutable; }) };
  });
  const call = h.start(); h.authorize(); await turns();
  const before = call.observation(); assert.equal(before.decision!.fieldRestrictions[0], "ssn");
  (mutable!.fieldRestrictions as string[])[0] = "changed";
  if (mutable!.outcome === "allowed") Reflect.set(mutable!, "admissionId", "changed");
  h.submitted.trace!.traceId = "3".repeat(32);
  assert.deepEqual(call.observation(), before);
  h.authClosed.resolve(); await turns(); h.upstreamResult.resolve({ content: [] });
  assert.equal((await call.result).decision.fieldRestrictions[0], "ssn");
  h.upstreamClosed.resolve(); await turns(); h.complete(); h.completionClosed.resolve(); await call.closed;
  assert.deepEqual(h.owner.pending(), []);
  const closedSnapshot = call.observation(), reads = h.clockReads;
  h.failClock(); assert.deepEqual(call.observation(), closedSnapshot); assert.equal(h.clockReads, reads);
});

for (const failure of ["throw", "regress"] as const) test(`observation clock ${failure} stops work without fabricating closure times`, async t => {
  const h = observationFixture(t), call = h.start(); h.authorize(); await turns();
  if (failure === "throw") h.failClock(); else h.time(h.started - 1n);
  h.authClosed.resolve(); await assert.rejects(call.result, /managed call refused safely/); await call.closed;
  const observed = call.observation();
  assert.equal(observed.decision?.outcome, "allowed"); assert.equal(observed.upstream, undefined);
  assert.equal(observed.authorization!.closedAtMonotonicNs, undefined);
  assert.equal(observed.cleanup!.closedAtMonotonicNs, undefined); assert.equal(observed.closedAtMonotonicNs, undefined);
  assert.equal(h.active, 0); assert.equal(h.owner.pending()[0].state, "completion_pending");
  const reads = h.clockReads; assert.deepEqual(call.observation(), observed); assert.equal(h.clockReads, reads);
});

test("failed authorization decoding omits the decision and cannot manufacture an admission", async t => {
  const h = observationFixture(t), call = h.start();
  h.authResult.resolve(Buffer.from([255])); h.authClosed.resolve(); await assert.rejects(call.result); await call.closed;
  assert.equal(call.observation().decision, undefined); assert.equal(call.observation().authorization!.state, "error");
  assert.equal(call.observation().upstream, undefined);
  assert.deepEqual(h.owner.pending(), [{ callId: h.submitted.callId, state: "unknown_reservation" }]);
});

test("initial completion failure remains an observed error across an explicit later retry", async () => {
  const h = callHarness({ failCompletion: true }), call = h.start(); await call.result; await call.closed;
  const before = call.observation(); assert.equal(before.cleanup!.state, "error");
  h.allowCompletion(); const retry = h.owner.retryCompletion(h.submitted.callId);
  assert.equal(await retry.result, true); await retry.closed;
  assert.deepEqual(call.observation(), before); assert.deepEqual(h.owner.pending(), []);
});

test("observing a local bigint clock does not impose a new wire uint64 limit on owner deadlines", async t => {
  const started = 18_446_744_073_709_551_616n, h = observationFixture(t, true, started), call = h.start();
  h.authorize(); await turns();
  assert.equal(call.observation().decision?.outcome, "allowed");
  assert.equal(call.observation().startedAtMonotonicNs, started);
  h.authClosed.resolve(); await turns(); h.upstreamResult.resolve({ content: [] }); await call.result;
  h.upstreamClosed.resolve(); await turns(); h.complete(); h.completionClosed.resolve(); await call.closed;
  assert.equal(call.observation().closedAtMonotonicNs, started);
});
