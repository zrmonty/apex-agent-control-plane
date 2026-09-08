import test from "node:test";
import assert from "node:assert/strict";
import { servingFixture, tick, admissionId } from "./testing.js";
import { disposeRuntimeMaterials } from "../bootstrap/runtime-materials.js";
import { disposeStageOwner } from "../bootstrap/stage-owner.js";

test("local cancellation retains completion capability until the exact upstream physical closure", async t => {
  const f = await servingFixture(t); f.holdCalls(); f.holdPhysical();
  const call = f.start(); await tick();
  assert.equal(f.core.grants.snapshot().activeCalls, 1);
  let drained = false; void f.handle.closed.then(() => { drained = true; });
  f.handle.cancel(); await assert.rejects(call.result); await tick();
  assert.equal(f.core.isAdmitting(), false); assert.equal(f.completions.length, 0);
  assert.equal(f.stats().controlCancelled, false); assert.equal(drained, false);
  f.releasePhysical(); await call.closed; await f.handle.closed;
  assert.equal(f.completions.length, 1);
  assert.equal(f.completions[0].admissionId, admissionId);
  assert.equal(f.completions[0].callId, f.authorizations[0].callId);
  assert.equal(f.completions[0].binding!.target!.generation, 9007199254740993n);
  assert.deepEqual(await f.handle.completionHandoff, []);
  assert.equal(f.stats().controlCancelled, true);
});

test("normal completion failure exposes exact pending identity and a physically owned explicit retry", async t => {
  const f = await servingFixture(t); f.failCompletion(true);
  const call = f.start(); await call.result; await call.closed;
  const callId = f.authorizations[0].callId;
  assert.deepEqual(f.core.pendingCompletions(), [{ callId, admissionId, state: "completion_pending" }]);
  f.failCompletion(false); const retry = f.core.retryCompletion(callId);
  assert.throws(() => f.core.retryCompletion(callId), /refused safely/);
  assert.equal(await retry.result, true); await retry.closed;
  assert.equal(f.completions.length, 2);
  assert.deepEqual(f.completions[0], f.completions[1]);
  assert.deepEqual(f.core.pendingCompletions(), []);
  f.handle.cancel(); await f.handle.closed;
  assert.deepEqual(await f.handle.completionHandoff, []);
  assert.throws(() => f.core.retryCompletion(callId), /refused safely/);
});

test("failed shutdown completion returns the exact unresolved handoff after physical drain", async t => {
  const f = await servingFixture(t); f.holdCalls(); f.holdPhysical(); f.failCompletion(true);
  const call = f.start(); await tick(); f.handle.cancel(); await assert.rejects(call.result);
  f.releasePhysical(); await f.handle.closed;
  assert.equal(f.completions.length, 1);
  const pending = [{ callId: f.authorizations[0].callId, admissionId, state: "completion_pending" }];
  assert.deepEqual(await f.handle.completionHandoff, pending);
  assert.deepEqual(f.core.pendingCompletions(), pending);
  assert.ok(Object.isFrozen(await f.handle.completionHandoff));
});

for (const invalidation of ["material disposal", "stage disposal", "credential expiry", "control revocation", "backwards clock"] as const) {
  test(`${invalidation} during shutdown cannot extend completion credentials and hands off the reservation`, async t => {
    const f = await servingFixture(t); f.holdCalls(); f.holdPhysical();
    const call = f.start(); await tick();
    f.handle.cancel(); await assert.rejects(call.result);
    if (invalidation === "material disposal") disposeRuntimeMaterials(f.materials);
    if (invalidation === "stage disposal") disposeStageOwner(f.stage);
    if (invalidation === "credential expiry") f.time.time = (f.materials.notAfterUnixUs - 1783123456123456n) * 1000n;
    if (invalidation === "control revocation") f.revokeControl();
    if (invalidation === "backwards clock") f.time.time = -1n;
    await tick(); f.releasePhysical(); await f.handle.closed;
    assert.equal(f.completions.length, 0);
    assert.deepEqual(await f.handle.completionHandoff,
      [{ callId: f.authorizations[0].callId, admissionId, state: "completion_pending" }]);
  });
}

test("cleanup timeout preserves the active reservation and waits for closure before completing after grant expiry", async t => {
  const f = await servingFixture(t); f.holdCalls(); f.holdPhysical();
  const call = f.start(); await tick(); f.handle.cancel(); await assert.rejects(call.result);
  let drained = false, handedOff = false;
  void f.handle.closed.then(() => { drained = true; });
  assert.ok(f.handle.completionHandoff);
  void f.handle.completionHandoff.then(() => { handedOff = true; });
  f.time.advance(11000); await tick();
  assert.equal(f.stats().fatals, 1); assert.equal(drained, false); assert.equal(handedOff, false);
  assert.equal(f.core.grants.snapshot().activeCalls, 1); assert.equal(f.completions.length, 0);
  f.releasePhysical(); await f.handle.closed;
  assert.equal(f.completions.length, 1); assert.deepEqual(await f.handle.completionHandoff, []);
});

test("cancelled unknown authorization is handed off without inventing an admission or a completion", async t => {
  const f = await servingFixture(t); f.holdAuthorization();
  const call = f.start(); await tick(); f.handle.cancel(); await assert.rejects(call.result); await f.handle.closed;
  const pending = [{ callId: f.authorizations[0].callId, state: "unknown_reservation" }];
  assert.deepEqual(await f.handle.completionHandoff, pending);
  assert.equal(f.completions.length, 0);
});
