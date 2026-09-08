import test from "node:test";
import assert from "node:assert/strict";
import { ReadinessCheckStatus as Status } from "@apex/contracts";
import { servingFixture, tick } from "../runtime-core/testing.js";
import { assertRuntimeMaterialsStage, disposeRuntimeMaterials } from "../bootstrap/runtime-materials.js";

test("application converges after cold NETWORK Busy using the same core and original cadence", async t => {
  const f = await servingFixture(t, { application: true, skipReadiness: true, networkUnavailable: true });
  let outcome = "pending";
  void f.application!.result.then(() => { outcome = "ready"; }, () => { outcome = "rejected"; });
  await tick();
  assert.equal(f.networkProbes.length, 1);
  assert.equal(outcome, "pending");
  assert.equal(f.admitting(), false); assert.equal(f.core.grants.tryBeginCall(), undefined);
  assert.equal(f.policies.length, 0); assert.equal(f.probes.length, 0); assert.equal(f.requests.length, 0);
  f.networkUnavailable(false);
  f.time.advance(4999); await tick();
  assert.equal(f.networkProbes.length, 1); assert.equal(outcome, "pending"); assert.equal(f.admitting(), false);
  f.time.advance(1); await tick();
  assert.equal(outcome, "ready");
  assert.deepEqual(await f.application!.result, { host: "10.96.0.2", port: 8080 });
  assert.equal(f.networkProbes.length, 2); assert.equal(f.stats().coreStarts, 1);
  assert.equal(f.core.readiness.snapshot().checks.filter(check => check.status === Status.PASS).length, 9);
  assert.equal(f.admitting(), true);
  assert.equal(f.grantRequests[0].renewalSequence, 1n);
  assert.ok(f.grantRequests.every((request, i) => request.renewalSequence === BigInt(i + 1)));
  assert.equal(f.authorizations.length, 0); assert.equal(f.events.length, 0); assert.equal(f.stats().fatals, 0);
});

test("persistent cold failure exhausts the original twenty-second budget without a fifth sweep", async t => {
  const f = await servingFixture(t, { application: true, skipReadiness: true, networkUnavailable: true });
  let outcome = "pending";
  void f.application!.result.then(() => { outcome = "ready"; }, () => { outcome = "rejected"; });
  for (const advance of [5000, 5000, 5000, 4999]) {
    f.time.advance(advance); await tick();
    assert.equal(outcome, "pending"); assert.equal(f.admitting(), false);
  }
  assert.equal(f.networkProbes.length, 4);
  f.time.advance(1); await tick();
  assert.equal(outcome, "rejected"); await f.application!.closed;
  f.networkUnavailable(false); f.time.advance(10000); await tick();
  assert.equal(f.networkProbes.length, 4); assert.equal(f.stats().coreStarts, 1);
  assert.equal(f.stats().fatals, 0); assert.equal(f.admitting(), false);
});

for (const at of [19999, 20000]) {
  test(`delayed cold startup observes the original deadline with NETWORK completion at ${at}ms before timer polling`, async t => {
    const f = await servingFixture(t, { application: true, skipReadiness: true,
      networkUnavailable: true, startupDelayMs: 4000 });
    for (let i = 0; i < 2; i++) { f.time.advance(5000); await tick(); }
    f.networkUnavailable(false); f.holdNetworkReply(); f.holdNetworkClosure();
    f.time.advance(5000); await tick(); // dispatch at 19s; original application deadline is still 20s.
    let outcome = "pending";
    void f.application!.result.then(() => { outcome = "ready"; }, () => { outcome = "rejected"; });
    await tick(); assert.equal(outcome, "pending"); assert.equal(f.admitting(), false);
    f.time.time = BigInt(at) * 1000000n; f.replyNetwork(); await tick(); f.releaseNetwork(); await tick();
    assert.equal(outcome, at < 20000 ? "ready" : "rejected");
    assert.equal(f.admitting(), at < 20000);
    assert.equal(f.stats().coreStarts, 1); assert.equal(f.networkProbes.length, 4);
  });
}

test("cancelling between cold sweeps settles startup and closes without another dispatch", async t => {
  const f = await servingFixture(t, { application: true, skipReadiness: true, networkUnavailable: true });
  await tick();
  assert.equal(f.application!.cancel(), true); assert.equal(f.application!.cancel(), false);
  await assert.rejects(f.application!.result, /managed application refused safely/);
  await f.application!.closed; assert.deepEqual(await f.application!.completionHandoff, []);
  f.networkUnavailable(false); f.time.advance(10000); await tick();
  assert.equal(f.networkProbes.length, 1); assert.equal(f.admitting(), false); assert.equal(f.stats().fatals, 0);
});

test("a first PASS delivered at the application sweep boundary cannot start another cold retry", async t => {
  const f = await servingFixture(t, { application: true, skipReadiness: true, networkUnavailable: true });
  f.networkUnavailable(false); f.holdNetworkReply(); f.holdNetworkClosure();
  f.time.advance(5000); await tick(); f.replyNetwork(); f.releaseNetwork();
  // Let the monitor publish all nine owners, but hold delivery to the awaiting
  // application until its original sweep bound. No timer callback has polled.
  for (let i = 0; i < 500 && !f.core.readiness.snapshot().ready; i++) await Promise.resolve();
  assert.equal(f.core.readiness.snapshot().ready, true);
  f.time.time = 7_000_000_000n;
  let outcome = "pending";
  void f.application!.result.then(() => { outcome = "ready"; }, () => { outcome = "rejected"; });
  await tick(); assert.equal(outcome, "rejected");
  await f.application!.closed; assert.equal(f.admitting(), false);
  f.time.advance(5000); await tick(); assert.equal(f.networkProbes.length, 2);
});

test("hung cold NETWORK cleanup retains the sole exchange until the original fatal bound", async t => {
  const f = await servingFixture(t, { application: true, skipReadiness: true, networkUnavailable: true });
  f.networkUnavailable(false); f.holdNetworkReply(); f.holdNetworkClosure();
  f.time.advance(5000); await tick();
  f.networkUnavailable(true); f.replyNetwork(); await tick();
  assert.equal(f.networkProbes.length, 2); assert.equal(f.admitting(), false);
  f.time.advance(2000); await tick(); // logical sweep deadline, physical closure still absent.
  let closed = false; void f.application!.closed.then(() => { closed = true; });
  f.networkUnavailable(false); f.time.advance(3000); await tick();
  assert.equal(f.networkProbes.length, 2, "cadence cannot replace a held physical owner");
  assert.equal(closed, false); assertRuntimeMaterialsStage(f.materials, f.stage);
  f.time.advance(1999); await tick(); assert.equal(f.stats().fatals, 0);
  f.time.advance(1); await tick(); assert.equal(f.stats().fatals, 1);
  await assert.rejects(f.application!.result, /managed application refused safely/);
  assert.equal(closed, false); assertRuntimeMaterialsStage(f.materials, f.stage);
  f.releaseNetwork(); await f.application!.closed;
  assert.equal(closed, true); assert.equal(f.networkProbes.length, 2);
});

for (const loss of ["material", "verifier", "credential", "grant", "clock"] as const) {
  test(`cold ${loss} continuity loss never converges after NETWORK becomes healthy`, async t => {
    const f = await servingFixture(t, { application: true, skipReadiness: true, networkUnavailable: true });
    if (loss === "material") disposeRuntimeMaterials(f.materials);
    if (loss === "verifier") await f.core.verifier.close();
    if (loss === "credential") f.revokeControl();
    if (loss === "grant") await f.core.grants.close();
    if (loss === "clock") f.time.time = -1n;
    assert.equal(f.core.readiness.snapshot().ready, false);
    if (loss === "clock") f.time.time = 0n;
    f.networkUnavailable(false);
    for (let i = 0; i < 4; i++) { f.time.advance(5000); await tick(); }
    await assert.rejects(f.application!.result, /managed application refused safely/);
    await f.application!.closed;
    assert.equal(f.networkProbes.length, 1); assert.equal(f.admitting(), false);
  });
}
