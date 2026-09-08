import test from "node:test";
import assert from "node:assert/strict";
import { ReadinessCheckId as Check, ReadinessCheckStatus as Status } from "@apex/contracts";
import { servingFixture, tick } from "./testing.js";
import { disposeRuntimeMaterials } from "../bootstrap/runtime-materials.js";

test("cold NETWORK unavailability can pass a later sweep on the same concrete owners", async t => {
  const f = await servingFixture(t, { skipReadiness: true, networkUnavailable: true });
  assert.equal((await f.core.readiness.checkStartup()).ready, false);
  assert.equal(f.core.readiness.hasBeenReady, false);
  assert.equal(f.core.isAdmitting(), false); assert.equal(f.networkProbes.length, 1);
  f.networkUnavailable(false); f.time.advance(4999); await tick();
  assert.equal((await f.core.readiness.checkStartup()).ready, false);
  assert.equal(f.networkProbes.length, 1);
  f.time.advance(1); await tick();
  assert.equal((await f.core.readiness.checkStartup()).ready, true);
  assert.equal(f.core.readiness.hasBeenReady, true);
  assert.equal(f.networkProbes.length, 2); assert.equal(f.stats().coreStarts, 1);
  assert.equal(f.core.isAdmitting(), true);
});

for (const dependency of ["EVIDENCE", "GOVERNANCE"] as const) {
  test(`cold ${dependency} unavailability retries only after its exact exchange closes`, async t => {
    const f = await servingFixture(t, { skipReadiness: true });
    const selected = dependency === "EVIDENCE"
      ? { hold: f.holdProbeClosure, fail: f.refuseProbe, release: f.releaseProbes, requests: f.probes }
      : { hold: f.holdPolicyClosure, fail: f.policyUnavailable, release: f.releasePolicies, requests: f.policies };
    selected.hold(); selected.fail(true);
    let settled = false;
    const first = f.core.readiness.checkStartup(); void first.then(() => { settled = true; });
    await tick(); assert.equal(selected.requests.length, 1); assert.equal(settled, false);
    assert.equal(f.core.isAdmitting(), false); assert.equal(f.core.readiness.hasBeenReady, false);
    f.time.advance(2000); await tick(); assert.equal((await first).ready, false);
    f.time.advance(1000); await tick(); selected.release(); await tick();
    selected.fail(false); f.time.advance(1999); await tick();
    assert.equal((await f.core.readiness.checkStartup()).ready, false); assert.equal(selected.requests.length, 1);
    f.time.advance(1); await tick();
    const retry = f.core.readiness.checkStartup(); await tick();
    assert.equal(selected.requests.length, 2); assert.equal(f.core.isAdmitting(), false);
    selected.release(); assert.equal((await retry).ready, true); assert.equal(f.core.isAdmitting(), true);
    assert.equal(f.stats().coreStarts, 1); assert.equal(f.stats().fatals, 0);
  });
}

for (const dependency of ["NETWORK", "EVIDENCE", "GOVERNANCE"] as const) {
  test(`post-ready ${dependency} unavailability never recovers after physical closure and healthy replies`, async t => {
    const f = await servingFixture(t);
    const selected = dependency === "NETWORK"
      ? { hold: f.holdNetworkClosure, holdReply: f.holdNetworkReply, reply: f.replyNetwork,
        fail: f.networkUnavailable, release: f.releaseNetwork, requests: f.networkProbes }
      : dependency === "EVIDENCE"
        ? { hold: f.holdProbeClosure, holdReply: f.holdProbeReply, reply: f.replyProbes,
          fail: f.refuseProbe, release: f.releaseProbes, requests: f.probes }
        : { hold: f.holdPolicyClosure, holdReply: f.holdPolicyReply, reply: f.replyPolicies,
          fail: f.policyUnavailable, release: f.releasePolicies, requests: f.policies };
    f.time.advance(5000); await tick(); selected.hold(); selected.holdReply();
    const failed = f.core.readiness.checkStartup(); await tick();
    selected.fail(true); selected.reply(); await tick();
    assert.equal(selected.requests.length, 2); assert.equal(f.core.isAdmitting(), false);
    assert.equal(f.core.grants.tryBeginCall(), undefined);
    selected.fail(false); selected.release(); await tick();
    assert.equal((await failed).ready, false);
    f.time.advance(5000); await tick();
    assert.equal((await f.core.readiness.checkStartup()).ready, false);
    assert.equal(f.core.isAdmitting(), false); assert.equal(selected.requests.length, 2);
    await f.core.grants.renew(); assert.equal(f.grantRequests.at(-1)!.applied!.admitting, false);
  });
}

test("SERVE alone cannot admit calls or acknowledge admission before the nine actual owners pass", async t => {
  const f = await servingFixture(t, { skipReadiness: true });
  assert.equal(f.core.grants.snapshot().mode, "serve");
  assert.equal(f.core.grants.snapshot().admitting, false);
  assert.equal(f.core.grants.tryBeginCall(), undefined);
  await f.core.grants.renew();
  assert.equal(f.grantRequests.at(-1)!.applied!.admitting, false);
  const report = await f.core.readiness.checkStartup();
  assert.equal(report.ready, true);
  assert.equal(report.checks.length, 9);
  assert.ok(report.checks.every(check => check.status === Status.PASS));
  assert.equal(f.networkProbes.length, 1); assert.equal(f.probes.length, 1); assert.equal(f.policies.length, 1);
  assert.equal(f.core.isAdmitting(), true);
  await f.core.grants.renew();
  assert.equal(f.grantRequests.at(-1)!.applied!.admitting, true);
  assert.equal(f.authorizations.length, 0); assert.equal(f.events.length, 0);
});

test("all nine PREPARE owners can pass without creating an admission or business call", async t => {
  const f = await servingFixture(t, { prepareOnly: true });
  assert.equal((await f.core.readiness.checkStartup()).ready, true);
  assert.equal(f.core.grants.snapshot().mode, "prepare");
  assert.equal(f.core.isAdmitting(), false); assert.equal(f.core.grants.tryBeginCall(), undefined);
  await f.core.grants.renew();
  assert.equal(f.grantRequests.at(-1)!.applied!.admitting, false);
  assert.equal(f.authorizations.length, 0); assert.equal(f.events.length, 0);
  assert.equal(f.requests.filter(request => request.method === "tools/call").length, 0);
});

test("the real network owner must physically close before dependent readiness RPCs start", async t => {
  const f = await servingFixture(t, { skipReadiness: true }); f.holdNetworkClosure();
  const sweep = f.core.readiness.checkStartup(); await tick();
  assert.equal(f.networkProbes.length, 1); assert.equal(f.probes.length, 0); assert.equal(f.policies.length, 0);
  assert.equal(f.requests.length, 0); assert.equal(f.core.isAdmitting(), false);
  f.releaseNetwork(); assert.equal((await sweep).ready, true);
  assert.equal(f.core.isAdmitting(), true);
});

test("NETWORK mismatch prevents upstream, governance, evidence and local admission", async t => {
  const f = await servingFixture(t, { skipReadiness: true }); f.wrongNetwork();
  const report = await f.core.readiness.checkStartup();
  assert.equal(report.ready, false);
  assert.equal(report.checks.find(check => check.id === Check.NETWORK)!.status, Status.FAIL);
  assert.equal(f.requests.length, 0); assert.equal(f.policies.length, 0); assert.equal(f.probes.length, 0);
  assert.equal(f.core.grants.tryBeginCall(), undefined);
});

test("cached readiness expiry closes admission and applied acknowledgement even with a fresh SERVE grant", async t => {
  const f = await servingFixture(t, { skipReadiness: true });
  assert.equal((await f.core.readiness.checkStartup()).ready, true);
  f.time.advance(5000); await tick();
  assert.equal(f.core.isAdmitting(), true);
  f.time.advance(5000); await tick();
  assert.equal(f.core.grants.snapshot().mode, "serve");
  assert.equal(f.core.readiness.snapshot().ready, false);
  assert.equal(f.core.isAdmitting(), false); assert.equal(f.core.grants.tryBeginCall(), undefined);
  await f.core.grants.renew();
  assert.equal(f.grantRequests.at(-1)!.applied!.admitting, false);
});

test("material disposal invalidates the cached report and admission without waiting for another sweep", async t => {
  const f = await servingFixture(t);
  assert.equal(f.core.isAdmitting(), true);
  disposeRuntimeMaterials(f.materials);
  assert.equal(f.core.readiness.snapshot().ready, false);
  assert.equal(f.core.grants.snapshot().admitting, false);
  await f.handle.closed;
});

test("closed staged inbound verifier cannot pass its concrete owner or permit admission", async t => {
  const f = await servingFixture(t, { skipReadiness: true });
  await f.core.verifier.close();
  const report = await f.core.readiness.checkStartup();
  assert.equal(report.ready, false);
  assert.equal(report.checks.find(check => check.id === Check.INBOUND_AUTH)!.status, Status.FAIL);
  assert.equal(f.core.grants.tryBeginCall(), undefined);
});

test("verifier closure immediately invalidates cached readiness, actual calls and applied admission", async t => {
  const f = await servingFixture(t);
  const call = f.core.grants.tryBeginCall(); assert.ok(call);
  call.release();
  await f.core.verifier.close();
  const io = [f.networkProbes.length, f.probes.length, f.policies.length, f.requests.length];
  assert.equal(f.core.readiness.snapshot().ready, false);
  assert.equal(f.core.grants.snapshot().admitting, false);
  assert.equal(f.core.isAdmitting(), false);
  assert.equal(f.core.grants.tryBeginCall(), undefined);
  assert.deepEqual([f.networkProbes.length, f.probes.length, f.policies.length, f.requests.length], io);
  await f.core.grants.renew();
  assert.equal(f.grantRequests.at(-1)!.applied!.admitting, false);
});

test("verifier closure during held sweep prevents publication and retains physical cleanup", async t => {
  const f = await servingFixture(t); f.time.advance(5000); await tick();
  f.holdProbeClosure();
  const sweep = f.core.readiness.checkStartup(); await tick();
  assert.equal(f.probes.length, 2);
  assert.equal(f.core.readiness.snapshot().ready, true);
  await f.core.verifier.close();
  assert.equal(f.core.readiness.snapshot().ready, false);
  assert.equal(f.core.grants.snapshot().admitting, false);
  assert.equal(f.core.grants.tryBeginCall(), undefined);
  await f.core.grants.renew();
  assert.equal(f.grantRequests.at(-1)!.applied!.admitting, false);
  let published = false; void sweep.then(() => { published = true; });
  await tick(); assert.equal(published, false);
  let closed = false;
  const closing = f.core.readiness.close().then(() => { closed = true; }); await tick();
  assert.equal((await sweep).ready, false);
  assert.equal(closed, false);
  f.releaseProbes();
  await closing; assert.equal(closed, true);
  assert.equal(f.core.readiness.snapshot().ready, false);
});

test("verifier closure before held completion cannot publish a fresh PASS without intervening reads", async t => {
  const f = await servingFixture(t); f.time.advance(5000); await tick();
  f.holdProbeClosure();
  const sweep = f.core.readiness.checkStartup(); await tick();
  assert.equal(f.probes.length, 2);
  await f.core.verifier.close();
  f.releaseProbes();
  assert.equal((await sweep).ready, false);
  assert.equal(f.core.grants.tryBeginCall(), undefined);
  await f.core.grants.renew();
  assert.equal(f.grantRequests.at(-1)!.applied!.admitting, false);
});

for (const dependency of ["NETWORK", "EVIDENCE", "GOVERNANCE"] as const) {
  test(`${dependency} result failure invalidates previous PASS before physical closure`, async t => {
    const f = await servingFixture(t); f.time.advance(5000); await tick();
    const selected = dependency === "NETWORK"
      ? { holdReply: f.holdNetworkReply, holdClosure: f.holdNetworkClosure, fail: f.wrongNetwork,
        reply: f.replyNetwork, release: f.releaseNetwork, requests: f.networkProbes }
      : dependency === "EVIDENCE"
        ? { holdReply: f.holdProbeReply, holdClosure: f.holdProbeClosure, fail: f.refuseProbe,
          reply: f.replyProbes, release: f.releaseProbes, requests: f.probes }
        : { holdReply: f.holdPolicyReply, holdClosure: f.holdPolicyClosure, fail: f.wrongPolicy,
          reply: f.replyPolicies, release: f.releasePolicies, requests: f.policies };
    selected.holdReply(); selected.holdClosure();
    const sweep = f.core.readiness.checkStartup(); await tick();
    assert.equal(selected.requests.length, 2);
    assert.equal(f.core.readiness.snapshot().ready, true);
    const call = f.core.grants.tryBeginCall(); assert.ok(call); call.release();
    await f.core.grants.renew();
    assert.equal(f.grantRequests.at(-1)!.applied!.admitting, true);
    selected.fail(); selected.reply(); await tick();
    // No deadline or physical closure has occurred: only the genuine decoder's
    // newer negative observation may invalidate the still-unexpired cache.
    assert.equal(f.time.now(), 5_000_000_000n);
    const io = [f.networkProbes.length, f.probes.length, f.policies.length, f.requests.length];
    assert.equal(f.core.readiness.snapshot().ready, false);
    assert.equal(f.core.grants.snapshot().admitting, false);
    assert.equal(f.core.isAdmitting(), false);
    assert.equal(f.core.grants.tryBeginCall(), undefined);
    assert.deepEqual([f.networkProbes.length, f.probes.length, f.policies.length, f.requests.length], io);
    await f.core.grants.renew();
    assert.equal(f.grantRequests.at(-1)!.applied!.admitting, false);
    let closed = false;
    const closing = f.core.readiness.close().then(() => { closed = true; }); await tick();
    assert.equal((await sweep).ready, false);
    assert.equal(closed, false, "the monitor must retain the failed exchange's physical permit");
    if (dependency === "NETWORK") {
      assert.equal(f.probes.length, 1); assert.equal(f.policies.length, 1);
      assert.equal(f.stats().owners, 1);
    }
    selected.release(); await closing;
    assert.equal(closed, true); assert.equal(f.stats().fatals, 0);
  });
}

test("closing readiness during a real held NETWORK exchange retains the physical probe permit", async t => {
  const f = await servingFixture(t, { skipReadiness: true }); f.holdNetworkReply(); f.holdNetworkClosure();
  const sweep = f.core.readiness.checkStartup(); await tick();
  let closed = false;
  const closing = f.core.readiness.close().then(() => { closed = true; }); await tick();
  assert.equal((await sweep).ready, false); assert.equal(closed, false);
  assert.equal(f.core.grants.snapshot().admitting, false);
  assert.equal(f.policies.length, 0); assert.equal(f.requests.length, 0);
  f.replyNetwork(); await tick(); assert.equal(closed, false);
  f.releaseNetwork(); await closing;
  assert.equal(closed, true); assert.equal(f.stats().fatals, 0);
});

test("cancelling a recurring catalog probe closes its exact session and retains physical cleanup", async t => {
  const f = await servingFixture(t); f.time.advance(5000); await tick();
  f.holdCatalog(); f.holdOwnerClose();
  const sweep = f.core.readiness.checkStartup(); await tick();
  assert.equal(f.stats().owners, 2);
  assert.equal(f.core.isAdmitting(), true);
  let rootClosed = false; void f.handle.closed.then(() => { rootClosed = true; });
  const closing = f.core.readiness.close(); await tick();
  assert.equal((await sweep).ready, false);
  assert.equal(f.core.isAdmitting(), false); assert.equal(rootClosed, false);
  f.releaseOwners(); await closing; await f.handle.closed;
  assert.equal(rootClosed, true); assert.equal(f.stats().fatals, 0);
});
