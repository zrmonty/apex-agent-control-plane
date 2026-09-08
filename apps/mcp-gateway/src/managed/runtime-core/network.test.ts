import test from "node:test";
import assert from "node:assert/strict";
import { readBinding } from "../authority/grant-transport.js";
import { servingFixture, tick } from "./testing.js";

test("PREPARE core probes exact original NETWORK binding without evidence, reservation or upstream work", async t => {
  const f = await servingFixture(t, { prepareOnly: true });
  const started = f.time.now(), job = f.core.startNetworkReadiness(started, started + 2_000_000_000n);
  assert.deepEqual(await job.result, { validUntilMonotonicNs: started + 10_000_000_000n }); await job.closed;
  assert.equal(f.networkProbes.length, 1);
  assert.deepEqual(readBinding(f.networkProbes[0].binding), f.stage.documents.binding);
  assert.equal(f.networkProbes[0].nonce.length, 32);
  assert.equal(f.events.length, 0); assert.equal(f.authorizations.length, 0); assert.equal(f.requests.length, 0);
  assert.equal(f.probes.length, 0); assert.equal(f.core.grants.snapshot().activeCalls, 0);
  assert.equal(f.core.isAdmitting(), false);
});

test("core network probe uses protected stage network hash rather than trusting a matching-binding reply", async t => {
  const f = await servingFixture(t, { prepareOnly: true }); f.wrongNetwork();
  const job = f.core.startNetworkReadiness(f.time.now(), f.time.now() + 2_000_000_000n);
  await assert.rejects(job.result, /managed network readiness refused safely/); await job.closed;
  assert.equal(f.networkProbes.length, 1); assert.equal(f.core.isAdmitting(), false);
});

for (const reason of ["shutdown", "credential revocation"] as const) {
  test(`${reason} retains network probe physical ownership and refuses late readiness`, async t => {
    const f = await servingFixture(t, { prepareOnly: true }); f.holdNetworkReply(); f.holdNetworkClosure();
    const job = f.core.startNetworkReadiness(f.time.now(), f.time.now() + 2_000_000_000n);
    const rejected = assert.rejects(job.result, /managed network readiness refused safely/);
    if (reason === "shutdown") f.handle.cancel(); else f.revokeControl();
    await tick(); f.replyNetwork(); await rejected;
    let drained = false; void f.handle.closed.then(() => { drained = true; }); await tick();
    assert.equal(drained, false);
    assert.throws(() => f.core.startNetworkReadiness(f.time.now(), f.time.now() + 2_000_000_000n));
    assert.equal(f.networkProbes.length, 1);
    f.releaseNetwork(); await job.closed; await f.handle.closed;
    assert.equal(f.events.length, 0); assert.equal(f.core.isAdmitting(), false); assert.equal(f.stats().fatals, 0);
  });
}
