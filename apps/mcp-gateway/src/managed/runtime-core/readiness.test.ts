import test from "node:test";
import assert from "node:assert/strict";
import { servingFixture, tick } from "./testing.js";

test("healthy recurring readiness preserves admission and an active business exchange", async t => {
  const f = await servingFixture(t); f.holdCalls();
  const call = f.start(); await tick();
  assert.equal(f.requests.filter(r => r.method === "tools/call").length, 1);
  const sweep = f.core.prepareUpstream(f.timing()); void sweep.catch(() => {});
  assert.equal(f.core.isAdmitting(), true);
  await sweep;
  assert.equal(f.core.isAdmitting(), true);
  assert.equal(f.core.grants.snapshot().activeCalls, 1);
  f.reply(); assert.equal((await call.result).structuredContent.portfolioId, "p-1"); await call.closed;
  assert.equal(f.authorizations.length, 1); assert.equal(f.events.length, 1);
  assert.equal(f.stats().openOwners, 1);
});

test("authorization completing during a held readiness catalog still dispatches on the ready serving session", async t => {
  const f = await servingFixture(t); f.holdAuthorization();
  const call = f.start(); await tick(); assert.equal(f.authorizations.length, 1);
  f.holdCatalog(); const sweep = f.core.prepareUpstream(f.timing()); void sweep.catch(() => {}); await tick();
  f.authorize(); await tick();
  assert.equal(f.requests.filter(r => r.method === "tools/call").length, 1);
  assert.equal((await call.result).structuredContent.portfolioId, "p-1"); await call.closed;
  assert.equal(f.core.isAdmitting(), true);
  f.reply(); await sweep;
  assert.equal(f.stats().openOwners, 1);
});

test("concurrent sweeps coalesce through physical cleanup and repeated sweeps retire only their probe sessions", async t => {
  const f = await servingFixture(t);
  for (let i = 0; i < 8; i++) {
    f.holdOwnerClose();
    const sweep = f.core.prepareUpstream(f.timing()); void sweep.catch(() => {}); await tick();
    const coalesced = f.core.prepareUpstream(f.timing()); void coalesced.catch(() => {});
    assert.equal(coalesced, sweep);
    let settled = false; void sweep.then(() => { settled = true; }, () => {});
    await tick(); assert.equal(settled, false);
    assert.equal(f.core.isAdmitting(), true);
    f.releaseOwners(); await sweep;
    assert.equal(f.stats().openOwners, 1);
  }
  assert.equal(f.stats().owners, 9);
  assert.deepEqual(f.requests.filter(r => r.method === "DELETE").map(r => r.owner), [2, 3, 4, 5, 6, 7, 8, 9]);
  assert.equal(f.authorizations.length, 0); assert.equal(f.events.length, 0);
});

test("probe cleanup timeout reports fatal but cannot fabricate physical root closure", async t => {
  const f = await servingFixture(t); f.holdOwnerClose();
  const sweep = f.core.prepareUpstream(f.timing()); void sweep.catch(() => {}); await tick();
  let closed = false; void f.handle.closed.then(() => { closed = true; });
  f.time.advance(5000); await tick();
  assert.equal(f.stats().fatals, 1); assert.equal(f.core.isAdmitting(), false); assert.equal(closed, false);
  f.releaseOwners(); await sweep.catch(() => {}); await f.handle.closed;
  assert.equal(closed, true);
});
