import assert from "node:assert/strict";
import test from "node:test";
import { startOwnedStage, type BootstrapOptions } from "./job.js";
import { ownerFixture, tick, isStatic } from "./fixture.js";
import { copyStageRole, disposeStageOwner } from "../stage-owner.js";

test("invalid ENV and active public options refuse before the loader", async () => {
  let hooks = 0;
  const bad = () => { hooks++; throw new Error("SECRET-CANARY"); };
  const f = ownerFixture();
  for (const input of [{ ...f, env: {} }, { ...f, onFatal: undefined }, { get env() { return bad(); }, onFatal() {} },
    new Proxy(f, { get: bad, getOwnPropertyDescriptor: bad })]) {
    const h = startOwnedStage(input as BootstrapOptions, f.load, f.time, f.gate);
    await assert.rejects(h.result, isStatic); await h.closed; assert.equal(f.counts.loads, 0);
  }
  assert.equal(hooks, 0);
});
test("invalid joined document disposes all bytes but waits for physical close", async () => {
  const f = ownerFixture(); f.stage.files["tool-bindings.json"] = Buffer.from("{}");
  const h = startOwnedStage(f, f.load, f.time, f.gate); f.result.resolve(f.material);
  await assert.rejects(h.result, isStatic); assert.equal(f.counts.disposals, 1);
  let closed = false; void h.closed.then(() => { closed = true; }); await tick(); assert.equal(closed, false);
  const blocked = startOwnedStage(f, f.load, f.time, f.gate); await assert.rejects(blocked.result, isStatic);
  assert.equal(f.counts.loads, 1); f.closed.resolve(); await h.closed;
});
test("cancellation before dispatch starts no loader", async () => {
  const f = ownerFixture(), h = startOwnedStage(f, f.load, f.time, f.gate); h.cancel(); h.cancel();
  await assert.rejects(h.result, isStatic); await h.closed; assert.equal(f.counts.loads, 0);
});
for (const closeFirst of [false, true]) {
  test(`pending cancel contains late success and requires both conditions (closeFirst=${closeFirst})`, async () => {
    const f = ownerFixture(), h = startOwnedStage(f, f.load, f.time, f.gate); await tick();
    h.cancel(); h.cancel(); await assert.rejects(h.result, isStatic); assert.equal(f.counts.cancels, 1);
    let closed = false; void h.closed.then(() => { closed = true; });
    if (closeFirst) f.closed.resolve(); else f.result.resolve(f.material);
    await tick(); assert.equal(closed, false); assert(f.gate && "held" in f.gate);
    if (closeFirst) f.result.resolve(f.material); else f.closed.resolve();
    await h.closed; assert.equal(f.counts.disposals, 1);
    for (const bytes of Object.values(f.stage.files)) assert(bytes.every(b => b === 0));
  });
}
test("OS closure and elapsed time do not free successfully published material", async () => {
  const f = ownerFixture(), h = startOwnedStage(f, f.load, f.time, f.gate);
  f.result.resolve(f.material); f.closed.resolve(); const owner = await h.result;
  f.time.advance(1000000);
  const blocked = startOwnedStage(f, f.load, f.time, f.gate); await assert.rejects(blocked.result, isStatic);
  assert.equal(f.counts.loads, 1); assert(copyStageRole(owner, "instance-proof").some(b => b !== 0));
  disposeStageOwner(owner); await h.closed;
  const next = ownerFixture(), second = startOwnedStage(next, next.load, next.time, f.gate);
  next.result.resolve(next.material); next.closed.resolve(); await second.result; second.cancel(); await second.closed;
  assert.equal(next.counts.loads, 1);
});
test("explicit disposal before loader.close revokes but cannot release the slot", async () => {
  const f = ownerFixture(), h = startOwnedStage(f, f.load, f.time, f.gate); f.result.resolve(f.material);
  const owner = await h.result; disposeStageOwner(owner);
  assert.throws(() => copyStageRole(owner, "workload-key"), isStatic);
  let closed = false; void h.closed.then(() => { closed = true; }); await tick(); assert.equal(closed, false);
  f.closed.resolve(); await h.closed;
});
test("reader reentry/cancel during dispatch still adopts both promises and late material", async () => {
  const f = ownerFixture(); let blocked!: Promise<unknown>;
  const h = startOwnedStage(f, options => {
    blocked = assert.rejects(startOwnedStage(f, f.load, f.time, f.gate).result, isStatic);
    h.cancel(); return f.load(options);
  }, f.time, f.gate);
  await assert.rejects(h.result, isStatic); await blocked;
  f.result.resolve(f.material); f.closed.resolve(); await h.closed;
  assert.equal(f.counts.cancels, 1); assert.equal(f.counts.disposals, 1);
});
test("disposal revokes before callback reentry and is exactly once", async () => {
  const f = ownerFixture(), h = startOwnedStage(f, f.load, f.time, f.gate);
  f.result.resolve({ ...f.material, dispose() {
    assert.throws(() => copyStageRole(owner, "governance-key"), isStatic);
    disposeStageOwner(owner); h.cancel(); f.material.dispose();
  } });
  f.closed.resolve(); const owner = await h.result; disposeStageOwner(owner); await h.closed;
  assert.equal(f.counts.disposals, 1);
});
test("uncertain close and throwing trusted fatal callback never synthesize closure", async () => {
  const f = ownerFixture(), h = startOwnedStage({ ...f, onFatal() { f.onFatal(); throw new Error("SECRET-CANARY"); } }, f.load, f.time, f.gate);
  await tick(); f.result.reject(new Error("SECRET-CANARY")); f.closed.reject(new Error("SECRET-CANARY"));
  await assert.rejects(h.result, isStatic); await tick(); assert.equal(f.counts.fatals, 1);
  f.options().onFatal(); assert.equal(f.counts.fatals, 1); f.time.advance(1000000);
  let closed = false; void h.closed.then(() => { closed = true; }); await tick(); assert.equal(closed, false);
  await assert.rejects(startOwnedStage(f, f.load, f.time, f.gate).result, isStatic);
});
test("failed wipe retains ownership and invokes trusted fatal once", async () => {
  const f = ownerFixture(), h = startOwnedStage(f, f.load, f.time, f.gate);
  f.result.resolve({ ...f.material, dispose() { throw new Error("SECRET-CANARY"); } }); f.closed.resolve();
  const owner = await h.result; disposeStageOwner(owner); disposeStageOwner(owner);
  assert.equal(f.counts.fatals, 1); assert.throws(() => copyStageRole(owner, "evidence-key"), isStatic);
  let closed = false; void h.closed.then(() => { closed = true; }); await tick(); assert.equal(closed, false);
  await assert.rejects(startOwnedStage(f, f.load, f.time, f.gate).result, isStatic);
  f.material.dispose(); // Test fixture cleanup is not an owner closure claim.
});
test("loader rejection is contained before a throwing post-dispatch clock", async () => {
  const f = ownerFixture(); let calls = 0;
  f.time.now = () => { if (++calls === 5) throw new Error("CLOCK-CANARY"); return 0n; };
  const h = startOwnedStage(f, options => {
    f.result.reject(new Error("REJECTION-CANARY")); f.closed.resolve(); return f.load(options);
  }, f.time, f.gate);
  await assert.rejects(h.result, isStatic); await h.closed; await tick(); assert.equal(f.counts.cancels, 1);
});
