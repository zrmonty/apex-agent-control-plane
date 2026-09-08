import test from "node:test";
import assert from "node:assert/strict";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { ManagedDeploymentRenewalSchema, ManagedDeploymentGrantSchema, ManagedGrantMode } from "@apex/contracts";
import { materialFixture, now } from "../bootstrap/runtime-materials/fixture.js";
import { jwks } from "../bootstrap/inbound-verifier/fixture.js";
import { createManagedRuntimeMaterials, disposeRuntimeMaterials } from "../bootstrap/runtime-materials.js";
import { disposeStageOwner } from "../bootstrap/stage-owner.js";
import { FakeTime, deferred } from "../stage-reader/fixture.js";
import { startCore } from "./job.js";

async function setup(t: test.TestContext) {
  const f = await materialFixture(f => {
    Object.assign(f.env, { APEX_MCP_MANAGED_BOOTSTRAP: "sealed-stage-v2", APEX_MCP_NETWORK_PROFILE: "isolated-bridge-v1",
      APEX_MCP_GUARD_ADDRESS: "10.96.0.3", APEX_MCP_NETWORK_BINDING_SHA256: "b".repeat(64) });
    f.stage.files["inbound-jwks"] = jwks();
  });
  const materials = createManagedRuntimeMaterials(f.stageOwner, now), time = new FakeTime();
  t.after(async () => { disposeRuntimeMaterials(materials); disposeStageOwner(f.stageOwner); await f.bootstrap.closed; });
  const closed = deferred<void>(), revoked = deferred<void>();
  let connects = 0, cancels = 0, requests = 0, fatals = 0, mode = ManagedGrantMode.PREPARE, held = false;
  let validForUs = 10_000_000n, renewalReply: (() => void) | undefined;
  let holdRenewal = false;
  const control = { result: Promise.resolve({ authority: { start(method: string, bytes: Uint8Array) {
    assert.equal(method, "/apex.v1.ManagedRuntimeAuthority/RenewDeployment"); requests++;
    const request = fromBinary(ManagedDeploymentRenewalSchema, bytes);
    const bytesReply = toBinary(ManagedDeploymentGrantSchema, create(ManagedDeploymentGrantSchema, {
      binding: request.binding, nonce: request.nonce, renewalSequence: request.renewalSequence,
      decisionId: `018f3d4a-8b9c-7000-8000-${String(requests).padStart(12, "0")}`,
      epoch: 1n, mode, validForUs,
    }));
    const reply = deferred<Uint8Array>();
    if (holdRenewal) renewalReply = () => reply.resolve(bytesReply); else reply.resolve(bytesReply);
    const result = reply.promise;
    return { result, closed: Promise.resolve(), cancel() {} };
  } }, evidence: { start() { throw Error("readiness must never admit an event"); },
    startReadiness() { throw Error("this fixture starts no evidence probes"); } } }),
    closed: closed.promise, revoked: revoked.promise,
    cancel() { cancels++; revoked.resolve(); if (!held) closed.resolve(); } };
  const options = { stage: f.stageOwner, materials,
    clock: { now: () => ({ monotonicNs: time.now(), unixUs: now + time.now() / 1000n,
      resolutionNs: 1000n, source: "test high resolution clock", uncertaintyUs: 1n }) },
    onFatal() { fatals++; } };
  const deps = { timers: time, unixMs: () => Number(now / 1000n) + Number(time.now() / 1_000_000n),
    control() { connects++; return control; } };
  return { options, deps, time, closed, revoked, stats: () => ({ connects, cancels, requests, fatals }),
    hold() { held = true; }, serve() { mode = ManagedGrantMode.SERVE; },
    shortGrant() { validForUs = 2_500_000n; }, holdRenewal() { holdRenewal = true; },
    replyRenewal() { assert.ok(renewalReply); renewalReply(); } };
}
const tick = async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); };

test("core composes real owners in PREPARE without upstream calls or evidence and renews independently", async t => {
  const f = await setup(t), h = startCore(f.options, f.deps);
  t.after(async () => { h.cancel(); await h.closed; });
  const core = await h.result;
  assert.equal(core.grants.snapshot().mode, "prepare");
  assert.equal(core.grants.snapshot().admitting, false);
  assert.equal(typeof core.executor.start, "function");
  f.time.advance(2000); await tick();
  assert.equal(f.stats().requests, 2);
  h.cancel(); await h.closed;
  assert.equal(core.grants.snapshot().admitting, false);
  f.time.advance(20000); await tick();
  assert.equal(f.stats().requests, 2);
});

test("core revocation stops admission and retains physical control ownership past cleanup timeout", async t => {
  const f = await setup(t); f.hold(); f.serve();
  const h = startCore(f.options, f.deps), core = await h.result;
  assert.equal(core.grants.snapshot().mode, "serve");
  assert.equal(core.grants.snapshot().admitting, false, "this fixture has no completed readiness sweep");
  let drained = false; void h.closed.then(() => { drained = true; });
  f.revoked.resolve(); await tick();
  assert.equal(core.grants.snapshot().admitting, false);
  assert.equal(drained, false);
  f.time.advance(5000); await tick();
  assert.equal(f.stats().fatals, 1);
  assert.equal(drained, false);
  f.closed.resolve(); await h.closed;
  assert.equal(drained, true);
});

test("core rejects fabricated stage provenance before opening control channels", async t => {
  const f = await setup(t);
  const h = startCore({ ...f.options, stage: { ...f.options.stage } }, f.deps);
  await assert.rejects(h.result, /refused safely/); await h.closed;
  assert.equal(f.stats().connects, 0);
});

test("an expired applied grant closes the core before a late timer can renew and resurrect sessions", async t => {
  const f = await setup(t); f.serve();
  const h = startCore(f.options, f.deps); const core = await h.result;
  t.after(async () => { h.cancel(); await h.closed; });
  let revoked = false; void h.revoked.then(() => { revoked = true; });
  f.time.advance(10000); await tick();
  assert.equal(revoked, true);
  assert.equal(core.grants.snapshot().admitting, false);
  assert.equal(f.stats().requests, 1);
});

test("material disposal invalidates the live root without retaining stale credentials", async t => {
  const f = await setup(t); const h = startCore(f.options, f.deps); const core = await h.result;
  disposeRuntimeMaterials(f.options.materials);
  assert.equal(core.isAdmitting(), false);
  await h.revoked; await h.closed;
  assert.equal(f.stats().cancels, 1);
});

test("close during channel startup holds the core until the actual channel closes", async t => {
  const f = await setup(t), result = deferred<Awaited<ReturnType<typeof f.deps.control>["result"]>>();
  const channel = f.deps.control(); f.hold();
  const h = startCore(f.options, { ...f.deps, control: () => ({ ...channel, result: result.promise }) });
  await tick(); h.cancel(); await assert.rejects(h.result);
  let drained = false; void h.closed.then(() => { drained = true; });
  result.resolve(await channel.result); await tick();
  assert.equal(drained, false); assert.equal(f.stats().requests, 0);
  f.closed.resolve(); await h.closed;
  assert.equal(drained, true);
});

for (const physical of ["prompt", "held"] as const) {
  test(`pending control startup is cancelled immediately with ${physical} physical closure and no completion retention`, async t => {
    const f = await setup(t), result = deferred<Awaited<ReturnType<typeof f.deps.control>["result"]>>();
    const channel = f.deps.control();
    if (physical === "held") f.hold();
    const h = startCore(f.options, { ...f.deps, control: () => ({ ...channel, result: result.promise,
      cancel() { result.reject(Error("synthetic startup cancellation")); channel.cancel(); },
    }) });
    let drained = false, handedOff = false;
    void h.closed.then(() => { drained = true; });
    void h.completionHandoff.then(() => { handedOff = true; });
    try {
      await tick(); assert.equal(f.stats().requests, 0);
      h.cancel();
      assert.equal(f.stats().cancels, 1, "no coordinator exists to justify retaining the startup connection");
      await assert.rejects(h.result, /refused safely/); await tick();
      assert.equal(drained, physical === "prompt"); assert.equal(handedOff, drained);
      if (physical === "held") {
        f.time.advance(4999); await tick();
        assert.equal(drained, false); assert.equal(handedOff, false); assert.equal(f.stats().fatals, 0);
        f.closed.resolve();
      }
      await h.closed; assert.deepEqual(await h.completionHandoff, []);
      f.time.advance(10001); await tick();
      assert.equal(f.stats().fatals, 0); assert.equal(f.stats().requests, 0); assert.equal(f.stats().cancels, 1);
    } finally {
      result.reject(Error("synthetic test cleanup")); f.closed.resolve(); h.cancel(); await h.closed;
    }
  });
}

for (const source of ["timer", "exposed grants.renew()"] as const) {
  test(`${source}: replacement received at t2.6 cannot bridge predecessor expiry at t2.5 before watcher t3`, async t => {
    const f = await setup(t); f.serve(); f.shortGrant();
    const h = startCore(f.options, f.deps), core = await h.result;
    t.after(async () => { h.cancel(); await h.closed; });
    let revoked = false; void h.revoked.then(() => { revoked = true; });
    f.holdRenewal();
    // In the exposed case move the clock without firing the timer or watcher.
    if (source === "timer") f.time.advance(2000); else f.time.time = 2_000_000_000n;
    const renewal = source === "timer" ? undefined : core.grants.renew();
    await tick(); assert.equal(f.stats().requests, 2);
    f.time.time = 2_600_000_000n;
    f.replyRenewal(); await tick();
    assert.equal(revoked, true);
    if (renewal) assert.equal(await renewal, false);
    assert.equal(core.grants.snapshot().admitting, false);
    assert.equal(await core.grants.renew(), false);
    assert.equal(f.stats().requests, 2);
  });
}
