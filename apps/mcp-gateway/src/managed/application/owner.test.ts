import test from "node:test";
import assert from "node:assert/strict";
import { Server } from "node:http";
import { EventEmitter } from "node:events";
import { createClock } from "../../telemetry/clock.js";
import { copyToken } from "../../health/token.js";
import { create } from "@bufbuild/protobuf";
import { ReadinessCheckSchema, ReadinessCheckStatus, ReadinessReason, RuntimeLaunchContextSchema,
  encodeJson, type RuntimeLaunchContext } from "@apex/contracts";
import { materialFixture, now } from "../bootstrap/runtime-materials/fixture.js";
import { jwks } from "../bootstrap/inbound-verifier/fixture.js";
import { assertRuntimeMaterialsStage, disposeRuntimeMaterials, type RuntimeMaterials } from "../bootstrap/runtime-materials.js";
import { disposeStageOwner } from "../bootstrap/stage-owner.js";
import { ReadinessMonitor } from "../readiness.js";
import { CHECK_IDS } from "../readiness/types.js";
import { FakeTime, deferred } from "../stage-reader/fixture.js";
import type { RuntimeCore } from "../runtime-core.js";
import { startHealthServer, type HealthServer, type HealthServerInput } from "../health-server.js";
import type { PendingCompletion } from "../call-owner.js";
import { fixture as readinessFixture } from "../readiness/report-codec/test-support.js";
import { startApplication } from "./owner.js";
import { runApplicationProcess } from "./process-owner.js";

const tick = async () => { for (let i = 0; i < 150; i++) await Promise.resolve(); };
// The actual factory must request its fixed endpoint. Isolate only the native
// test bind so parallel health-transport.test.ts still owns literal port 8081.
// The HTTP server, health owner, error handler and loss notification are real;
// only OS teardown is held when a test needs to withhold physical completion.
function actualHealth(t: test.TestContext) {
  const started = deferred<HealthServer>(), listen = Server.prototype.listen;
  let listener: Server, restoreClose: (() => void) | undefined;
  t.mock.method(Server.prototype, "listen", function (this: Server, ...args: unknown[]) {
    assert.equal(args[0], 8081); assert.equal(args[1], "127.0.0.1");
    listener = this; return Reflect.apply(listen, this, [0, ...args.slice(1)]);
  });
  return {
    ready: started.promise,
    async start(input: HealthServerInput) {
      try { const health = await startHealthServer(input); started.resolve(health); return health; }
      catch (error) { started.reject(error); throw error; }
    },
    fail() { listener.emit("error", Error("synthetic native listener failure")); },
    listening: () => listener.listening,
    holdClose() {
      const mocked = t.mock.method(listener, "close", function (this: Server) { return this; });
      restoreClose = () => mocked.mock.restore();
    },
    async releaseClose() {
      restoreClose?.(); restoreClose = undefined;
      if (listener?.listening) await new Promise<void>(resolve => listener.close(() => resolve()));
    },
  };
}
async function fixture(t: test.TestContext, options: { holdCoreClose?: boolean; holdHealthStart?: boolean; uncertainHealth?: boolean;
  realHealth?: boolean; holdIngressStart?: boolean; holdHandoff?: boolean; failedHealthCleanup?: boolean; rejectHealth?: boolean } = {}) {
  const f = await materialFixture(f => {
    Object.assign(f.env, { APEX_MCP_MANAGED_BOOTSTRAP: "sealed-stage-v2", APEX_MCP_NETWORK_PROFILE: "isolated-bridge-v1",
      APEX_MCP_GUARD_ADDRESS: "10.96.0.3", APEX_MCP_NETWORK_BINDING_SHA256: "b".repeat(64) });
    f.stage.files["inbound-jwks"] = jwks();
  });
  const time = new FakeTime(), order: string[] = [], coreClosed = deferred<void>(), revoked = deferred<void>();
  const coreHandoff = deferred<readonly PendingCompletion[]>(), ingressStarted = deferred<{ host: string; port: number }>();
  const nativeHealth = options.realHealth ? actualHealth(t) : undefined;
  const healthStarted = deferred<HealthServer>(); let monitor: ReadinessMonitor, materials: RuntimeMaterials, fatals = 0, sweeps = 0;
  const healthy = { lost: new Promise<void>(() => {}), close: async () => { order.push("health-close"); } };
  let healthBytes: Uint8Array | undefined;
  let admitting = () => false;
  let failSweep = false;
  const clock = { now: () => ({ monotonicNs: time.now(), unixUs: now + time.now() / 1000n,
    resolutionNs: 1000n, uncertaintyUs: 1n, source: "application owner fixture clock" }) };
  const handle = startApplication({ env: f.env, onFatal() { fatals++; } }, {
    clock, timers: time, bootstrap() { order.push("bootstrap"); return f.bootstrap; },
    core(input) {
      order.push("core"); materials = input.materials; assertRuntimeMaterialsStage(materials, f.stageOwner);
      monitor = new ReadinessMonitor({ configuration: f.stageOwner.documents.config,
        launchContext: encodeJson(RuntimeLaunchContextSchema, f.stageOwner.documents.launch as RuntimeLaunchContext),
        clock, scheduler: time, isCurrent: () => true, onFatal: input.onFatal,
        owners: CHECK_IDS.map(id => ({ id, start() {
          if (id === CHECK_IDS[0]) { sweeps++; order.push("sweep"); }
          return { completion: Promise.resolve({ check: create(ReadinessCheckSchema, {
            id, status: failSweep ? ReadinessCheckStatus.FAIL : ReadinessCheckStatus.PASS,
            reason: failSweep ? ReadinessReason.UNAVAILABLE : ReadinessReason.OK,
          }), validUntilMonotonicNs: time.now() + 10_000_000_000n }), cancel() {} };
        } })),
      });
      // Root-order/ownership fixture only; separate core tests exercise real
      // execution, authentication and nine concrete owners over actual TLS.
      const core = { readiness: monitor, isAdmitting: () => monitor.snapshot().ready,
        verifier: {}, executor: {} } as unknown as RuntimeCore;
      return { result: Promise.resolve(core), revoked: revoked.promise, closed: coreClosed.promise,
        completionHandoff: coreClosed.promise.then(() => options.holdHandoff ? coreHandoff.promise : []), cancel() {
          order.push("core-close"); revoked.resolve(); void monitor.close();
          if (!options.holdCoreClose) coreClosed.resolve();
        } };
    },
    health(input) {
      order.push("health"); assert.equal(input.state.observation().report.ready, false);
      assert.equal(input.codec.decode(input.codec.encode(input.state.observation().report)).ready, false);
      healthBytes = input.tokenBytes;
      const checked = copyToken(input.tokenBytes);
      assert.deepEqual(checked, Buffer.alloc(32, 8)); checked.fill(0);
      if (options.rejectHealth) return Promise.reject(Error("synthetic health startup refusal"));
      if (nativeHealth) return nativeHealth.start(input);
      if (options.uncertainHealth) {
        input.onFatal(); healthStarted.reject(Error("uncertain synthetic listener cleanup"));
      }
      if (!options.holdHealthStart) healthStarted.resolve(healthy);
      return healthStarted.promise;
    },
    ingress(input) {
      order.push("ingress"); assert.equal(input.isAdmitting(), false);
      admitting = input.isAdmitting;
      const closed = deferred<void>();
      if (!options.holdIngressStart) ingressStarted.resolve({ host: "10.96.0.2", port: 8080 });
      return { result: ingressStarted.promise, closed: closed.promise,
        cancel() { order.push("ingress-close"); ingressStarted.reject(Error("cancelled synthetic ingress")); closed.resolve(); } };
    },
  });
  t.after(async () => {
    handle.cancel(); coreClosed.resolve(); coreHandoff.resolve([]); healthStarted.resolve(healthy);
    await nativeHealth?.releaseClose();
    if (options.uncertainHealth || options.failedHealthCleanup) {
      // Simulated process termination, after any actual listener is closed.
      // Do not pretend its intentionally unproved application.closed settled.
      disposeRuntimeMaterials(materials); disposeStageOwner(f.stageOwner);
    } else await handle.closed;
    await f.bootstrap.closed;
  });
  return { handle, order, time, stage: f.stageOwner, get materials() { return materials; },
    get healthBytes() { return healthBytes; },
    health: nativeHealth, admitting: () => admitting(), releaseHandoff: coreHandoff.resolve,
    stats: () => ({ fatals, sweeps }), releaseCore: () => coreClosed.resolve(),
    releaseHealth: () => healthStarted.resolve(healthy),
    revoke: () => revoked.resolve(), failSweep() { failSweep = true; } };
}

test("root binds health and HTTPS before starting readiness and refreshes at the original five-second cadence", async t => {
  const f = await fixture(t);
  assert.deepEqual(await f.handle.result, { host: "10.96.0.2", port: 8080 });
  assert.deepEqual(f.order.slice(0, 5), ["bootstrap", "core", "health", "ingress", "sweep"]);
  assert.equal(f.stats().sweeps, 1);
  f.time.advance(4999); await tick(); assert.equal(f.stats().sweeps, 1);
  f.time.advance(1); await tick(); assert.equal(f.stats().sweeps, 2);
  f.handle.cancel(); await f.handle.closed;
  f.time.advance(10000); await tick(); assert.equal(f.stats().sweeps, 2);
  assert.equal(f.stats().fatals, 0);
});

test("shutdown closes listeners but retains genuine stage and material until core completion drains", async t => {
  const f = await fixture(t, { holdCoreClose: true }); await f.handle.result;
  f.handle.cancel(); await tick();
  assert.ok(f.order.includes("ingress-close")); assert.ok(f.order.includes("health-close"));
  assertRuntimeMaterialsStage(f.materials, f.stage);
  let closed = false; void f.handle.closed.then(() => { closed = true; }); await tick(); assert.equal(closed, false);
  f.releaseCore(); await f.handle.closed;
  assert.throws(() => assertRuntimeMaterialsStage(f.materials, f.stage)); assert.equal(closed, true);
});

test("root cancellation disposition reports only the call that initiates stop", async t => {
  const f = await fixture(t, { holdCoreClose: true }); await f.handle.result;
  assert.equal(f.handle.cancel(), true);
  assert.equal(f.handle.cancel(), false); assertRuntimeMaterialsStage(f.materials, f.stage);
  f.releaseCore(); await f.handle.closed; assert.equal(f.handle.cancel(), false);
});

for (const loss of ["health", "revocation", "signal-first"] as const) {
  test(`real root ${loss} preserves first stop classification through later signal and held closure/handoff`, async t => {
    const f = await fixture(t, { realHealth: true, holdCoreClose: true, holdHandoff: true });
    await f.handle.result;
    const events = new EventEmitter(), messages: string[] = [];
    let settled = false;
    const result = runApplicationProcess({}, () => f.handle, {
      on: events.on.bind(events), removeListener: events.removeListener.bind(events),
      report(message) { messages.push(message); }, terminate() { assert.fail("unexpected process termination"); },
    });
    void result.then(() => { settled = true; });
    if (loss === "signal-first") events.emit("SIGTERM");
    else if (loss === "health") f.health!.fail();
    else f.revoke();
    await tick(); assert.equal(f.admitting(), false);
    events.emit("SIGINT"); await tick();
    assert.equal(settled, false); assertRuntimeMaterialsStage(f.materials, f.stage);
    f.releaseCore(); await tick();
    assert.equal(settled, false); assertRuntimeMaterialsStage(f.materials, f.stage);
    f.releaseHandoff([]);
    assert.equal(await result, loss === "signal-first" ? 0 : 1);
    assert.deepEqual(messages, loss === "signal-first" ? [] : ["GOVERNANCE_UNAVAILABLE: managed application stopped safely"]);
    assert.equal(f.stats().fatals, 0); assert.deepEqual(await f.handle.completionHandoff, []);
    assert.throws(() => assertRuntimeMaterialsStage(f.materials, f.stage));
  });
}

test("cancellation during health startup retains its pending owner and closes a late listener before disposal", async t => {
  const f = await fixture(t, { holdHealthStart: true }); await tick();
  const rejected = assert.rejects(f.handle.result, /managed application refused safely/);
  f.handle.cancel(); await rejected; await tick();
  assertRuntimeMaterialsStage(f.materials, f.stage);
  let closed = false; void f.handle.closed.then(() => { closed = true; });
  f.time.advance(5000); await tick(); assert.equal(f.stats().fatals, 1); assert.equal(closed, false);
  f.releaseHealth(); await f.handle.closed;
  assert.equal(f.order.includes("ingress"), false); assert.ok(f.order.includes("health-close"));
  assert.deepEqual(f.healthBytes, Buffer.alloc(32));
  assert.throws(() => assertRuntimeMaterialsStage(f.materials, f.stage));
});

test("runtime revocation closes the application without allowing scheduled probes to restart", async t => {
  const f = await fixture(t); await f.handle.result; f.revoke(); await f.handle.closed;
  f.time.advance(10000); await tick(); assert.equal(f.stats().sweeps, 1);
  assert.ok(f.order.includes("ingress-close")); assert.ok(f.order.includes("health-close"));
  assert.equal(f.stats().fatals, 0);
});

test("a failed scheduled readiness sweep closes both listeners and cannot restart admission", async t => {
  const f = await fixture(t); await f.handle.result; f.failSweep();
  f.time.advance(5000); await f.handle.closed;
  assert.ok(f.order.includes("ingress-close")); assert.ok(f.order.includes("health-close"));
  f.time.advance(10000); await tick(); assert.equal(f.stats().sweeps, 2);
  assert.equal(f.stats().fatals, 0);
});

test("a late health-start reply cannot bypass the original startup deadline before timers poll", async t => {
  const f = await fixture(t, { holdHealthStart: true }); await tick();
  const rejected = assert.rejects(f.handle.result, /managed application refused safely/);
  f.time.time = 20_000_000_000n; // No due callback is delivered by this clock edit.
  f.releaseHealth(); await rejected; await f.handle.closed;
  assert.equal(f.order.includes("ingress"), false); assert.ok(f.order.includes("health-close"));
});

test("physical cleanup arriving at its original deadline reports fatal even before timer polling", async t => {
  const f = await fixture(t, { holdCoreClose: true }); await f.handle.result;
  f.handle.cancel(); await tick();
  f.time.time = 5_000_000_000n; // Actual closure is still awaited; timeout is not closure.
  f.releaseCore(); await f.handle.closed;
  assert.equal(f.stats().fatals, 1);
  assert.throws(() => assertRuntimeMaterialsStage(f.materials, f.stage));
});

test("health startup fatal rejection cannot masquerade as proof the unreturned listener closed", async t => {
  const f = await fixture(t, { uncertainHealth: true });
  await assert.rejects(f.handle.result, /managed application refused safely/); await tick();
  let closed = false; void f.handle.closed.then(() => { closed = true; }); await tick();
  assert.equal(f.stats().fatals, 1);
  assert.equal(closed, false);
  assertRuntimeMaterialsStage(f.materials, f.stage);
  assert.equal(f.order.includes("ingress"), false);
  assert.deepEqual(f.healthBytes, Buffer.alloc(32));
});

for (const rejectHealth of [false, true]) {
  test(`root supplies raw health token and wipes its copy after ${rejectHealth ? "startup refusal" : "startup success"}`, async t => {
    const f = await fixture(t, { rejectHealth });
    if (rejectHealth) await assert.rejects(f.handle.result, /managed application refused safely/);
    else await f.handle.result;
    assert.equal(f.healthBytes!.byteLength, 32);
    assert.deepEqual(f.healthBytes, Buffer.alloc(32));
  });
}

test("actual health error reports loss before its held physical listener closes", async t => {
  const f = readinessFixture(), native = actualHealth(t);
  const health = await native.start({ codec: f.codec, state: f.monitor, tokenBytes: Buffer.alloc(32, 7),
    clock: createClock(), onFatal: () => assert.fail("unexpected fatal") });
  t.after(async () => { await native.releaseClose(); await health.close(); await f.monitor.close(); });
  assert.ok(health.lost instanceof Promise, "fixed health factory must expose actual lifecycle loss");
  let lost = 0; void health.lost.then(() => { lost++; });
  await tick(); assert.equal(lost, 0);
  native.holdClose(); native.fail(); await tick();
  assert.equal(lost, 1); assert.equal(native.listening(), true);
  let closed = false; const closing = health.close().then(() => { closed = true; });
  await tick(); assert.equal(closed, false);
  native.fail(); await tick(); assert.equal(lost, 1);
  await native.releaseClose(); await closing;
  assert.equal(closed, true);
});

test("actual native health closure also reports listener loss", async t => {
  const f = readinessFixture(), native = actualHealth(t);
  const health = await native.start({ codec: f.codec, state: f.monitor, tokenBytes: Buffer.alloc(32, 7),
    clock: createClock(), onFatal: () => assert.fail("unexpected fatal") });
  t.after(async () => { await native.releaseClose(); await health.close(); await f.monitor.close(); });
  assert.ok(health.lost instanceof Promise);
  let lost = false; void health.lost.then(() => { lost = true; });
  await native.releaseClose(); await tick();
  assert.equal(lost, true); await health.close();
});

for (const pendingIngress of [true, false]) {
  test(`actual health self-close stops root ${pendingIngress ? "during ingress startup" : "after publication"} and retains closure/handoff`, async t => {
    const f = await fixture(t, { realHealth: true, holdIngressStart: pendingIngress, holdCoreClose: true, holdHandoff: true });
    await f.health!.ready; await tick();
    if (!pendingIngress) await f.handle.result;
    assert.equal(f.admitting(), !pendingIngress);
    assert.equal(f.stats().sweeps, pendingIngress ? 0 : 1);
    f.health!.fail(); await tick();
    assert.equal(f.admitting(), false);
    assert.ok(f.order.includes("core-close")); assert.ok(f.order.includes("ingress-close"));
    if (pendingIngress) await assert.rejects(f.handle.result, /managed application refused safely/);
    assert.equal(f.stats().sweeps, pendingIngress ? 0 : 1);
    let closed = false; void f.handle.closed.then(() => { closed = true; }); await tick();
    assert.equal(closed, false); assertRuntimeMaterialsStage(f.materials, f.stage);
    f.releaseCore(); await tick();
    assert.equal(closed, false); assertRuntimeMaterialsStage(f.materials, f.stage);
    const pending = Object.freeze([{ callId: "call-1", admissionId: "admission-1", state: "completion_pending" as const }]);
    f.releaseHandoff(pending); await f.handle.closed;
    assert.equal(await f.handle.completionHandoff, pending);
    assert.throws(() => assertRuntimeMaterialsStage(f.materials, f.stage));
    f.time.advance(10000); await tick();
    assert.equal(f.stats().sweeps, pendingIngress ? 0 : 1); assert.equal(f.stats().fatals, 0);
  });
}

test("actual failed health cleanup reports fatal without releasing root material or claiming physical closure", async t => {
  const f = await fixture(t, { realHealth: true, holdCoreClose: true, failedHealthCleanup: true });
  await f.handle.result;
  const health = await f.health!.ready;
  t.mock.timers.enable({ apis: ["setTimeout"] });
  f.health!.holdClose(); f.health!.fail(); await tick();
  assert.equal(f.admitting(), false);
  assert.ok(f.order.includes("core-close")); assert.ok(f.order.includes("ingress-close"));
  let closed = false; void f.handle.closed.then(() => { closed = true; });
  f.releaseCore(); await tick();
  assert.equal(closed, false); assert.equal(f.health!.listening(), true);
  assertRuntimeMaterialsStage(f.materials, f.stage);
  const refusedCleanup = assert.rejects(health.close(), /health transport rejected safely/);
  t.mock.timers.tick(5000); await refusedCleanup; await tick();
  assert.equal(f.stats().fatals, 1); assert.equal(closed, false);
  assert.equal(f.health!.listening(), true); assertRuntimeMaterialsStage(f.materials, f.stage);
  t.mock.timers.reset(); await f.health!.releaseClose(); await tick();
  assert.equal(closed, false, "a rejected health cleanup promise never becomes physical proof");
  assertRuntimeMaterialsStage(f.materials, f.stage);
});
