import test from "node:test";
import assert from "node:assert/strict";
import { create } from "@bufbuild/protobuf";
import { ReadinessCheckSchema, ReadinessCheckStatus, ReadinessReason, RuntimeLaunchContextSchema, encodeJson,
  type RuntimeLaunchContext } from "@apex/contracts";
import { materialFixture, now } from "../bootstrap/runtime-materials/fixture.js";
import { copyStageRole, disposeStageOwner, type StageOwner } from "../bootstrap/stage-owner.js";
import { ReadinessMonitor } from "../readiness.js";
import { CHECK_IDS } from "../readiness/types.js";
import { FakeTime, deferred } from "../stage-reader/fixture.js";
import { observeStageHealth } from "./owner.js";
import { observeFreshHealth } from "../../health-probe.js";
import { ReadinessReportCodec } from "../readiness/report-codec.js";
import { rawServer, response } from "../health-testing/raw-server.js";
import { isolateHealthTransport } from "./isolated-transport.js";

const tick = async () => { for (let i = 0; i < 50; i++) await Promise.resolve(); };
async function fixture(t: test.TestContext) {
  const f = await materialFixture(f => Object.assign(f.env, { APEX_MCP_MANAGED_BOOTSTRAP: "sealed-stage-v2",
    APEX_MCP_NETWORK_PROFILE: "isolated-bridge-v1", APEX_MCP_GUARD_ADDRESS: "10.96.0.3", APEX_MCP_NETWORK_BINDING_SHA256: "b".repeat(64) }));
  const time = new FakeTime(), controller = new AbortController();
  const clock = { now: () => ({ monotonicNs: time.time, unixUs: now + time.time / 1000n,
    resolutionNs: 1n, source: "observation test" }) };
  const monitor = new ReadinessMonitor({ configuration: f.stageOwner.documents.config,
    launchContext: encodeJson(RuntimeLaunchContextSchema, f.stageOwner.documents.launch as RuntimeLaunchContext),
    clock, scheduler: time, isCurrent: () => true, onFatal() { assert.fail("monitor fatal"); },
    owners: CHECK_IDS.map(id => ({ id, start: () => ({ cancel() {}, completion: Promise.resolve({
      check: create(ReadinessCheckSchema, { id, status: ReadinessCheckStatus.PASS, reason: ReadinessReason.OK }),
      validUntilMonotonicNs: 10_000_000_000n }) }) })) });
  const report = await monitor.checkStartup();
  t.after(async () => { disposeStageOwner(f.stageOwner); f.bootstrap.cancel(); await f.bootstrap.closed; await monitor.close(); });
  let calls = 0, fatals = 0, transportToken: Uint8Array | undefined;
  const options = { env: f.env as NodeJS.ProcessEnv, signal: controller.signal, onFatal() { fatals++; } };
  const deps = { clock, timers: time, bootstrap: () => f.bootstrap, async observe(input: Parameters<typeof import("../../health-probe.js").observeHealth>[0]) {
    calls++; transportToken = input.tokenBytes; assert.deepEqual(transportToken, Buffer.alloc(32, 8));
    assert.equal(input.deadlineMonotonicNs, 7_000_000_000n);
    return { report: input.codec.decode(input.codec.encode(report)), validUntilMonotonicNs: 10_000_000_000n };
  } };
  return { f, time, controller, report, options, deps, stats: () => ({ calls, fatals, transportToken }) };
}

test("genuine sealed stage yields canonical integer-microsecond report only after stage/token disposal and bootstrap closure", async t => {
  const f = await fixture(t), closed = deferred<void>();
  f.deps.bootstrap = () => ({ ...f.f.bootstrap, closed: closed.promise });
  let settled = false;
  const result = observeStageHealth(f.options, f.deps); void result.then(() => { settled = true; });
  await tick(); assert.equal(settled, false); assert.equal(f.stats().calls, 1);
  assert.deepEqual(f.stats().transportToken, Buffer.alloc(32));
  assert.throws(() => copyStageRole(f.f.stageOwner, "health-token"));
  closed.resolve(); const line = await result; assert.ok(line);
  assert.equal(line.includes("\n"), false); assert.ok(Buffer.byteLength(line) <= 8192);
  assert.equal(JSON.parse(line).observedAtUnixUs, now.toString());
  assert.equal(JSON.parse(line).target.generation, "9007199254740993");
  assert.equal(f.stats().fatals, 0);
});

for (const kind of ["forged", "wrong-env", "wrong-network", "revoked", "v1"] as const) {
  test(`${kind} stage selection fails before HTTP`, async t => {
    const f = await fixture(t);
    if (kind === "forged") f.deps.bootstrap = () => ({ ...f.f.bootstrap, result: Promise.resolve({ ...f.f.stageOwner } as StageOwner) });
    if (kind === "wrong-env") f.options.env = { ...f.options.env, APEX_RUNTIME_CONFIG_FILE: "/other" };
    if (kind === "wrong-network") f.options.env = { ...f.options.env, APEX_MCP_GUARD_ADDRESS: "10.96.0.11" };
    if (kind === "revoked") disposeStageOwner(f.f.stageOwner);
    if (kind === "v1") f.options.env = { ...f.options.env, APEX_MCP_MANAGED_BOOTSTRAP: "sealed-stage-v1" };
    const result = observeStageHealth(f.options, f.deps);
    await tick(); assert.equal(f.stats().calls, 0);
    // A forged returned owner cannot be disposed as genuine; no closure claim.
    if (kind === "forged") { assert.equal(f.stats().fatals, 1); }
    else assert.equal(await result, undefined);
  });
}

for (const kind of ["signal", "deadline", "fatal"] as const) {
  test(`${kind} during held bootstrap cleanup cannot publish or fabricate closure`, async t => {
    const f = await fixture(t), closed = deferred<void>();
    f.deps.bootstrap = () => ({ ...f.f.bootstrap, closed: closed.promise });
    if (kind === "fatal") f.deps.observe = async input => { input.onFatal!(); return { report: f.report, validUntilMonotonicNs: 10_000_000_000n }; };
    let settled = false; const result = observeStageHealth(f.options, f.deps); void result.then(() => { settled = true; });
    await tick();
    if (kind === "signal") f.controller.abort();
    if (kind === "deadline") f.time.advance(7000);
    await tick(); assert.equal(settled, false);
    if (kind !== "signal") assert.equal(f.stats().fatals, 1);
    closed.resolve(); await tick();
    if (kind === "signal") assert.equal(await result, undefined);
    else assert.equal(settled, false, "fatal is not proof that all physical operations closed");
  });
}

test("original budget is checked after physical disposal even before watchdog delivery", async t => {
  const f = await fixture(t), closed = deferred<void>();
  f.deps.bootstrap = () => ({ ...f.f.bootstrap, closed: closed.promise });
  const result = observeStageHealth(f.options, f.deps); await tick();
  f.time.time = 7_000_000_000n; closed.resolve();
  assert.equal(await result, undefined); assert.equal(f.stats().fatals, 0);
});

test("actual observation transport composes with genuine stage ownership and canonical report disposal", async t => {
  isolateHealthTransport(t);
  const f = await fixture(t);
  const codec = new ReadinessReportCodec({ config: f.f.stageOwner.documents.config, launch: f.f.stageOwner.documents.launch });
  const text = codec.encode(f.report);
  const server = await rawServer(t, socket => socket.end(response(text)));
  const result = await observeStageHealth(f.options, { ...f.deps, observe: observeFreshHealth });
  assert.equal(result, text); assert.equal(server.stats.requests, 1);
  assert.equal(server.stats.request.includes(`Authorization: Bearer ${Buffer.alloc(32, 8).toString("base64url")}`), true);
  assert.throws(() => copyStageRole(f.f.stageOwner, "health-token"));
  assert.ok(Object.values(f.f.stage.files).every(bytes => bytes.every(byte => byte === 0)));
  await server.close(); assert.equal(server.sockets.size, 0);
});

test("short dependency lease consumed by stage cleanup refuses output despite remaining owner budget", async t => {
  isolateHealthTransport(t);
  const f = await fixture(t), closed = deferred<void>(), observed = deferred<void>();
  f.deps.bootstrap = () => ({ ...f.f.bootstrap, closed: closed.promise });
  const codec = new ReadinessReportCodec({ config: f.f.stageOwner.documents.config, launch: f.f.stageOwner.documents.launch });
  const server = await rawServer(t, socket => socket.end(response(codec.encode(f.report), [], "200 OK", "7000")));
  const result = observeStageHealth(f.options, { ...f.deps, observe: async input => {
    const report = await observeFreshHealth(input); observed.resolve(); return report;
  } });
  await observed.promise;
  f.time.time = 7_000n; closed.resolve();
  assert.equal(await result, undefined);
  assert.equal(f.stats().fatals, 0);
  await server.close(); assert.equal(server.sockets.size, 0);
});
