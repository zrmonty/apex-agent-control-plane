import assert from "node:assert/strict";
import type { TestContext } from "node:test";
import { ReadinessReason } from "@apex/contracts";
import { createClock } from "../../telemetry/clock.js";
import { startHealthServer, type HealthServer } from "../health-server.js";
import { completed } from "../readiness/report-codec/test-support.js";
import { bounded, peer, requestText, token, wire } from "./http.js";

export async function cachedLifecycle(t: TestContext): Promise<void> {
  const f = await completed(); t.after(() => f.monitor.close());
  const server = await startHealthServer({ codec: f.codec, state: f.monitor, tokenBytes: token(),
    clock: createClock(), onFatal: () => assert.fail("fatal") }); t.after(() => server.close());
  const initial = await requestText(wire()); assert.equal(initial.status, 200);
  const original = f.codec.decode(initial.body);
  assert.equal(original.target!.fencingToken, 9007199254740993n);
  assert.equal(original.observedAtUnixUs, 9007199254740993n);
  assert.equal(original.stages.length, 9);
  f.time.advance(9999999n);
  assert.equal((await requestText(wire())).body, initial.body, "GET cannot refresh observation or stages");
  assert.equal(f.stats.starts, 9);
  f.time.advance(10000000000n);
  const stale = await requestText(wire()); assert.equal(stale.status, 503);
  const expired = f.codec.decode(stale.body);
  assert.equal(expired.observedAtUnixUs, original.observedAtUnixUs);
  assert.deepEqual(expired.stages, original.stages);
  await f.monitor.close();
  assert.equal((await requestText(wire("/livez"))).status, 503);
  assert.equal(f.stats.starts, 9); assert.equal(f.stats.fatal, 0);
  await server.close();

  const fresh = await completed(); t.after(() => fresh.monitor.close());
  const currentServer = await startHealthServer({ codec: fresh.codec, state: fresh.monitor, tokenBytes: token(),
    clock: createClock(), onFatal: () => assert.fail("fatal") }); t.after(() => currentServer.close());
  const ready = await requestText(wire()); assert.equal(ready.status, 200);
  const beforeLoss = fresh.codec.decode(ready.body), readyNs = fresh.time.ns;
  assert.equal(beforeLoss.live, true); assert.equal(beforeLoss.ready, true);
  assert.equal(fresh.stats.starts, 9);
  // No time advance: observation and all owner leases remain live when binding is lost.
  fresh.stats.current = false;
  const lost = await requestText(wire()); assert.equal(lost.status, 503);
  const afterLoss = fresh.codec.decode(lost.body);
  assert.equal(afterLoss.live, true); assert.equal(afterLoss.ready, false);
  assert.equal(afterLoss.checks.length, 9);
  assert.ok(afterLoss.checks.every(check => check.reason === ReadinessReason.MISMATCH));
  assert.equal(afterLoss.observedAtUnixUs, beforeLoss.observedAtUnixUs);
  assert.deepEqual(afterLoss.stages, beforeLoss.stages);
  assert.equal(fresh.time.ns, readyNs);
  assert.equal(fresh.stats.starts, 9); assert.equal(fresh.stats.fatal, 0);
}

export async function emptyFailures(t: TestContext): Promise<void> {
  for (const mode of ["overflow", "snapshot", "codec"] as const) {
    const f = await completed(); t.after(() => f.monitor.close());
    if (mode === "overflow") f.codec.encode = () => "x".repeat(8193);
    if (mode === "codec") f.codec.encode = () => { throw new Error("HEALTH_CANARY"); };
    const server = await startHealthServer({ codec: f.codec, state: { snapshot() {
      if (mode === "snapshot") throw new Error("HEALTH_CANARY"); return f.monitor.snapshot();
    } }, tokenBytes: token(), clock: createClock(), onFatal: () => assert.fail("fatal") });
    t.after(() => server.close());
    const response = await requestText(wire());
    await server.close();
    assert.equal(response.status, 503, mode); assert.equal(response.body, "", mode);
    assert.ok(!response.raw.includes("HEALTH_CANARY"));
  }
}

export async function callbackFences(t: TestContext): Promise<void> {
  const failures: string[] = [];
  for (const mode of ["snapshot-close", "codec-close", "clock-close", "snapshot-deadline", "codec-deadline", "clock-backwards"] as const) {
    const f = await completed(); t.after(() => f.monitor.close());
    let server: HealthServer | undefined, closing: Promise<void> | undefined;
    let snapshots = 0, encodes = 0, ns = 1n, armed = true, calls = 0;
    const encode = f.codec.encode.bind(f.codec);
    const clock = { now() {
      calls++;
      if (mode === "clock-close" && armed && server) { armed = false; closing = server.close(); }
      if (mode === "clock-backwards" && calls > 1) ns = 0n;
      return { monotonicNs: ns, unixUs: 7n, resolutionNs: 1n, source: "transport-test" };
    } };
    f.codec.encode = report => {
      encodes++;
      if (mode === "codec-close") closing = server!.close();
      if (mode === "codec-deadline") ns += 2000000000n;
      return encode(report);
    };
    server = await startHealthServer({ codec: f.codec, state: { snapshot() {
      snapshots++;
      if (mode === "snapshot-close") closing = server!.close();
      if (mode === "snapshot-deadline") ns += 2000000000n;
      return f.monitor.snapshot();
    } }, tokenBytes: token(), clock, onFatal: () => assert.fail("fatal") });
    t.after(() => server!.close());
    const response = await requestText(wire());
    const close1 = server.close(), close2 = server.close();
    await close1;
    if (close1 !== close2 || (closing && closing !== close1) || response.status === 200 || response.body !== "" ||
      ((mode === "snapshot-close" || mode === "snapshot-deadline") && encodes !== 0) ||
      ((mode === "clock-close" || mode === "clock-backwards") && snapshots !== 0)) failures.push(mode);
  }
  assert.deepEqual(failures, [], "reentry/deadline cannot restore work ownership or write healthy data");
}

export async function connectionCap(t: TestContext): Promise<void> {
  const f = await completed(); t.after(() => f.monitor.close());
  let snapshots = 0;
  const server = await startHealthServer({ codec: f.codec, state: { snapshot() { snapshots++; return f.monitor.snapshot(); } },
    tokenBytes: token(), clock: createClock(), onFatal: () => assert.fail("fatal") }); t.after(() => server.close());
  const peers = [];
  for (let i = 0; i < 9; i++) peers.push(await peer(t));
  await bounded(peers[8].closed, 1000);
  assert.equal(peers[8].socket.closed, true, "ninth partial/unauthenticated socket refused");
  assert.ok(peers.slice(0, 8).every(p => !p.socket.closed)); assert.equal(snapshots, 0);
  const closing = server.close(); assert.equal(closing, server.close());
  await bounded(closing); await bounded(Promise.all(peers.map(p => p.closed)));
}

export async function absoluteIdle(t: TestContext): Promise<void> {
  const f = await completed(); t.after(() => f.monitor.close());
  let snapshots = 0;
  const server = await startHealthServer({ codec: f.codec, state: { snapshot() { snapshots++; return f.monitor.snapshot(); } },
    tokenBytes: token(), clock: createClock(), onFatal: () => assert.fail("fatal") }); t.after(() => server.close());
  const idle = await peer(t), trickle = await peer(t), started = performance.now();
  trickle.socket.write("GET /readyz HTTP/1.1\r\nX-Trickle: ");
  const timer = setInterval(() => trickle.socket.write("a"), 100); t.after(() => clearInterval(timer));
  await bounded(Promise.all([idle.closed, trickle.closed])); clearInterval(timer);
  assert.ok(performance.now() - started >= 1800, "actual default deadline, not a short test mode");
  assert.ok(performance.now() - started < 2900); assert.equal(snapshots, 0);
}
