import assert from "node:assert/strict";
import type { TestContext } from "node:test";
import { GatewayError } from "../../contracts.js";
import { probeHealth } from "../../health-probe.js";
import { createClock } from "../../telemetry/clock.js";
import { ReadinessMonitor } from "../readiness.js";
import { ReadinessReportCodec } from "../readiness/report-codec.js";
import { completed } from "../readiness/report-codec/test-support.js";
import { controlled, flush, setup, pass } from "../readiness/test-support.js";
import { startHealthServer } from "../health-server.js";
import { peer, requestText, token, wire } from "./http.js";

export async function byteEdgesAndPipeline(t: TestContext): Promise<void> {
  const f = await completed(); t.after(() => f.monitor.close()); let snapshots = 0;
  const server = await startHealthServer({ codec: f.codec, state: { snapshot() { snapshots++; return f.monitor.snapshot(); } },
    tokenBytes: token(), clock: createClock(), onFatal: () => assert.fail("fatal") }); t.after(() => server.close());
  const base = wire().replace("\r\n\r\n", "\r\nX-Pad: \r\n\r\n");
  assert.equal((await requestText(base.replace("X-Pad: ", `X-Pad: ${"a".repeat(4096 - Buffer.byteLength(base))}`))).status, 200);
  const headers32 = wire().replace("\r\n\r\n", `\r\n${Array.from({ length: 29 }, (_, i) => `X-${i}: a`).join("\r\n")}\r\n\r\n`);
  assert.equal((await requestText(headers32)).status, 200);
  const before = snapshots, pipelined = await requestText(wire() + wire());
  assert.ok(snapshots - before <= 1); assert.ok((pipelined.raw.match(/HTTP\/1\.1/g) ?? []).length <= 1);
  const slow = await peer(t); slow.socket.pause(); slow.socket.write(wire());
  await server.close(); slow.socket.resume();
  await slow.closed;
  assert.equal(f.stats.fatal, 0);
}

export async function bindingCollision(t: TestContext): Promise<void> {
  const f = await completed(); t.after(() => f.monitor.close());
  const input = { codec: f.codec, state: f.monitor, tokenBytes: token(), clock: createClock(), onFatal: () => assert.fail("fatal") };
  const first = await startHealthServer(input); t.after(() => first.close());
  await assert.rejects(startHealthServer(input), (error: unknown) => error instanceof GatewayError &&
    error.message === "INVALID_INPUT: health transport rejected safely" && error.cause === undefined);
  assert.equal((await requestText(wire())).status, 200, "collision never kills or takes over the existing listener");
}

export async function preciseStages(t: TestContext): Promise<void> {
  const f = controlled(), monitor = new ReadinessMonitor(f.options); t.after(() => monitor.close());
  const checking = monitor.checkStartup();
  for (const [id, ns] of [[1, 999n], [5, 1000n], [6, 7000n], [7, 999000n]] as const) {
    f.time.advance(ns); f.release(id); await flush();
  }
  for (const id of [2, 3, 4, 8, 9]) { f.release(id); await flush(); }
  assert.equal((await checking).ready, true);
  const codec = new ReadinessReportCodec({ config: f.options.configuration, launch: f.launch });
  const clock = createClock(), server = await startHealthServer({ codec, state: monitor, tokenBytes: token(), clock,
    onFatal: () => assert.fail("fatal") }); t.after(() => server.close());
  const report = codec.decode((await requestText(wire())).body);
  assert.equal(report.observedAtUnixUs, 9007199254742000n);
  for (const [index, ns, us] of [[0, 999n, 0n], [4, 1000n, 1n], [5, 7000n, 7n], [6, 999000n, 999n]] as const) {
    assert.equal(report.stages[index].durationNs, ns); assert.equal(report.stages[index].durationUs, us);
    assert.equal(report.stages[index].clockUncertaintyUs, 7n);
  }
  assert.equal(await probeHealth({ codec, tokenBytes: token(), clock }), 0);
}

export async function leaseExpiry(t: TestContext): Promise<void> {
  const f = setup();
  const monitor = new ReadinessMonitor({ ...f.options, owners: f.owners.map(owner => ({ id: owner.id, start() {
    f.stats.starts++;
    return { completion: Promise.resolve(pass(owner.id, f.time.ns + 10000000n)), cancel() {} };
  } })) }); t.after(() => monitor.close());
  const ready = await monitor.checkStartup(); assert.equal(ready.ready, true);
  const codec = new ReadinessReportCodec({ config: f.options.configuration, launch: f.launch });
  const server = await startHealthServer({ codec, state: monitor, tokenBytes: token(), clock: createClock(),
    onFatal: () => assert.fail("fatal") }); t.after(() => server.close());
  assert.equal((await requestText(wire())).status, 200);
  f.time.advance(10000000n); // Owner's 10ms lease, well before the 10s observation cap.
  const response = await requestText(wire()); assert.equal(response.status, 503);
  const expired = codec.decode(response.body);
  assert.equal(expired.observedAtUnixUs, ready.observedAtUnixUs); assert.deepEqual(expired.stages, ready.stages);
  assert.equal(f.stats.starts, 9);
}
