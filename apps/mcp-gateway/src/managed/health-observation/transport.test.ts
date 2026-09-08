import test from "node:test";
import assert from "node:assert/strict";
import { Socket } from "node:net";
import * as probe from "../../health-probe.js";
import { createClock } from "../../telemetry/clock.js";
import { completed } from "../readiness/report-codec/test-support.js";
import { rawServer, response } from "../health-testing/raw-server.js";
import { token } from "../health-testing/http.js";
import { isolateHealthTransport } from "./isolated-transport.js";

test("observation returns the bound report, not just status, after actual socket close", async t => {
  isolateHealthTransport(t);
  assert.equal(typeof probe.observeHealth, "function");
  const f = await completed(); t.after(() => f.monitor.close());
  const server = await rawServer(t, socket => socket.end(response(f.codec.encode(f.report))));
  const report = await probe.observeHealth({ codec: f.codec, clock: createClock(), tokenBytes: token() });
  assert.deepEqual(report, f.report); await server.close(); assert.equal(server.sockets.size, 0);
});

for (const mode of ["release", "late", "failed", "expired-lease"] as const) {
  test(`held client physical close: ${mode} cannot publish prematurely`, async t => {
    const isolation = isolateHealthTransport(t);
    assert.equal(typeof probe.observeHealth, "function");
    const f = await completed(); t.after(() => f.monitor.close());
    const server = await rawServer(t, socket => socket.end(response(f.codec.encode(f.report), [], "200 OK",
      mode === "expired-lease" ? "7000" : "10000000000")));
    const emit = Socket.prototype.emit;
    let owned: Socket | undefined, restore: (() => void) | undefined, attempted!: () => void;
    const closing = new Promise<void>(done => { attempted = done; });
    t.mock.method(Socket.prototype, "emit", function (this: Socket, event: string | symbol, ...args: unknown[]) {
      if (event === "connect" && this.remotePort === isolation.port()) {
        owned = this; const destroy = this.destroy.bind(this);
        this.destroy = () => { attempted(); return this; };
        restore = () => { this.destroy = destroy; destroy(); };
      }
      return Reflect.apply(emit, this, [event, ...args]);
    });
    t.after(() => restore?.());
    let ns = 1n, fatal = 0, settled = false;
    const result = probe.observeHealth({ codec: f.codec, tokenBytes: token(), onFatal() { fatal++; },
      clock: { now: () => ({ monotonicNs: ns, unixUs: 1n, resolutionNs: 1n, source: "test" }) } });
    void result.then(() => { settled = true; });
    await closing; await new Promise(done => setTimeout(done, 30));
    assert.equal(settled, false); assert.equal(owned!.closed, false);
    if (mode !== "failed") {
      if (mode === "late") ns += 2_000_000_000n;
      if (mode === "expired-lease") ns += 7_000n;
      restore!();
    }
    assert.deepEqual(await result, mode === "release" ? f.report : undefined);
    assert.equal(fatal, mode === "failed" ? 1 : 0);
    if (mode === "failed") { assert.equal(owned!.closed, false); restore!(); }
    await server.close();
  });
}

test("malformed report and elapsed original whole-observation deadline never return metadata", async t => {
  isolateHealthTransport(t);
  assert.equal(typeof probe.observeHealth, "function");
  const f = await completed(); t.after(() => f.monitor.close());
  const server = await rawServer(t, socket => socket.end(response("{}")));
  assert.equal(await probe.observeHealth({ codec: f.codec, tokenBytes: token(), clock: createClock() }), undefined);
  assert.equal(await probe.observeHealth({ codec: f.codec, tokenBytes: token(), clock: createClock(), deadlineMonotonicNs: 0n }), undefined);
  assert.equal(server.stats.requests, 1);
});
