import assert from "node:assert/strict";
import { createServer, createConnection, type Socket } from "node:net";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { ReadinessCheckId, ReadinessReason } from "@apex/contracts";
import { createClock } from "../../telemetry/clock.js";
import { runNode } from "../../testing/node-runner.js";
import { ReadinessMonitor, type ProbeOwner, type ProbeResult } from "../readiness.js";
import { failed } from "./evidence.js";
import { CHECK_IDS } from "./types.js";
import { setup, pass } from "./test-support.js";

test("real asynchronous loopback probe closes its socket before releasing readiness shutdown ownership", { timeout: 3000 }, async t => {
  const f = setup(), clock = createClock();
  const sockets = new Set<Socket>();
  let received!: () => void;
  const request = new Promise<void>(resolve => { received = resolve; });
  const server = createServer(socket => {
    sockets.add(socket); socket.on("error", () => {});
    socket.once("data", () => received()); // Actual asynchronous, non-mutating fixture request.
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address(); assert.ok(address && typeof address !== "string");
  let client: Socket | undefined, terminated = false, cancels = 0;
  let monitor: ReadinessMonitor | undefined;
  t.after(async () => {
    client?.destroy(); for (const socket of sockets) socket.destroy();
    await new Promise<void>(resolve => server.close(() => resolve()));
    await monitor?.close();
  });
  const owners: ProbeOwner[] = CHECK_IDS.map(id => ({ id, start: () => {
    if (id !== ReadinessCheckId.NETWORK) return { completion: Promise.resolve(pass(id, clock.now().monotonicNs + 10000000000n)), cancel: () => {} };
    const socket = client = createConnection({ host: "127.0.0.1", port: address.port });
    socket.on("error", () => {});
    socket.once("connect", () => socket.write("probe"));
    const completion = new Promise<ProbeResult>(resolve => socket.once("close", () => {
      terminated = true;
      resolve({ check: failed(id, ReadinessReason.CANCELLED), validUntilMonotonicNs: 0n });
    }));
    return { completion, cancel: () => {
      assert.equal(monitor!.snapshot().live, false, "invalidation precedes cancellation callback");
      cancels++; socket.destroy();
    } };
  } }));
  monitor = new ReadinessMonitor({ ...f.options, owners, clock, scheduler: undefined });
  const running = monitor.checkStartup();
  await request;
  assert.equal(terminated, false);
  await monitor.close();
  assert.equal(cancels, 1);
  assert.equal(terminated, true);
  assert.equal(client?.destroyed, true);
  assert.equal((await running).ready, false);
  assert.equal(f.stats.fatal, 0);
});

test("direct-child watchdog observes real unresponsive socket work trigger fatal and process exit", async () => {
  const result = await runNode({ cwd: fileURLToPath(new URL("../../../", import.meta.url)),
    entrypoint: "src/managed/readiness/watchdog-child.ts", env: process.env, timeoutMs: 3000 });
  assert.equal(result.code, 73, "fixture safety fuse or runner timeout is NOT the required fatal outcome");
  assert.equal(result.stderr.byteLength, 0);
  assert.deepEqual(JSON.parse(result.stdout.toString("utf8")), { fatal: true, ready: false, cancellations: 1, connected: true });
  assert.equal(result.reaped, true);
  assert.throws(() => process.kill(result.pid!, 0), { code: "ESRCH" });
});
