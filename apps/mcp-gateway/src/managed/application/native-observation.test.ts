import test from "node:test";
import assert from "node:assert/strict";
import { createServer, connect } from "node:net";
import { once } from "node:events";
import { assertRefresh, observePending, cleanupFixture } from "./native-observation.js";
import { create } from "@bufbuild/protobuf";
import { ReadinessReportSchema, ReadinessCheckStatus } from "@apex/contracts";

function report(at: bigint) {
  return create(ReadinessReportSchema, { ready: true, observedAtUnixUs: at + 100_000n,
    checks: Array.from({ length: 9 }, (_, i) => ({ id: i + 1, status: ReadinessCheckStatus.PASS })),
    stages: ["config", "launch", "material", "inbound_auth", "network", "upstream_catalog", "governance", "evidence_admission", "admission"]
      .map(name => ({ name: `readiness.${name}`, startedAtUnixUs: at, durationNs: 100_000_000n })) });
}
test("refresh requires newer completed nine-check anchors and monotonic cadence", () => {
  const first = report(1_000_000n), next = report(6_000_000n);
  assertRefresh(first, next, [1_000_000_000n, 5_950_000_000n]); // 50ms phase variation is valid.
  assert.throws(() => assertRefresh(first, first, [0n, 5_000_000_000n]));
  assert.throws(() => assertRefresh(first, report(2_000_000n), [0n, 5_000_000_000n]));
  assert.throws(() => assertRefresh(first, next, [0n, 1_000_000_000n]));
  next.stages.pop(); assert.throws(() => assertRefresh(first, next, [0n, 5_000_000_000n]));
});

for (const progress of ["output", "rejection", "closed", "handoff", "stream reset"]) {
  test(`observation rejects delayed ${progress} delivered through real I/O`, async () => {
    const server = createServer(socket => { setTimeout(() => socket.end(progress), 15); });
    server.listen(0, "127.0.0.1"); await once(server, "listening");
    const socket = connect((server.address() as { port: number }).port, "127.0.0.1");
    let progressed = false; socket.on("data", () => { progressed = true; });
    try { await assert.rejects(observePending(() => assert.equal(progressed, false), 60)); }
    finally { socket.destroy(); await new Promise<void>(done => server.close(() => done())); }
  });
}
test("healthy pending observation spans actual monotonic interval", async () => {
  const start = performance.now(); await observePending(() => {}, 40);
  assert.ok(performance.now() - start >= 40);
});
test("failure cleanup destroys remotes before waiting for owner", async () => {
  let release!: () => void, destroyed = false;
  const closed = new Promise<void>(done => { release = done; });
  let watchdogFired = false;
  const watchdog = setTimeout(() => { watchdogFired = true; release(); }, 80);
  try {
    await cleanupFixture({ cancel() {}, closed }, async () => { destroyed = true; release(); }, 40);
    assert.equal(destroyed, true); assert.equal(watchdogFired, false);
  } finally { clearTimeout(watchdog); }
});
test("unknown physical closure yields bounded failure, never graceful proof", async () => {
  let destroyed = false;
  const result = cleanupFixture({ cancel() {}, closed: new Promise(() => {}) }, async () => { destroyed = true; }, 30);
  const outcome = await Promise.race([result, new Promise<string>(done => setTimeout(() => done("hung"), 100))]);
  assert.equal(outcome, "fixture-cleanup-unproved"); assert.equal(destroyed, true);
});
