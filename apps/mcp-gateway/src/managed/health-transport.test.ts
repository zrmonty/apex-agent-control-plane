import assert from "node:assert/strict";
import test from "node:test";
import { startHealthServer } from "./health-server.js";
import { fixture } from "./readiness/report-codec/test-support.js";
import { createClock } from "../telemetry/clock.js";
import { requestText, token, wire } from "./health-testing/http.js";
import { rejectsBeforeState, invalidTokens } from "./health-testing/envelope.js";
import { cachedLifecycle, emptyFailures, callbackFences, connectionCap, absoluteIdle } from "./health-testing/server-lifetime.js";
import { completed } from "./readiness/report-codec/test-support.js";
import { probeHealth } from "../health-probe.js";
import { probeEnvelope, probeDeadline, probeCallbackBudget, probeInvalidInput } from "./health-testing/probe.js";
import { runNode } from "../testing/node-runner.js";
import { fileURLToPath } from "node:url";
import { byteEdgesAndPipeline, bindingCollision, preciseStages, leaseExpiry } from "./health-testing/boundaries.js";

// One serial entry owns literal port 8081. No port override, fallback or skips.
test("authenticated cold liveness is cached real monitor state, not readiness", { timeout: 5000 }, async t => {
  const f = fixture();
  t.after(() => f.monitor.close());
  const server = await startHealthServer({ codec: f.codec, state: f.monitor,
    tokenBytes: token(), clock: createClock(), onFatal: () => assert.fail("unexpected fatal") });
  t.after(() => server.close());
  const live = await requestText(wire("/livez"));
  assert.equal(live.status, 200);
  assert.equal(live.headers["content-type"], "application/json");
  assert.equal(live.headers["cache-control"], "no-store");
  assert.equal(live.headers.connection, "close");
  assert.equal(live.headers.date, undefined);
  const report = f.codec.decode(live.body);
  assert.equal(report.live, true);
  assert.equal(report.ready, false);
  assert.equal(report.observedAtUnixUs, 0n);
  const ready = await requestText(wire("/readyz"));
  assert.equal(ready.status, 503);
  assert.equal(ready.body, live.body);
  assert.equal(f.stats.starts, 0, "GET must not start dependency probes");
});

test("probe enforces raw response framing, bounds and the real codec over fixed HTTP", { timeout: 10000 }, probeEnvelope);
test("probe trickle cannot extend its actual two-second deadline and leaves no sockets", { timeout: 5000 }, probeDeadline);
test("probe rechecks the absolute budget after trusted codec decode", probeCallbackBudget);
test("probe rejects invalid token/clock before any I/O", probeInvalidInput);
test("exact byte/field edges pass while pipelining and paused readers retain one owned lifetime", { timeout: 5000 }, byteEdgesAndPipeline);
test("fixed-port collision fails statically without touching the existing listener", bindingCollision);
test("real monitor stages retain 1/7/999us, 999ns and bigint wall anchors through HTTP/probe", preciseStages);
test("HTTP exposes a short owner lease expiry without restamping or another sweep", leaseExpiry);
test("direct child cannot conceal an expired owned-socket teardown with a late close", async () => {
  const result = await runNode({ cwd: fileURLToPath(new URL("../../", import.meta.url)),
    entrypoint: "src/managed/health-testing/watchdog-child.ts", env: process.env, timeoutMs: 4800 });
  assert.equal(result.code, 73, "safety fuse 74 and runner timeout are failures");
  const observation = JSON.parse(result.stdout.toString("utf8"));
  assert.equal(observation.fatal, true); assert.equal(observation.connected, true);
  assert.equal(observation.attempted, true); assert.equal(observation.actualGrace, false);
  assert.equal(observation.closed, true);
  assert.equal(result.stderr.length, 0); assert.equal(result.reaped, true);
  assert.throws(() => process.kill(result.pid!, 0), { code: "ESRCH" });
});
test("probe refuses success after actual one-second unresponsive cleanup; direct child is reaped", async () => {
  const result = await runNode({ cwd: fileURLToPath(new URL("../../", import.meta.url)),
    entrypoint: "src/managed/health-testing/probe-cleanup-child.ts", env: process.env, timeoutMs: 3500 });
  assert.equal(result.code, 73, "fuse/runner termination cannot stand in for cleanup refusal");
  const observed = JSON.parse(result.stdout.toString("utf8"));
  assert.equal(observed.result, 1); assert.equal(observed.beforeRestoreClosed, false);
  assert.equal(observed.attempted, true); assert.equal(observed.closed, true); assert.equal(observed.serverSockets, 0);
  assert.ok(observed.elapsedMs >= 900 && observed.elapsedMs < 2000);
  assert.equal(result.stderr.length, 0); assert.equal(result.reaped, true);
  assert.throws(() => process.kill(result.pid!, 0), { code: "ESRCH" });
});

test("every refused HTTP envelope is empty and performs zero state or codec calls", { timeout: 10000 }, rejectsBeforeState);
test("invalid token lengths fail statically before binding; caller bytes remain owned by caller", invalidTokens);
test("HTTP reads retain bigint anchors/stages and expose local staleness, loss and shutdown", cachedLifecycle);
test("snapshot/codec failures and oversize encode produce only empty 503", { timeout: 10000 }, emptyFailures);
test("trusted callbacks cannot reenter close or cross a deadline and resume healthy work", { timeout: 10000 }, callbackFences);
test("eight partial sockets occupy the bound; ninth is rejected and close joins owned sockets", { timeout: 5000 }, connectionCap);
test("idle and trickled sockets expire at the actual absolute two-second budget", { timeout: 5000 }, absoluteIdle);
test("fixed probe accepts an actual bound ready report, rejects shutdown and never starts probes", { timeout: 5000 }, async t => {
  const f = await completed(); t.after(() => f.monitor.close());
  const clock = createClock();
  const server = await startHealthServer({ codec: f.codec, state: f.monitor, tokenBytes: token(), clock,
    onFatal: () => assert.fail("fatal") }); t.after(() => server.close());
  assert.equal(await probeHealth({ codec: f.codec, tokenBytes: token(), clock }), 0);
  assert.equal(f.stats.starts, 9);
  await f.monitor.close();
  assert.equal(await probeHealth({ codec: f.codec, tokenBytes: token(), clock }), 1);
});
