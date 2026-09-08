import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { request as httpRequest, type IncomingHttpHeaders } from "node:http";
import { startManagedApplication } from "../application.js";
import { fixture as pki } from "../bootstrap/tls-role-fixture.js";
import { nativeServices } from "./native-services.js";
import { decodeStrict, ReadinessReportSchema, type ReadinessReport } from "@apex/contracts";
import { setTimeout as delay } from "node:timers/promises";
import { assertRefresh, bounded, cleanupFixture, observePending } from "./native-observation.js";

function mcp(token: string, body: unknown, session?: string, progress: () => void = () => {}) {
  return new Promise<{ status: number; headers: IncomingHttpHeaders; body: string }>((resolve, reject) => {
    const bytes = Buffer.from(JSON.stringify(body));
    const req = httpsRequest({ host: "10.248.245.2", port: 8080, servername: "gateway.test", ca: pki.ca,
      ...pki.governance, minVersion: "TLSv1.3", agent: false, method: "POST", path: "/mcp",
      headers: { host: "proxy.apex.test", origin: "https://console.apex.test", authorization: `Bearer ${token}`,
        accept: "application/json, text/event-stream", "content-type": "application/json", "content-length": String(bytes.length),
        "mcp-protocol-version": "2025-11-25", ...(session ? { "mcp-session-id": session } : {}) },
    }, res => {
      // SSE headers may open before dispatch; ANY body bytes (including partial
      // events), resolution or rejection before evidence admission fail the gate.
      let text = ""; res.on("data", bytes => { progress(); text += String(bytes); if (text.length > 65536) req.destroy(Error("fixture response exceeded bound")); });
      res.on("end", () => resolve({ status: res.statusCode!, headers: res.headers, body: text })); res.on("error", reject);
    });
    req.on("error", reject); req.setTimeout(3000, () => req.destroy(Error("fixture MCP deadline"))); req.end(bytes);
  });
}
function health(token: string) {
  return new Promise<{ status: number; body: ReadinessReport }>((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port: 8081, path: "/readyz", agent: false,
      headers: { host: "127.0.0.1:8081", authorization: `Bearer ${token}` } }, res => {
      let text = ""; res.on("data", bytes => { text += String(bytes); if (text.length > 8192) req.destroy(Error("fixture health bound")); });
      res.on("end", () => { try { resolve({ status: res.statusCode!, body: decodeStrict(ReadinessReportSchema, text) }); } catch (error) { reject(error); } });
      res.on("error", reject);
    });
    req.on("error", reject); req.setTimeout(2000, () => req.destroy(Error("fixture health deadline"))); req.end();
  });
}
function rpc(body: string) {
  return JSON.parse(body.startsWith("{") ? body : body.split("\n").find(line => line.startsWith("data: "))!.slice(6));
}

test("public application reads actual sealed RO stage, exposes fixed health/HTTPS, and governs an authenticated MCP call", {
  timeout: 20000, skip: process.env.APEX_TEST_APPLICATION_ROOT !== "owned-native-v1",
}, async t => {
  assert.equal(process.platform, "linux"); assert.equal(process.getuid!(), 10001);
  const fixture = JSON.parse(await readFile("/fixture/client.json", "utf8")) as { env: NodeJS.ProcessEnv; token: string };
  const services = await nativeServices(); let fatals = 0;
  const owner = startManagedApplication({ env: fixture.env, onFatal() { fatals++; } });
  t.after(async () => {
    assert.equal(await cleanupFixture(owner, services.close), "fixture-cleaned",
      "failure cleanup unproved; external supervisor must reap fixture, not count graceful proof");
  });
  assert.deepEqual(await owner.result, { host: "10.248.245.2", port: 8080 });
  const readiness = await health(await readFile("/apex/runtime/health-token", "utf8"));
  assert.equal(readiness.status, 200); assert.equal(readiness.body.ready, true); assert.equal(readiness.body.checks.length, 9);
  assert.equal(services.stats().toolCalls, 0); assert.equal(services.stats().event, undefined);
  const initialize = { jsonrpc: "2.0", id: 0, method: "initialize", params: {
    protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "owned-application-fixture", version: "1" } } };
  assert.equal((await mcp(fixture.token, initialize)).status, 503, "PREPARE never accepts a business session");
  await bounded(services.refreshed, 7500, "second NETWORK deadline");
  const healthToken = await readFile("/apex/runtime/health-token", "utf8");
  const refreshDeadline = performance.now() + 1500;
  let refreshed = await health(healthToken);
  while (refreshed.body.observedAtUnixUs === readiness.body.observedAtUnixUs && performance.now() < refreshDeadline) {
    await delay(20); refreshed = await health(healthToken);
  }
  assert.equal(refreshed.status, 200);
  assertRefresh(readiness.body, refreshed.body, services.stats().networkAt);
  assert.equal((await mcp(fixture.token, initialize)).status, 503, "completed refresh remains non-admitting PREPARE");
  assert.equal(services.stats().toolCalls, 0); assert.equal(services.stats().event, undefined);
  services.serve(); await services.applied;
  assert.equal((await mcp("invalid-token", initialize)).status, 401);
  const initialized = await mcp(fixture.token, initialize);
  assert.equal(initialized.status, 200); assert.equal(rpc(initialized.body).id, 0);
  const session = initialized.headers["mcp-session-id"]; assert.equal(typeof session, "string");
  await mcp(fixture.token, { jsonrpc: "2.0", method: "notifications/initialized" }, session as string);
  let progressed = false, settled = false, closed = false, handoff = false;
  void owner.closed.then(() => { closed = true; }, () => { closed = true; });
  void owner.completionHandoff.then(() => { handoff = true; }, () => { handoff = true; });
  const call = mcp(fixture.token, { jsonrpc: "2.0", id: 2, method: "tools/call",
    params: { name: "portfolio.read", arguments: { portfolioId: "p-1" } } }, session as string, () => { progressed = true; });
  void call.then(() => { settled = true; }, () => { settled = true; });
  await Promise.race([services.evidenceSeen, call.then(() => { throw Error("MCP finished before required evidence"); })]);
  await observePending(() => {
    assert.equal(progressed || settled || closed || handoff, false, "no output/rejection/closure before evidence receipt");
    services.assertHeld("evidence");
  });
  assert.equal(services.stats().toolCalls, 1);
  const event = services.stats().event!;
  assert.equal(event.data!.generation, "9007199254740993"); assert.match(event.timestamp, /\.\d{6}Z$/);
  assert.equal(JSON.stringify(event).includes("RAW-MUST-NOT-ESCAPE"), false);
  services.admit(); const response = await call;
  assert.equal(response.status, 200); assert.equal(rpc(response.body).result.structuredContent.portfolioId, "p-1");
  assert.equal(response.body.includes("RAW-MUST-NOT-ESCAPE"), false);
  await services.completionSeen;
  owner.cancel();
  await observePending(() => {
    assert.equal(closed || handoff, false, "missing completion receipt retains physical ownership and handoff");
    services.assertHeld("completion");
  });
  services.complete(); await bounded(owner.closed, 4500, "graceful application closure deadline");
  assert.deepEqual(await bounded(owner.completionHandoff, 500, "completion handoff deadline"), []);
  assert.deepEqual(services.stats().destinations, ["evidence", "governance", "upstream"]);
  assert.equal(services.stats().completion, 1); assert.equal(fatals, 0);
});
