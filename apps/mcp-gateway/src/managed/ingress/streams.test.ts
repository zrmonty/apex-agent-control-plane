import test from "node:test";
import assert from "node:assert/strict";
import { request } from "node:https";
import { setTimeout as delay } from "node:timers/promises";
import { ingressFixture, initialize, send, pki } from "./fixture.js";

test("GET streams have a fixed lifetime and cannot bypass the per-session request ceiling", async t => {
  const f = await ingressFixture(t, { requestMs: 180, sessionRequests: 1 });
  const opened = await send(f.address.port, { body: initialize });
  const headers = { "mcp-session-id": opened.headers["mcp-session-id"] as string, "mcp-protocol-version": "2025-11-25" };
  let ended = false;
  const stream = send(f.address.port, { method: "GET", headers }).then(() => { ended = true; }, () => { ended = true; });
  await delay(40);
  assert.equal(ended, false);
  assert.equal((await send(f.address.port, { headers, body: { jsonrpc: "2.0", id: 2, method: "tools/list" } })).status, 503);
  await delay(220); assert.equal(ended, true); await stream;
});

test("a bounded chunked initialization succeeds but oversized and duplicate-key JSON is rejected", async t => {
  const f = await ingressFixture(t);
  const raw = (body: string) => new Promise<number>((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port: f.address.port, servername: "gateway.test", ca: pki.ca,
      ...pki.governance, agent: false, method: "POST", path: "/mcp", headers: {
        host: "proxy.apex.test", origin: "https://console.apex.test", authorization: "Bearer alice",
        accept: "application/json, text/event-stream", "content-type": "application/json", "transfer-encoding": "chunked",
      } }, res => { res.resume(); res.once("end", () => resolve(res.statusCode!)); });
    req.on("error", reject); req.write(body.slice(0, 10)); req.end(body.slice(10));
  });
  assert.equal(await raw(JSON.stringify(initialize)), 200);
  assert.equal(await raw(JSON.stringify(initialize).replace('"id":1', '"id":1,"id":2')), 400);
  await raw(JSON.stringify({ ...initialize, excess: "x".repeat(1_048_576) })).then(
    status => assert.equal(status, 400), () => {});
});
