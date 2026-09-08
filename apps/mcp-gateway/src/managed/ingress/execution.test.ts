import test from "node:test";
import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import { ingressFixture, initialize, send, until } from "./fixture.js";
import { envelope } from "../compiled-executor/testing.js";

test("streamed tool success waits for canonical evidence and close retains physical execution ownership", async t => {
  const f = await ingressFixture(t), opened = await send(f.address.port, { body: initialize });
  const headers = { "mcp-session-id": opened.headers["mcp-session-id"] as string, "mcp-protocol-version": "2025-11-25" };
  const pending = send(f.address.port, { headers, body: { jsonrpc: "2.0", id: 2, method: "tools/call",
    params: { name: "portfolio.read", arguments: { portfolioId: "p-1" } } } });
  let delivered = false; void pending.then(() => { delivered = true; }, () => {});
  const e = f.execution;
  await until(() => e.effects.includes("authorize")); e.authorize();
  await until(() => e.effects.includes("upstream")); e.upstream.resolve(envelope());
  await until(() => e.events.length === 1); assert.equal(delivered, false);
  e.evidenceReply.resolve(Buffer.alloc(0));
  const response = await pending;
  assert.equal(response.status, 200); assert.match(response.headers["content-type"]!, /text\/event-stream/);
  assert.match(response.body, /p-1/); assert.doesNotMatch(response.body, /PRIVATE-canary/);
  let closed = false; void f.ingress.closed.then(() => { closed = true; }); f.ingress.cancel();
  await delay(30); assert.equal(closed, false);
  e.rawClosed.resolve(); e.completionClosed.resolve(); e.evidenceClosed.resolve();
  await f.ingress.closed; assert.equal(closed, true);
});

test("SDK cancellation and DELETE cancel upstream work without releasing uncertain physical ownership", async t => {
  const f = await ingressFixture(t, { cleanupMs: 50 }), e = f.execution;
  const opened = await send(f.address.port, { body: initialize });
  const headers = { "mcp-session-id": opened.headers["mcp-session-id"] as string, "mcp-protocol-version": "2025-11-25" };
  const pending = send(f.address.port, { headers, body: { jsonrpc: "2.0", id: 2, method: "tools/call",
    params: { name: "portfolio.read", arguments: { portfolioId: "p-1" } } } });
  void pending.catch(() => {});
  await until(() => e.effects.includes("authorize")); e.authorize();
  await until(() => e.effects.includes("upstream"));
  assert.equal((await send(f.address.port, { headers, body: { jsonrpc: "2.0", method: "notifications/cancelled",
    params: { requestId: 2, reason: "synthetic cancellation" } } })).status, 202);
  await until(() => e.effects.includes("cancel-upstream"));
  assert.equal((await send(f.address.port, { method: "DELETE", headers })).status, 200);
  assert.equal(e.effects.includes("released"), false);
  let closed = false; void f.ingress.closed.then(() => { closed = true; });
  await delay(120); assert.equal(f.fatals, 1); assert.equal(closed, false);
  e.upstream.reject(Error("synthetic cancelled operation settled"));
  e.rawClosed.resolve(); e.completionClosed.resolve(); e.evidenceClosed.resolve();
  await f.ingress.closed; await pending.catch(() => {});
});
