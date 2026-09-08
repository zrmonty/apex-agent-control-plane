import test from "node:test";
import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import { ingressFixture, initialize, send, until } from "./fixture.js";
import { envelope } from "../compiled-executor/testing.js";

test("numeric zero cancellation targets only numeric zero and retains physical execution ownership", async t => {
  const f = await ingressFixture(t);
  const opened = await send(f.address.port, { body: initialize });
  const headers = { "mcp-session-id": opened.headers["mcp-session-id"] as string,
    "mcp-protocol-version": "2025-11-25" };
  let ended = false;
  const work = send(f.address.port, { headers, body: { jsonrpc: "2.0", id: 0, method: "tools/call",
    params: { name: "portfolio.read", arguments: { portfolioId: "p-1" } } } });
  void work.then(() => { ended = true; }, () => { ended = true; });
  try {
    await until(() => f.execution.effects.includes("authorize")); f.execution.authorize();
    await until(() => f.execution.effects.includes("upstream"));
    const cancel = (requestId: string | number) => send(f.address.port, { headers,
      body: { jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId } } });
    assert.equal((await cancel("0")).status, 202);
    await delay(20); assert.equal(ended, false); assert.equal(f.execution.effects.includes("cancel-upstream"), false);
    assert.equal((await cancel(0)).status, 202);
    await until(() => f.execution.effects.includes("cancel-upstream")); await until(() => ended);
    assert.equal(f.execution.effects.includes("released"), false);
    // The same ID cannot replace the still-owned physical operation.
    assert.equal((await send(f.address.port, { headers, body: { jsonrpc: "2.0", id: 0, method: "tools/list" } })).status, 400);
    assert.equal((await send(f.address.port, { headers, body: { jsonrpc: "2.0", id: "0", method: "tools/list" } })).status, 200);
  } finally { await f.execution.cleanup(); await work.catch(() => {}); }
});

test("uncancelled numeric zero returns its exact id on successful execution", async t => {
  const f = await ingressFixture(t);
  const opened = await send(f.address.port, { body: initialize });
  const headers = { "mcp-session-id": opened.headers["mcp-session-id"] as string,
    "mcp-protocol-version": "2025-11-25" };
  const work = send(f.address.port, { headers, body: { jsonrpc: "2.0", id: 0, method: "tools/call",
    params: { name: "portfolio.read", arguments: { portfolioId: "p-1" } } } });
  void work.catch(() => {});
  try {
    await until(() => f.execution.effects.includes("authorize")); f.execution.authorize();
    await until(() => f.execution.effects.includes("upstream")); f.execution.upstream.resolve(envelope());
    await until(() => f.execution.events.length === 1); f.execution.evidenceReply.resolve(Buffer.alloc(0));
    const result = await work;
    assert.equal(result.status, 200); assert.match(result.body, /"id":0/); assert.match(result.body, /p-1/);
  } finally { await f.execution.cleanup(); }
});
