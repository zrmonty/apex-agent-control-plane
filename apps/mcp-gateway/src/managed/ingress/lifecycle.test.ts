import test from "node:test";
import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import { ingressFixture, initialize, send } from "./fixture.js";

test("PREPARE can listen but cannot initialize; observed SERVE withdrawal closes the listener permanently", async t => {
  const f = await ingressFixture(t, undefined, false);
  assert.equal((await send(f.address.port, { body: initialize })).status, 503);
  f.admit(); assert.equal((await send(f.address.port, { body: initialize })).status, 200);
  let closed = false; void f.ingress.closed.then(() => { closed = true; });
  f.revoke(); await delay(150); assert.equal(closed, true);
  f.admit(); await assert.rejects(send(f.address.port, { body: initialize }));
});

test("expired session handles cannot be reused and session count is bounded", async t => {
  const f = await ingressFixture(t, { sessions: 1, sessionMs: 100 });
  const opened = await send(f.address.port, { body: initialize });
  assert.equal((await send(f.address.port, { body: initialize })).status, 503);
  await delay(150);
  const headers = { "mcp-session-id": opened.headers["mcp-session-id"] as string, "mcp-protocol-version": "2025-11-25" };
  assert.equal((await send(f.address.port, { method: "DELETE", headers })).status, 404);
  assert.equal((await send(f.address.port, { body: initialize })).status, 200);
});
