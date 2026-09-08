import test from "node:test";
import assert from "node:assert/strict";
import { ingressFixture, send, initialize } from "./fixture.js";

test("MCP sessions belong to the authenticated caller and support authenticated DELETE", async t => {
  const f = await ingressFixture(t), port = f.address.port;
  const opened = await send(port, { body: initialize });
  assert.equal(opened.status, 200);
  const session = opened.headers["mcp-session-id"];
  assert.equal(typeof session, "string");
  const headers = { "mcp-session-id": session as string, "mcp-protocol-version": "2025-11-25" };
  const body = { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} };
  assert.equal((await send(port, { headers, body })).status, 200);
  assert.equal((await send(port, { headers: { ...headers, authorization: "Bearer bob" }, body })).status, 404);
  assert.equal((await send(port, { headers: { ...headers, authorization: "Bearer invalid" }, body })).status, 401);
  assert.equal((await send(port, { method: "DELETE", headers })).status, 200);
  assert.equal((await send(port, { headers, body })).status, 404);
  assert.equal((await send(port, { method: "GET" })).status, 400);
  assert.equal((await send(port, { method: "DELETE" })).status, 400);
});

test("a failed SDK initialization does not occupy a session slot", async t => {
  const f = await ingressFixture(t, { sessions: 1 });
  assert.equal((await send(f.address.port, { body: initialize, headers: { accept: "application/json" } })).status, 406);
  assert.equal((await send(f.address.port, { body: initialize })).status, 200);
});
