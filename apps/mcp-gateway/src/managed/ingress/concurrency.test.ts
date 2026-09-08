import test from "node:test";
import assert from "node:assert/strict";
import { ingressFixture, initialize, send, until } from "./fixture.js";

test("duplicate outstanding JSON-RPC ids cannot replace the original call or its cancellation owner", async t => {
  const f = await ingressFixture(t), e = f.execution;
  const opened = await send(f.address.port, { body: initialize });
  const headers = { "mcp-session-id": opened.headers["mcp-session-id"] as string, "mcp-protocol-version": "2025-11-25" };
  const body = { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "portfolio.read", arguments: { portfolioId: "p-1" } } };
  const first = send(f.address.port, { headers, body }); void first.catch(() => {});
  await until(() => e.effects.includes("authorize"));
  const timer = setTimeout(() => f.ingress.cancel(), 300);
  try { assert.equal((await send(f.address.port, { headers, body })).status, 400); }
  finally { clearTimeout(timer); f.ingress.cancel(); }
  await e.cleanup(); await first.catch(() => {});
});
