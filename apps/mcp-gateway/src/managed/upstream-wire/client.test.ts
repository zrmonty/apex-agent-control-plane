import assert from "node:assert/strict";
import test from "node:test";
import { wireFixture, context } from "./testing.js";
import type { WireRpc } from "./client.js";

for (const streamed of [false, true]) {
  test(`real guard/TLS/HTTP/MCP chain returns exact ${streamed ? "SSE" : "JSON"} call and physical cleanup`, async t => {
    let gates = 0, received = 0;
    const f = await wireFixture(t, (value, req, res) => {
      received++; assert.equal(gates, 1); assert.equal(req.headers["mcp-session-id"], "session-1");
      assert.deepEqual(value, { jsonrpc: "2.0", id: "call-1", method: "tools/call", params: { name: "portfolio.read", arguments: { portfolioId: "p-1" } } });
      const result = JSON.stringify({ jsonrpc: "2.0", id: "call-1", result: { content: [{ type: "text", text: "real result" }] } });
      res.writeHead(200, { "content-type": streamed ? "text/event-stream" : "application/json" });
      if (streamed) res.write(`data: ${result}\n\n`); else res.end(result);
    });
    const exchange = f.wire.startRpc({ id: "call-1", method: "tools/call", params: { name: "portfolio.read", arguments: { portfolioId: "p-1" } },
      sessionId: "session-1", protocolVersion: "2025-11-25" }, context(() => { gates++; }));
    assert.deepEqual(await exchange.result, { content: [{ type: "text", text: "real result" }] });
    await exchange.closed; assert.equal(received, 1);
  });
}

test("numeric or active request IDs refuse before guard or upstream work", async t => {
  let received = 0, invoked = 0;
  const f = await wireFixture(t, (_value, _req, res) => { received++; res.end(); });
  const value = { id: 1, method: "tools/list" } as unknown as WireRpc;
  assert.throws(() => f.wire.startRpc(value, context()), /managed MCP exchange refused safely/);
  const active = { method: "tools/list", get id() { invoked++; return "root-1"; } } as WireRpc;
  assert.throws(() => f.wire.startRpc(active, context()), /managed MCP exchange refused safely/);
  assert.equal(received, 0); assert.equal(invoked, 0);
});

for (const streamed of [false, true]) {
  test(`actual ${streamed ? "SSE" : "JSON"} wrong request id refuses statically and is not retried`, async t => {
    let received = 0;
    const f = await wireFixture(t, (_value, _req, res) => {
      received++;
      const wrong = '{"jsonrpc":"2.0","id":"OTHER_PRIVATE_CALL","result":{"content":[]}}';
      res.writeHead(200, { "content-type": streamed ? "text/event-stream" : "application/json" });
      res.end(streamed ? `data: ${wrong}\n\n` : wrong);
    });
    const exchange = f.wire.startRpc({ id: "call-1", method: "tools/call", params: { name: "portfolio.read", arguments: {} } }, context());
    await assert.rejects(exchange.result, /^Error: managed MCP exchange refused safely$/);
    await exchange.closed; assert.equal(received, 1);
  });
}

test("post-decode expiry refuses success even after a complete native HTTP body", async t => {
  let samples = 0;
  const timing = context();
  const f = await wireFixture(t, (_value, _req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end('{"jsonrpc":"2.0","id":"root-1","result":{"tools":[]}}');
  }, () => ++samples === 1 ? timing.startedAtMonotonicNs : timing.deadlineMonotonicNs);
  const exchange = f.wire.startRpc({ id: "root-1", method: "tools/list" }, timing);
  await assert.rejects(exchange.result, /^Error: managed MCP exchange refused safely$/);
  await exchange.closed; assert.equal(samples, 2);
});

test("cancellation during an unfinished MCP SSE result owns native cleanup", async t => {
  let sent!: () => void; const headersSent = new Promise<void>(done => { sent = done; });
  const f = await wireFixture(t, (_value, _req, res) => {
    res.writeHead(200, { "content-type": "text/event-stream" }); res.write(": waiting\n\n"); sent();
  });
  const exchange = f.wire.startRpc({ id: "root-1", method: "tools/list" }, context());
  const refused = assert.rejects(exchange.result, /^Error: managed MCP exchange refused safely$/);
  await headersSent; exchange.cancel(); await refused; await exchange.closed;
  const closing = f.wire.close(); assert.equal(f.wire.close(), closing); await closing;
  assert.throws(() => f.wire.startRpc({ id: "root-2", method: "tools/list" }, context()), /managed MCP exchange refused safely/);
});

test("an active RPC id cannot acquire a second physical group before cleanup", async t => {
  const f = await wireFixture(t, (_value, _req, res) => { res.writeHead(200, { "content-type": "text/event-stream" }); res.write(": held\n\n"); });
  const request = { id: "root-1", method: "tools/list" } as const;
  const first = f.wire.startRpc(request, context());
  const refused = assert.rejects(first.result, /managed MCP exchange refused safely/);
  assert.throws(() => f.wire.startRpc(request, context()), /managed MCP exchange refused safely/);
  first.cancel();
  assert.throws(() => f.wire.startRpc(request, context()), /managed MCP exchange refused safely/);
  await refused; await first.closed;
});

test("real open CR-only SSE result settles and drains without upstream EOF", async t => {
  const f = await wireFixture(t, (_value, _req, res) => {
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.write('data: {"jsonrpc":"2.0","id":"call-cr","result":{"content":[]}}\r\r');
  });
  const timing = context();
  const exchange = f.wire.startRpc({ id: "call-cr", method: "tools/call", params: { name: "portfolio.read", arguments: {} } },
    { ...timing, deadlineMonotonicNs: timing.startedAtMonotonicNs + 2_000_000_000n });
  assert.deepEqual(await exchange.result, { content: [] }); await exchange.closed;
});

test("session metadata is available only after the exact RPC reply validates", async t => {
  const f = await wireFixture(t, (_value, _req, res) => {
    res.writeHead(200, { "content-type": "application/json", "mcp-session-id": "verified-session" });
    res.end('{"jsonrpc":"2.0","id":"root-list","result":{"tools":[]}}');
  });
  const exchange = f.wire.startRpc({ id: "root-list", method: "tools/list" }, context());
  assert.throws(() => exchange.metadata(), /managed MCP exchange refused safely/);
  await exchange.result;
  assert.deepEqual(exchange.metadata(), { sessionId: "verified-session" });
  assert.equal(Object.isFrozen(exchange.metadata()), true); await exchange.closed;
});
