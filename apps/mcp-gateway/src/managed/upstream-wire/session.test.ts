import assert from "node:assert/strict";
import test from "node:test";
import type { TestContext } from "node:test";
import type { ServerResponse } from "node:http";
import { IncomingMessage } from "node:http";
import { wireFixture, context } from "./testing.js";
import { OwnedMcpSession } from "./session.js";

const tool = { name: "portfolio.read", inputSchema: { type: "object", properties: { portfolioId: { type: "string" } },
  required: ["portfolioId"], additionalProperties: false }, outputSchema: { type: "object" } };
const callId = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e05";

test("explicit actual MCP initialize notification discovery call keeps one selected session", async t => {
  const methods: string[] = [];
  const f = await wireFixture(t, (value, req, res) => {
    if (req.method === "DELETE") {
      methods.push("DELETE"); assert.equal(value, undefined); assert.equal(req.headers["mcp-session-id"], "selected-session");
      res.writeHead(204); res.end(); return;
    }
    const message = value as { method: string; id?: string; params?: unknown }; methods.push(message.method);
    if (message.method !== "initialize") {
      assert.equal(req.headers["mcp-session-id"], "selected-session");
      assert.equal(req.headers["mcp-protocol-version"], "2025-11-25");
    }
    if (message.method === "notifications/initialized") { assert.equal(message.id, undefined); res.writeHead(202); res.end(); return; }
    const result = message.method === "initialize" ? { protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: "fixture", version: "1" } }
      : message.method === "tools/list" ? { tools: [tool] } : { content: [{ type: "text", text: "session result" }] };
    res.writeHead(200, { "content-type": "application/json", "mcp-session-id": "selected-session" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }));
  });
  const session = new OwnedMcpSession(f.http, [tool]); t.after(() => session.close());
  assert.throws(() => session.call(callId, tool.name, { portfolioId: "p-1" }, context()), /managed MCP session refused safely/);
  await session.initialize(context()); assert.deepEqual(await session.discover(context()), [tool]);
  const exchange = session.call(callId, tool.name, { portfolioId: "p-1" }, context());
  assert.deepEqual(await exchange.result, { content: [{ type: "text", text: "session result" }] });
  await exchange.closed;
  await session.terminate(context());
  assert.deepEqual(methods, ["initialize", "notifications/initialized", "tools/list", "tools/call", "DELETE"]);
  assert.throws(() => session.call(callId, tool.name, {}, context()), /managed MCP session refused safely/);
});

type Message = { method: string; id: string; params?: { cursor?: string } };
async function prepared(t: TestContext, override?: (message: Message, res: ServerResponse) => boolean,
  options: { stateless?: boolean; now?: () => bigint } = {}) {
  const methods: string[] = [];
  const f = await wireFixture(t, (value, req, res) => {
    const message = value as Message | undefined; methods.push(message?.method ?? req.method!);
    if (override?.(message ?? { method: req.method!, id: "" }, res)) return;
    if (!options.stateless) res.setHeader("mcp-session-id", "stable-session");
    if (req.method === "DELETE" || message?.method === "notifications/initialized") { res.writeHead(204); res.end(); return; }
    assert.ok(message);
    const result = message.method === "initialize" ? { protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: "fixture", version: "1" } }
      : message.method === "tools/list" ? { tools: [tool] } : { content: [] };
    reply(res, message.id, result);
  });
  const session = new OwnedMcpSession(f.http, [tool], options.now); t.after(() => session.close());
  return { ...f, session, methods };
}
function reply(res: ServerResponse, id: string, result: unknown) {
  res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
}
const safe = /managed MCP session refused safely/;

for (const failure of ["version", "capability", "notification-body", "notification-session"]) {
  test(`initialization refuses ${failure} without discovery or business dispatch`, async t => {
    const f = await prepared(t, (message, res) => {
      if (message.method === "initialize" && ["version", "capability"].includes(failure)) {
        reply(res, message.id, { protocolVersion: failure === "version" ? "2024-11-05" : "2025-11-25",
          capabilities: failure === "capability" ? {} : { tools: {} }, serverInfo: { name: "fixture", version: "1" } }); return true;
      }
      if (message.method === "notifications/initialized") {
        if (failure === "notification-session") res.setHeader("mcp-session-id", "other-session");
        res.writeHead(202); res.end(failure === "notification-body" ? "not-empty" : undefined); return true;
      }
      return false;
    });
    await assert.rejects(f.session.initialize(context()), safe);
    await assert.rejects(f.session.discover(context()), safe);
    assert.throws(() => f.session.call(callId, tool.name, {}, context()), safe);
    assert.ok(f.methods.every(method => ["initialize", "notifications/initialized"].includes(method)));
  });
}

for (const failure of ["input-schema", "output-schema", "missing-tool", "duplicate-name", "duplicate-cursor", "page-limit", "session"]) {
  test(`discovery refuses ${failure} and poisons session`, async t => {
    let pages = 0;
    const f = await prepared(t, (message, res) => {
      if (message.method !== "tools/list") return false; pages++;
      if (failure === "session") res.setHeader("mcp-session-id", "wrong-session");
      const tools = failure === "missing-tool" ? [] : failure === "duplicate-name" ? [tool, tool]
        : failure === "input-schema" ? [{ ...tool, inputSchema: { type: "object" } }]
        : failure === "output-schema" ? [{ ...tool, outputSchema: undefined }]
        : failure.includes("cursor") || failure === "page-limit" ? [] : [tool];
      reply(res, message.id, { tools, ...(failure === "duplicate-cursor" ? { nextCursor: "same" }
        : failure === "page-limit" ? { nextCursor: `page-${pages}` } : {}) }); return true;
    });
    await f.session.initialize(context()); await assert.rejects(f.session.discover(context()), safe);
    assert.throws(() => f.session.call(callId, tool.name, {}, context()), safe);
    assert.equal(pages, failure === "duplicate-cursor" ? 2 : failure === "page-limit" ? 8 : 1);
    await assert.rejects(f.session.initialize(context()), safe);
  });
}

test("discovery paginates with exact cursor and quarantines unexposed tools", async t => {
  let pages = 0;
  const extra = { name: "unpublished", inputSchema: { type: "object" } };
  const f = await prepared(t, (message, res) => {
    if (message.method !== "tools/list") return false;
    assert.equal(message.params?.cursor, pages ? "next" : undefined);
    reply(res, message.id, pages++ ? { tools: [tool] } : { tools: [extra], nextCursor: "next" }); return true;
  });
  await f.session.initialize(context()); const found = await f.session.discover(context());
  assert.deepEqual(found, [extra, tool]); assert.ok(Object.isFrozen(found)); assert.ok(Object.isFrozen(found[1].inputSchema));
  for (const [id, name] of [[callId, "unpublished"], ["root:3", tool.name], [callId.toUpperCase(), tool.name]])
    assert.throws(() => f.session.call(id, name, {}, context()), safe);
  assert.equal(f.methods.filter(method => method === "tools/call").length, 0);
});

test("changed business response session is rejected and cannot be reinitialized", async t => {
  const f = await prepared(t, (message, res) => {
    if (message.method !== "tools/call") return false;
    res.setHeader("mcp-session-id", "replacement"); reply(res, message.id, { content: [] }); return true;
  });
  await f.session.initialize(context()); await f.session.discover(context());
  const call = f.session.call(callId, tool.name, {}, context());
  await assert.rejects(call.result, safe); await call.closed;
  await assert.rejects(f.session.initialize(context()), safe);
});

test("stateless termination closes locally without fabricating remote DELETE", async t => {
  const f = await prepared(t, undefined, { stateless: true });
  await f.session.initialize(context()); await f.session.discover(context());
  await f.session.terminate(context()); assert.ok(!f.methods.includes("DELETE"));
  assert.throws(() => f.session.call(callId, tool.name, {}, context()), safe);
});

test("termination failure reports refusal but closes the local session", async t => {
  const f = await prepared(t, (message, res) => {
    if (message.method !== "DELETE") return false; res.writeHead(202); res.end("not-empty"); return true;
  });
  await f.session.initialize(context()); await f.session.discover(context());
  await assert.rejects(f.session.terminate(context()), safe);
  await assert.rejects(f.session.terminate(context()), safe); assert.equal(f.methods.filter(m => m === "DELETE").length, 1);
  assert.throws(() => f.session.call(callId, tool.name, {}, context()), safe);
});

test("close during initialize prevents initialized notification and future work", async t => {
  let seen!: () => void; const received = new Promise<void>(done => { seen = done; });
  const f = await prepared(t, (message, _res) => { if (message.method === "initialize") { seen(); return true; } return false; });
  const initialization = f.session.initialize(context()); const rejected = assert.rejects(initialization, safe);
  await received; await f.session.close(); await rejected;
  assert.deepEqual(f.methods, ["initialize"]); await assert.rejects(f.session.discover(context()), safe);
});

test("termination refuses active call, then sends one DELETE only after physical closure", async t => {
  let seen!: () => void; const received = new Promise<void>(done => { seen = done; });
  const f = await prepared(t, (message, _res) => { if (message.method === "tools/call") { seen(); return true; } return false; });
  await f.session.initialize(context()); await f.session.discover(context());
  const call = f.session.call(callId, tool.name, {}, context()); const rejected = assert.rejects(call.result, safe);
  await received; await assert.rejects(f.session.terminate(context()), safe);
  call.cancel(); await rejected; await call.closed;
  const termination = f.session.terminate(context()); assert.equal(f.session.terminate(context()), termination);
  assert.throws(() => f.session.call(callId, tool.name, {}, context()), safe); await termination;
  assert.equal(f.methods.filter(m => m === "DELETE").length, 1);
});

test("invalid session clock poisons owner rather than allowing later recovery", async t => {
  let invalid = false;
  const f = await prepared(t, undefined, { now: () => { if (invalid) throw new Error("private clock detail"); return process.hrtime.bigint(); } });
  await f.session.initialize(context()); await f.session.discover(context());
  invalid = true; assert.throws(() => f.session.call(callId, tool.name, {}, context()), safe);
  invalid = false; assert.throws(() => f.session.call(callId, tool.name, {}, context()), safe);
});

test("a held native response close event prevents termination even after cancellation", async t => {
  const f = await prepared(t);
  await f.session.initialize(context()); await f.session.discover(context());
  let reached!: () => void, release!: () => void;
  const held = new Promise<void>(done => { reached = done; });
  const original = IncomingMessage.prototype.emit;
  t.mock.method(IncomingMessage.prototype, "emit", function (this: IncomingMessage, event: string | symbol, ...args: unknown[]) {
    if (event === "close" && this.statusCode === 200) {
      release = () => Reflect.apply(original, this, [event, ...args]); reached(); return true;
    }
    return Reflect.apply(original, this, [event, ...args]);
  });
  const call = f.session.call(callId, tool.name, {}, context());
  const outcome = call.result.then(() => "result", () => "refused");
  await held; call.cancel();
  let closed = false; void call.closed.then(() => { closed = true; });
  await Promise.resolve(); assert.equal(closed, false);
  await assert.rejects(f.session.terminate(context()), safe); assert.ok(!f.methods.includes("DELETE"));
  release(); await outcome; await call.closed;
  await f.session.terminate(context()); assert.equal(f.methods.filter(m => m === "DELETE").length, 1);
});

test("original final-write gate prevents business bytes after readiness has succeeded", async t => {
  const f = await prepared(t); await f.session.initialize(context()); await f.session.discover(context());
  let gates = 0;
  const call = f.session.call(callId, tool.name, {}, context(() => { gates++; throw new Error("revoked"); }));
  await assert.rejects(call.result, safe); await call.closed;
  assert.equal(gates, 1); assert.ok(!f.methods.includes("tools/call"));
});

test("expired supplied context cannot dispatch or silently acquire a fresh budget", async t => {
  const f = await prepared(t); await f.session.initialize(context()); await f.session.discover(context());
  const started = process.hrtime.bigint();
  assert.throws(() => f.session.call(callId, tool.name, {}, { startedAtMonotonicNs: started,
    deadlineMonotonicNs: started, beforeWrite() {} }), safe);
  assert.ok(!f.methods.includes("tools/call"));
});

for (const action of ["none", "close", "clock"] as const) {
  test(`async rejecting gate is contained before post-gate ${action} check`, async t => {
    let broken = false;
    const f = await prepared(t, undefined, { now: () => { if (broken) throw new Error("PRIVATE_CLOCK"); return process.hrtime.bigint(); } });
    await f.session.initialize(context()); await f.session.discover(context());
    const call = f.session.call(callId, tool.name, {}, context(async () => {
      if (action === "close") void f.session.close();
      if (action === "clock") broken = true;
      throw new Error("PRIVATE_GATE_CANARY");
    }));
    await assert.rejects(call.result, safe); await call.closed;
    assert.ok(!f.methods.includes("tools/call"));
    // Node's test harness also fails on an unhandled private rejection.
    await new Promise<void>(done => setImmediate(done));
  });
}
