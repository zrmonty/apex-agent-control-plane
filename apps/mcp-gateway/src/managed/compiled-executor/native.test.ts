import test from "node:test";
import assert from "node:assert/strict";
import { wireFixture, context } from "../upstream-wire/testing.js";
import { OwnedMcpSession } from "../upstream-wire/session.js";
import { createClock } from "../../telemetry/clock.js";
import { harness, envelope, turns, canary } from "./testing.js";

test("compiled execution covers real guard TLS HTTP MCP session/parser before typed evidence acceptance", { timeout: 10000 }, async t => {
  // Existing explicit non-production loopback fixture. Native upstream transport,
  // not protected deployment/network provenance or real EventIngest durability.
  const calls: { id: string; method: string }[] = [];
  const tool = { name: "portfolio.read", inputSchema: { type: "object" as const,
    properties: { portfolioId: { type: "string" } }, required: ["portfolioId"], additionalProperties: false }, outputSchema: { type: "object" as const } };
  const native = await wireFixture(t, (value, _req, res) => {
    const rpc = value as { id: string; method: string }; calls.push(rpc);
    if (rpc.method === "notifications/initialized") { res.writeHead(202); res.end(); return; }
    const result = rpc.method === "initialize" ? { protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: "fixture", version: "1" } }
      : rpc.method === "tools/list" ? { tools: [tool] } : envelope();
    res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result }));
  });
  const session = new OwnedMcpSession(native.http, [tool]);
  await session.initialize(context()); await session.discover(context());
  const h = harness({ clock: createClock(), session }); t.after(() => h.cleanup()); const job = h.start();
  h.authorize(); h.completionClosed.resolve();
  // The actual network callback, not a fake microtask count, signals evidence.
  for (let i = 0; !h.events.length && i < 100; i++) await new Promise<void>(done => setTimeout(done, 10));
  assert.equal(h.events.length, 1); assert.equal(calls.filter(c => c.method === "tools/call").length, 1);
  assert.equal(calls.find(c => c.method === "tools/call")!.id, job.observation().callId);
  let delivered = false; void job.result.then(() => { delivered = true; }, () => {}); await turns(); assert.equal(delivered, false);
  h.evidenceReply.resolve(Buffer.alloc(0)); const result = await job.result;
  assert.equal(JSON.stringify(result).includes(canary), false); assert.equal(result.structuredContent.portfolioId, "p-1");
  h.evidenceClosed.resolve(); await job.closed; await h.executor.close(); await session.close();
});
