import test from "node:test";
import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import { startManagedIngress } from "../ingress.js";
import { disposeRuntimeMaterials } from "../bootstrap/runtime-materials.js";
import { ingressFixture, send, initialize, until } from "./fixture.js";
import { envelope } from "../compiled-executor/testing.js";

test("public ingress refuses missing protected network, forged stage, and mismatched material owners", async t => {
  const f = await ingressFixture(t), other = await ingressFixture(t);
  for (const options of [f.options, { ...f.options, stage: { ...f.options.stage } },
    { ...f.options, materials: other.options.materials }]) {
    const ingress = startManagedIngress(options);
    await assert.rejects(ingress.result, /^Error: managed ingress refused safely$/); await ingress.closed;
  }
});

test("disposing staged materials closes an already listening ingress", async t => {
  const f = await ingressFixture(t);
  disposeRuntimeMaterials(f.options.materials);
  let closed = false; void f.ingress.closed.then(() => { closed = true; });
  await until(() => closed);
  await assert.rejects(send(f.address.port, { body: initialize }));
});

test("dispatch independently authenticates caller and rejects authority lost during authentication", async t => {
  const f = await ingressFixture(t);
  const opened = await send(f.address.port, { body: initialize });
  const headers = { "mcp-session-id": opened.headers["mcp-session-id"] as string, "mcp-protocol-version": "2025-11-25" };
  const original = f.options.verifier.verify;
  let calls = 0;
  f.options.verifier.verify = async token => {
    const claims = await original(token); calls++;
    return calls === 2 ? { ...claims, subject: "bob" } : claims;
  };
  const body = { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "portfolio.read", arguments: { portfolioId: "p-1" } } };
  const rejected = await send(f.address.port, { headers, body });
  assert.match(rejected.body, /isError/); assert.equal(calls, 2); assert.equal(f.execution.effects.length, 0);
  f.options.verifier.verify = async token => { const claims = await original(token); f.revoke(); return claims; };
  await send(f.address.port, { headers, body }).catch(() => {});
  await delay(40); assert.equal(f.execution.effects.length, 0);
});

test("authentication time is charged to the original high-resolution request timestamp", async t => {
  const f = await ingressFixture(t), e = f.execution;
  const opened = await send(f.address.port, { body: initialize });
  const headers = { "mcp-session-id": opened.headers["mcp-session-id"] as string, "mcp-protocol-version": "2025-11-25" };
  const verify = f.options.verifier.verify;
  f.options.verifier.verify = async token => { const claims = await verify(token); e.advance(1234567n); return claims; };
  const pending = send(f.address.port, { headers, body: { jsonrpc: "2.0", id: 2, method: "tools/call",
    params: { name: "portfolio.read", arguments: { portfolioId: "p-1" } } } });
  void pending.catch(() => {});
  await until(() => e.effects.includes("authorize")); e.authorize();
  await until(() => e.effects.includes("upstream")); e.upstream.resolve(envelope());
  await until(() => e.events.length === 1);
  assert.equal(e.events[0].data!.started_at_unix_us, e.original.unixUs.toString());
  assert.equal(e.events[0].data!.duration_ns, "1234567");
  assert.equal(e.events[0].data!.generation, "9007199254740993");
  assert.equal(e.events[0].data!.process_instance_id, f.options.stage.documents.launch.processInstanceId);
  e.evidenceReply.resolve(Buffer.alloc(0)); e.rawClosed.resolve(); e.completionClosed.resolve(); e.evidenceClosed.resolve();
  assert.equal((await pending).status, 200);
});

test("a delayed verifier cannot reset an expired original call deadline", async t => {
  const f = await ingressFixture(t);
  const opened = await send(f.address.port, { body: initialize });
  const verify = f.options.verifier.verify;
  f.options.verifier.verify = async token => { const claims = await verify(token); f.execution.advance(120000000000n); return claims; };
  const response = await send(f.address.port, { headers: { "mcp-session-id": opened.headers["mcp-session-id"] as string,
    "mcp-protocol-version": "2025-11-25" }, body: { jsonrpc: "2.0", id: 2, method: "tools/call",
    params: { name: "portfolio.read", arguments: { portfolioId: "p-1" } } } });
  assert.equal(response.status, 400); assert.equal(f.execution.effects.length, 0);
});
