import test from "node:test";
import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import { ingressFixture, initialize, send, until } from "./fixture.js";

for (const method of ["tools/list", "tools/call"] as const) {
 for (const id of [0, 2]) {
  test(`${method} id ${id} cancellation closes its stream during dispatch verification while retaining verifier ownership`, async t => {
    const f = await ingressFixture(t, { cleanupMs: 50 });
    const opened = await send(f.address.port, { body: initialize });
    const headers = { "mcp-session-id": opened.headers["mcp-session-id"] as string,
      "mcp-protocol-version": "2025-11-25" };
    const verify = f.options.verifier.verify;
    let release!: () => void, calls = 0, ended = false, closed = false;
    const held = new Promise<void>(resolve => { release = resolve; });
    f.options.verifier.verify = async token => {
      if (++calls === 2) await held;
      return verify(token);
    };
    const pending = send(f.address.port, { headers, body: { jsonrpc: "2.0", id, method,
      ...(method === "tools/call" ? { params: { name: "portfolio.read", arguments: { portfolioId: "p-1" } } } : {}) } });
    void pending.then(() => { ended = true; }, () => { ended = true; });
    try {
      await until(() => calls === 2);
      assert.equal((await send(f.address.port, { headers, body: { jsonrpc: "2.0", method: "notifications/cancelled",
        params: { requestId: id } } })).status, 202);
      await until(() => ended);
      assert.equal(f.execution.effects.length, 0);
      assert.equal((await send(f.address.port, { headers, body: { jsonrpc: "2.0", id: 3, method: "tools/list" } })).status, 200);
      void f.ingress.closed.then(() => { closed = true; }); f.ingress.cancel();
      await delay(100); assert.equal(closed, false); assert.equal(f.fatals, 1);
      release(); await f.ingress.closed;
      assert.equal(f.execution.effects.length, 0, "late verification must not start cancelled work");
    } finally { release(); await pending.catch(() => {}); }
  });
 }
}
