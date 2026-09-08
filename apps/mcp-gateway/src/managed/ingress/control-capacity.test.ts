import test from "node:test";
import assert from "node:assert/strict";
import { ingressFixture, initialize, send, until } from "./fixture.js";

for (const scope of ["global", "session"] as const) {
  for (const control of ["cancel", "delete"] as const) {
    test(`${control} remains available at ${scope} ordinary request saturation`, async t => {
      const f = await ingressFixture(t, scope === "global" ? { requests: 1 } : { sessionRequests: 1 });
      const opened = await send(f.address.port, { body: initialize });
      const headers = { "mcp-session-id": opened.headers["mcp-session-id"] as string,
        "mcp-protocol-version": "2025-11-25" };
      const pending = send(f.address.port, { headers, body: { jsonrpc: "2.0", id: 2, method: "tools/call",
        params: { name: "portfolio.read", arguments: { portfolioId: "p-1" } } } });
      let ended = false; void pending.then(() => { ended = true; }, () => { ended = true; });
      try {
        await until(() => f.execution.effects.includes("authorize")); f.execution.authorize();
        await until(() => f.execution.effects.includes("upstream"));
        assert.equal((await send(f.address.port, { headers, body: { jsonrpc: "2.0", id: 3, method: "tools/list" } })).status, 503);
        assert.equal((await send(f.address.port, { headers, body: { jsonrpc: "2.0", method: "notifications/initialized" } })).status, 503);
        for (const invalid of [
          { jsonrpc: "2.0", method: "notifications/cancelled", params: {} },
          { jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: {} } },
          { jsonrpc: "2.0", id: 3, method: "notifications/cancelled", params: { requestId: 2 } },
        ]) assert.equal((await send(f.address.port, { headers, body: invalid })).status, 503);
        assert.ok([404, 503].includes((await send(f.address.port, { headers, token: "bob", method: "DELETE" })).status));
        const result = await send(f.address.port, control === "delete" ? { headers, method: "DELETE" } : {
          headers, body: { jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 2 } },
        });
        assert.equal(result.status, control === "delete" ? 200 : 202);
        await until(() => f.execution.effects.includes("cancel-upstream"));
        await until(() => ended);
        assert.equal(f.execution.effects.includes("released"), false);
      } finally { await f.execution.cleanup(); await pending.catch(() => {}); }
    });
  }
}

test("abandoned control verification cannot replenish the bounded control reserve", async t => {
  const f = await ingressFixture(t, { requests: 1, controlRequests: 1 });
  const opened = await send(f.address.port, { body: initialize });
  const headers = { "mcp-session-id": opened.headers["mcp-session-id"] as string,
    "mcp-protocol-version": "2025-11-25" };
  const work = send(f.address.port, { headers, body: { jsonrpc: "2.0", id: 2, method: "tools/call",
    params: { name: "portfolio.read", arguments: { portfolioId: "p-1" } } } });
  void work.catch(() => {});
  await until(() => f.execution.effects.includes("authorize")); f.execution.authorize();
  await until(() => f.execution.effects.includes("upstream"));
  const verify = f.options.verifier.verify;
  let release!: () => void, checks = 0;
  const held = new Promise<void>(resolve => { release = resolve; });
  f.options.verifier.verify = async token => { checks++; await held; return verify(token); };
  const abort = new AbortController();
  const control = send(f.address.port, { headers, method: "DELETE", signal: abort.signal }); void control.catch(() => {});
  try {
    await until(() => checks === 1); abort.abort(); await control.catch(() => {});
    assert.equal((await send(f.address.port, { headers, method: "DELETE" })).status, 503);
    assert.equal(checks, 1);
    assert.equal(f.execution.effects.includes("cancel-upstream"), false);
    release();
    // Wait for actual verifier settlement before checking capacity recovery.
    await new Promise(resolve => setTimeout(resolve, 20));
    assert.equal((await send(f.address.port, { headers, method: "DELETE" })).status, 200);
    await until(() => f.execution.effects.includes("cancel-upstream"));
  } finally { release(); await f.execution.cleanup(); await work.catch(() => {}); }
});
