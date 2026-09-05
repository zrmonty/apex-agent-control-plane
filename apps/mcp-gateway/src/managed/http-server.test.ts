import assert from "node:assert/strict";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import type { InboundTokenClaims } from "./auth.js";
import { componentFixture } from "./testing/runtime-fixture.js";
import { loopbackFetch } from "./testing/loopback-fetch.js";
import { buildManagedToolCatalog, ManagedHttpServer, type ManagedCallExecutor } from "./http-server.js";

const proxyId = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84";
const config = componentFixture();

const claims: InboundTokenClaims = {
  issuer: "https://issuer.example.test",
  audience: "https://proxy.example.test/mcp",
  subject: "operator:alice",
  expiresAt: Math.floor(Date.now() / 1000) + 300,
  scope: "mcp:proxy:invoke",
  proxyId,
};

test("serves a governed MCP call over Streamable HTTP with session isolation", async () => {
  const calls: Array<{ alias: string; input: unknown }> = [];
  const executor: ManagedCallExecutor = {
    async execute(alias, input, headers) {
      calls.push({ alias, input });
      assert.deepEqual(headers.authorization, ["Bearer signed-token"]);
      return { portfolioId: (input as { portfolioId: string }).portfolioId, status: "safe" };
    },
    async close() {},
  };
  const server = new ManagedHttpServer({
    config,
    verifier: { async verify(token) { assert.equal(token, "signed-token"); return claims; } },
    executor,
    host: "127.0.0.1",
    port: 18443,
  });
  const address = await server.start();
  const client = new Client({ name: "fixture-client", version: "1.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(config.resourceUrl), {
    fetch: async (_url, init) => loopbackFetch(`http://127.0.0.1:${address.port}/mcp`, {
      ...init,
      headers: {
        ...Object.fromEntries(new Headers(init?.headers).entries()),
        origin: "https://console.example.test", host: "proxy.example.test",
      },
    }),
    requestInit: { headers: { authorization: "Bearer signed-token" } },
  });

  try {
    await client.connect(transport);
    const tools = await client.listTools();
    const result = await client.callTool({
      name: "portfolio.read",
      arguments: { portfolioId: "northstar-401k" },
    });

    assert.equal(tools.tools[0].name, "portfolio.read");
    assert.deepEqual(result.structuredContent, { portfolioId: "northstar-401k", status: "safe" });
    assert.deepEqual(calls, [{ alias: "portfolio.read", input: { portfolioId: "northstar-401k" } }]);
  } finally {
    await client.close().catch(() => undefined);
    await server.close();
  }
});

test("builds an immutable managed tool catalog once per server configuration", () => {
  const catalog = buildManagedToolCatalog(config);
  assert.equal(Object.isFrozen(catalog), true);
  assert.equal(catalog.length, 1);
  assert.equal(catalog[0].name, "portfolio.read");
  assert.equal(catalog[0].inputSchema.type, "object");
});

test("returns a bearer challenge before MCP processing for invalid auth", async () => {
  const server = new ManagedHttpServer({
    config,
    verifier: { async verify() { throw new Error("invalid"); } },
    executor: { async execute() { throw new Error("must not execute"); }, async close() {} },
    host: "127.0.0.1",
    port: 18443,
  });
  const address = await server.start();

  try {
    const response = await loopbackFetch(`http://127.0.0.1:${address.port}/mcp`, {
      method: "POST",
      headers: {
        origin: "https://console.example.test",
        host: "proxy.example.test",
        "content-type": "application/json",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    });

    assert.equal(response.status, 401);
    assert.match(response.headers.get("www-authenticate") ?? "", /^Bearer resource_metadata=/);
  } finally {
    await server.close();
  }
});

test("serves protected-resource metadata at the advertised challenge URL", async () => {
  const server = new ManagedHttpServer({
    config,
    verifier: { async verify() { throw new Error("must not verify metadata"); } },
    executor: { async execute() { throw new Error("must not execute"); }, async close() {} },
    host: "127.0.0.1",
    port: 18443,
  });
  const address = await server.start();

  try {
    const response = await loopbackFetch(`http://127.0.0.1:${address.port}/.well-known/oauth-protected-resource`, { headers: { host: "proxy.example.test" } });

    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
      resource: config.resourceUrl,
      authorization_servers: ["https://issuer.example.test"],
      bearer_methods_supported: ["header"],
      scopes_supported: ["mcp:proxy:invoke"],
    });
  } finally {
    await server.close();
  }
});

test("refuses unsupported initialize body protocols before creating an MCP session", async () => {
  let calls = 0;
  const server = new ManagedHttpServer({ config, host: "127.0.0.1", port: 0,
    verifier: { async verify() { return claims; } },
    executor: { async execute() { calls++; }, async close() {} } });
  const address = await server.start();
  try {
    for (const protocolVersion of ["2025-06-18", "SENSITIVE-unsupported", undefined]) {
      const response = await loopbackFetch(`http://127.0.0.1:${address.port}/mcp`, {
        method: "POST", headers: { host: "proxy.example.test", origin: "https://console.example.test",
          authorization: "Bearer signed-token", "content-type": "application/json", accept: "application/json, text/event-stream" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {
          protocolVersion, capabilities: {}, clientInfo: { name: "fixture-client", version: "1" } } }),
      });
      assert.equal(response.status, 400);
      assert.equal(response.headers.get("mcp-session-id"), null);
      assert.deepEqual(await response.json(), { error: "request rejected safely" });
    }
    assert.equal(calls, 0);
  } finally { await server.close(); }
});
