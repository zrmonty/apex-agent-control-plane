import assert from "node:assert/strict";
import test from "node:test";

import type { UpstreamConfig } from "./config.js";
import { createOutboundCredentialProvider } from "./auth.js";
import { McpHttpUpstreamTransport } from "./mcp-http-transport.js";

const upstream = {
  upstreamId: "portfolio",
  transport: "streamable-http",
  endpointOrCommandRef: "https://portfolio.example.test/mcp",
  credentialRef: "secret://portfolio/read",
} as const satisfies UpstreamConfig;

test("uses the official MCP HTTP client with an isolated outbound credential", async () => {
  const requests: Array<{ body: Record<string, unknown> | undefined; headers: Headers }> = [];
  let resolves = 0;
  const fetch = async (_url: string | URL, init?: RequestInit): Promise<Response> => {
    const body = typeof init?.body === "string" ? JSON.parse(init.body) as Record<string, unknown> : undefined;
    requests.push({ body, headers: new Headers(init?.headers) });
    if (body?.method === "notifications/initialized") {
      return new Response(null, { status: 202 });
    }
    if (body?.method === "initialize") {
      return jsonResponse({
        jsonrpc: "2.0",
        id: body.id,
        result: {
          protocolVersion: "2025-06-18",
          capabilities: { tools: {} },
          serverInfo: { name: "fixture", version: "1.0.0" },
        },
      });
    }
    if (body?.method === "tools/list") {
      return jsonResponse({
        jsonrpc: "2.0",
        id: body.id,
        result: { tools: [{ name: "portfolio.read", inputSchema: { type: "object" } }] },
      });
    }
    if (body?.method === "tools/call") {
      return jsonResponse({
        jsonrpc: "2.0",
        id: body.id,
        result: { content: [{ type: "text", text: "fixture response" }] },
      });
    }
    return new Response(null, { status: 404 });
  };
  const credentialProvider = createOutboundCredentialProvider({
    async resolve(reference) {
      resolves += 1;
      assert.equal(reference, upstream.credentialRef);
      return "outbound-token-123456";
    },
  });
  const transport = new McpHttpUpstreamTransport(credentialProvider, {
    fetch,
    resolveAddresses: async () => ["93.184.216.34"],
  });

  const discovered = await transport.discover(upstream) as { tools: readonly [{ name: string }] };
  const result = await transport.call(upstream, "portfolio.read", { portfolioId: "northstar-401k" }) as {
    content: readonly [{ text: string }];
  };
  await transport.close(upstream);

  assert.equal(discovered.tools[0].name, "portfolio.read");
  assert.equal(result.content[0].text, "fixture response");
  assert.equal(resolves, 1);
  assert.ok(requests.length >= 3);
  for (const request of requests) {
    assert.equal(request.headers.get("authorization"), "Bearer outbound-token-123456");
    assert.equal(request.headers.get("cookie"), null);
    assert.equal(request.headers.get("x-inbound-token"), null);
  }
});

test("rejects a resolved private upstream address before connecting", async () => {
  const transport = new McpHttpUpstreamTransport(
    createOutboundCredentialProvider({ resolve: async () => "outbound-token-123456" }),
    {
      fetch: async () => { throw new Error("must not connect"); },
      resolveAddresses: async () => ["127.0.0.1"],
    },
  );

  await assert.rejects(() => transport.discover(upstream), /INVALID_INPUT/);
});

test("bounds streamed upstream responses even without a content-length header", async () => {
  const fetch = async (_url: string | URL, init?: RequestInit): Promise<Response> => {
    const body = typeof init?.body === "string" ? JSON.parse(init.body) as { method: string; id?: number } : undefined;
    if (body?.method === "notifications/initialized") {
      return new Response(null, { status: 202 });
    }
    if (body?.method === "initialize") {
      return jsonResponse({
        jsonrpc: "2.0",
        id: body.id,
        result: {
          protocolVersion: "2025-06-18",
          capabilities: { tools: {} },
          serverInfo: { name: "fixture", version: "x".repeat(512) },
        },
      });
    }
    return jsonResponse({
      jsonrpc: "2.0",
      id: body?.id,
      result: { tools: [{ name: "portfolio.read", description: "x".repeat(512), inputSchema: { type: "object" } }] },
    });
  };
  const transport = new McpHttpUpstreamTransport(
    createOutboundCredentialProvider({ resolve: async () => "outbound-token-123456" }),
    { fetch, resolveAddresses: async () => ["93.184.216.34"], maxResponseBytes: 256 },
  );

  await assert.rejects(() => transport.discover(upstream), /ADAPTER_FAILED/);
});

test("reuses a fresh validated address resolution and refreshes it after the TTL", async () => {
  let resolveCalls = 0;
  let now = 10_000;
  const transport = new McpHttpUpstreamTransport(
    createOutboundCredentialProvider({ resolve: async () => "outbound-token-123456" }),
    {
      fetch: async (_url, init) => {
        const body = typeof init?.body === "string" ? JSON.parse(init.body) as { method: string; id?: number } : undefined;
        if (body?.method === "notifications/initialized") return new Response(null, { status: 202 });
        if (body?.method === "initialize") {
          return jsonResponse({
            jsonrpc: "2.0",
            id: body.id,
            result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "fixture", version: "1" } },
          });
        }
        return jsonResponse({ jsonrpc: "2.0", id: body?.id, result: { tools: [{ name: "portfolio.read", inputSchema: { type: "object" } }] } });
      },
      resolveAddresses: async () => {
        resolveCalls += 1;
        return ["93.184.216.34"];
      },
      addressCacheTtlMs: 1_000,
      now: () => now,
    },
  );

  try {
    await transport.discover(upstream);
    assert.equal(resolveCalls, 1, "a fresh discovery should be reused by MCP handshake requests");

    now += 1_001;
    await transport.discover(upstream);
    assert.equal(resolveCalls, 2, "expired address data should be refreshed");
  } finally {
    await transport.close(upstream).catch(() => undefined);
  }
});

test("revalidates refreshed addresses instead of trusting a stale safe result", async () => {
  let now = 10_000;
  const addresses = [["93.184.216.34"], ["127.0.0.1"]];
  const transport = new McpHttpUpstreamTransport(
    createOutboundCredentialProvider({ resolve: async () => "outbound-token-123456" }),
    {
      fetch: async (_url, init) => {
        const body = typeof init?.body === "string" ? JSON.parse(init.body) as { method: string; id?: number } : undefined;
        if (body?.method === "notifications/initialized") return new Response(null, { status: 202 });
        if (body?.method === "initialize") {
          return jsonResponse({
            jsonrpc: "2.0",
            id: body.id,
            result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "fixture", version: "1" } },
          });
        }
        return jsonResponse({ jsonrpc: "2.0", id: body?.id, result: { tools: [{ name: "portfolio.read", inputSchema: { type: "object" } }] } });
      },
      resolveAddresses: async () => addresses.shift() ?? ["127.0.0.1"],
      addressCacheTtlMs: 1_000,
      now: () => now,
    },
  );

  try {
    await transport.discover(upstream);
    now += 1_001;
    await assert.rejects(() => transport.discover(upstream), /INVALID_INPUT/);
  } finally {
    await transport.close(upstream).catch(() => undefined);
  }
});

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}
