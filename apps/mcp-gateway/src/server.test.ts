import assert from "node:assert/strict";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { createMcpServer } from "./server.js";
import type { PortfolioReadExecutor } from "./server.js";

test("exposes only the read-only portfolio tool", async () => {
  const executor: PortfolioReadExecutor = {
    executePortfolioRead: async (): Promise<CallToolResult> => ({
      content: [{ type: "text", text: "{}" }],
    }),
  };
  const server = createMcpServer(executor);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "gateway-test", version: "0.1.0" });

  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  const result = await client.listTools();

  assert.deepEqual(result.tools.map((tool) => tool.name), ["portfolio.read"]);
  assert.equal(result.tools.some((tool) => tool.name === "portfolio.write"), false);
  assert.equal(result.tools.some((tool) => tool.name === "portfolio.trade"), false);

  await client.close();
  await server.close();
});
