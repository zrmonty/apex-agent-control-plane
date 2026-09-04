import assert from "node:assert/strict";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { LocalPortfolioAdapter } from "./adapters/portfolio.js";
import type { ApexEvents, EventReceipt, SafeTelemetry } from "./contracts.js";
import { GatewayExecutor } from "./execution.js";
import { StaticLocalApex } from "./governance/local.js";
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
  assert.equal(result.tools[0]?.inputSchema.additionalProperties, false);
  assert.deepEqual(Object.keys(result.tools[0]?.inputSchema.properties ?? {}).sort(), [
    "asOf",
    "portfolioId",
  ]);

  await client.close();
  await server.close();
});

test("normalizes SDK input validation failures to the safe invalid-input result", async () => {
  const apex = new StaticLocalApex();
  const executor = new GatewayExecutor({
    context: {
      principal: "spiffe://apex/agent/research",
      agentId: "research-agent",
      workspaceId: "northstar",
      namespaceId: "research",
      traceId: "trace-001",
    },
    governance: apex,
    events: apex,
    portfolio: new LocalPortfolioAdapter(),
  });
  const server = createMcpServer(executor);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "gateway-test", version: "0.1.0" });

  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  const result = (await client.callTool({
    name: "portfolio.read",
    arguments: {
      portfolioId: "northstar-401k",
      leakedInputKey: "must-not-echo",
    },
  })) as CallToolResult;

  assert.equal(result.isError, true);
  assert.equal(result.content[0]?.type, "text");
  assert.equal(result.content[0]?.text, "INVALID_INPUT: request rejected safely");
  assert.equal(result.content[0]?.text.includes("leakedInputKey"), false);
  assert.equal(result.content[0]?.text.includes("must-not-echo"), false);

  await client.close();
  await server.close();
});

test("preserves denied results when both event and safe telemetry sinks fail", async () => {
  class FailingEvents implements ApexEvents {
    async emit(_event: Parameters<ApexEvents["emit"]>[0]): Promise<EventReceipt> {
      throw new Error("raw event sink failure");
    }
  }

  class FailingTelemetry implements SafeTelemetry {
    record(): void {
      throw new Error("raw telemetry sink failure");
    }
  }

  const governance = new StaticLocalApex({ allowedPortfolios: [] });
  const executor = new GatewayExecutor({
    context: {
      principal: "spiffe://apex/agent/research",
      agentId: "research-agent",
      workspaceId: "northstar",
      namespaceId: "research",
      traceId: "trace-001",
    },
    governance,
    events: new FailingEvents(),
    portfolio: new LocalPortfolioAdapter(),
    telemetry: new FailingTelemetry(),
  });
  const server = createMcpServer(executor);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "gateway-test", version: "0.1.0" });

  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  const result = (await client.callTool({
    name: "portfolio.read",
    arguments: { portfolioId: "northstar-401k" },
  })) as CallToolResult;

  assert.equal(result.isError, true);
  assert.equal(result.content[0]?.type, "text");
  assert.equal(result.content[0]?.text, "AUTHORIZATION_DENIED: request rejected safely");
  assert.equal(result.content[0]?.text.includes("raw"), false);

  await client.close();
  await server.close();
});
