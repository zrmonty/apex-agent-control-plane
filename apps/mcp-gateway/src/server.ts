import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  CallToolRequestSchema,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

import { PortfolioReadInputSchema, type PortfolioReadInput } from "./schemas.js";

export interface PortfolioReadExecutor {
  executePortfolioRead(input: unknown): Promise<CallToolResult>;
}

function invalidInputResult(): CallToolResult {
  return {
    isError: true,
    content: [{ type: "text", text: "INVALID_INPUT: request rejected safely" }],
  };
}

export function createMcpServer(executor: PortfolioReadExecutor): McpServer {
  const server = new McpServer({
    name: "apex-mcp-gateway",
    version: "0.1.0",
  });

  server.registerTool(
    "portfolio.read",
    {
      title: "portfolio.read",
      inputSchema: PortfolioReadInputSchema,
    },
    async (input: PortfolioReadInput) => executor.executePortfolioRead(input),
  );

  server.server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (request.params.name !== "portfolio.read") {
      return invalidInputResult();
    }

    return executor.executePortfolioRead(request.params.arguments);
  });

  return server;
}
