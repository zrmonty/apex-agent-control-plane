import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { PortfolioReadInputSchema, type PortfolioReadInput } from "./schemas.js";

export interface PortfolioReadExecutor {
  executePortfolioRead(input: unknown): Promise<CallToolResult>;
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

  return server;
}
