import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import process from "node:process";

const packageRoot = new URL("..", import.meta.url);
const portfolioId = process.env.APEX_MCP_PROOF_PORTFOLIO ?? "northstar-401k";
const traceId = process.env.APEX_MCP_TRACE_ID ?? `mcp-live-proof-${Date.now()}`;

const childEnvironment = Object.fromEntries(
  Object.entries({
    ...process.env,
    APEX_MCP_GOVERNANCE_MODE: "live",
    APEX_MCP_TRACE_ID: traceId,
    APEX_MCP_AGENT_ID: process.env.APEX_MCP_AGENT_ID ?? "reference-agent",
    APEX_MCP_WORKSPACE_ID: process.env.APEX_MCP_WORKSPACE_ID ?? "acme",
    APEX_MCP_NAMESPACE_ID: process.env.APEX_MCP_NAMESPACE_ID ?? "prod",
    APEX_MCP_PRINCIPAL:
      process.env.APEX_MCP_PRINCIPAL ?? "spiffe://apex/agent/reference",
  }).filter(([, value]) => typeof value === "string"),
);

const transport = new StdioClientTransport({
  command: process.execPath,
  args: ["dist/index.js"],
  cwd: new URL(".", packageRoot),
  env: childEnvironment,
  stderr: "inherit",
});
const client = new Client({ name: "apex-live-proof", version: "0.1.0" });

try {
  await client.connect(transport);
  const result = await client.callTool({
    name: "portfolio.read",
    arguments: { portfolioId },
  });
  if (result.isError || typeof result.structuredContent !== "object") {
    const safeText = result.content
      ?.filter((item) => item.type === "text")
      .map((item) => item.text)
      .join(" ");
    throw new Error(`live MCP tool call was rejected${safeText ? `: ${safeText}` : ""}`);
  }

  const serialized = JSON.stringify(result.structuredContent);
  for (const forbidden of ["client-record-raw", "tax-record-raw", "costBasis"]) {
    if (serialized.includes(forbidden)) {
      throw new Error("live MCP result contained restricted portfolio data");
    }
  }
  if (!serialized.includes("Northstar Research")) {
    throw new Error("live MCP result did not contain the expected public view");
  }
  console.log(`MCP_LIVE_PROOF trace=${traceId} portfolio=${portfolioId}`);
} finally {
  await client.close().catch(() => undefined);
  await transport.close().catch(() => undefined);
}
