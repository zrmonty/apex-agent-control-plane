import { readFile } from "node:fs/promises";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { GatewayError } from "./contracts.js";
import { GatewayExecutor } from "./execution.js";
import { parseProxyRevisionConfig } from "./managed/config.js";
import { createMcpServer } from "./server.js";
import { buildGatewayDependencies } from "./wiring.js";

async function main(): Promise<void> {
  const revisionConfig = await loadRevisionConfig(process.env);
  if (revisionConfig?.ingress.transport === "streamable-http") {
    throw new GatewayError(
      "GOVERNANCE_UNAVAILABLE",
      "managed HTTP ingress is not available in this runtime",
    );
  }
  const executor = new GatewayExecutor(buildGatewayDependencies());
  const server = createMcpServer(executor);
  const transport = new StdioServerTransport();

  await server.connect(transport);
}

async function loadRevisionConfig(env: NodeJS.ProcessEnv) {
  const file = env.APEX_MCP_PROXY_REVISION_CONFIG_FILE?.trim();
  const serialized = env.APEX_MCP_PROXY_REVISION_CONFIG?.trim();
  if (file !== undefined && file.length > 0 && serialized !== undefined && serialized.length > 0) {
    throw new GatewayError(
      "INVALID_INPUT",
      "managed proxy configuration rejected safely",
    );
  }
  if ((file === undefined || file.length === 0) && (serialized === undefined || serialized.length === 0)) {
    return undefined;
  }

  try {
    const payload = file !== undefined && file.length > 0
      ? await readFile(file, "utf8")
      : serialized ?? "";
    return parseProxyRevisionConfig(JSON.parse(payload));
  } catch (error: unknown) {
    if (error instanceof GatewayError) {
      throw error;
    }
    throw new GatewayError("INVALID_INPUT", "managed proxy configuration rejected safely");
  }
}

main().catch((error: unknown) => {
  const message =
    error instanceof GatewayError ? error.message : "GOVERNANCE_UNAVAILABLE: gateway startup failed";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
