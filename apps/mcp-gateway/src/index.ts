import { readFile } from "node:fs/promises";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { GatewayError } from "./contracts.js";
import { GatewayExecutor } from "./execution.js";
import { ManagedHttpServer } from "./managed/http-server.js";
import { parseProxyRevisionConfig } from "./managed/config.js";
import { buildManagedRuntime } from "./live/managed-runtime.js";
import { createMcpServer } from "./server.js";
import { buildGatewayDependencies } from "./wiring.js";

async function main(): Promise<void> {
  const revisionConfig = await loadRevisionConfig(process.env);
  if (revisionConfig?.ingress.transport === "streamable-http") {
    const runtime = await buildManagedRuntime(revisionConfig, process.env);
    const server = new ManagedHttpServer({
      config: revisionConfig,
      verifier: runtime.verifier,
      executor: runtime.executor,
      host: process.env.APEX_MCP_LISTEN_HOST?.trim() || "127.0.0.1",
      port: parseListenPort(process.env.APEX_MCP_LISTEN_PORT),
    });
    await server.start();
    const shutdown = () => {
      void server.close().catch(() => {
        process.exitCode = 1;
      });
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
    return;
  }
  const executor = new GatewayExecutor(buildGatewayDependencies());
  const server = createMcpServer(executor);
  const transport = new StdioServerTransport();

  await server.connect(transport);
}

function parseListenPort(value: string | undefined): number {
  if (value === undefined || value.trim().length === 0) {
    return 8080;
  }
  if (!/^\d+$/.test(value.trim())) {
    throw new GatewayError("INVALID_INPUT", "managed HTTP listener configuration rejected safely");
  }
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new GatewayError("INVALID_INPUT", "managed HTTP listener configuration rejected safely");
  }
  return port;
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
