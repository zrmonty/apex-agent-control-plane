import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { GatewayError } from "./contracts.js";
import { GatewayExecutor } from "./execution.js";
import { ManagedHttpServer } from "./managed/http-server.js";
import { loadRuntimeConfiguration } from "./managed/startup-loader.js";
import { buildManagedRuntime } from "./live/managed-runtime.js";
import { createMcpServer } from "./server.js";
import { selectStartupProfile } from "./startup-profile.js";
import { buildGatewayDependencies } from "./wiring.js";

async function main(): Promise<void> {
  const profile = selectStartupProfile(process.env);
  if (profile === "managed") {
    const revisionConfig = await loadRuntimeConfiguration(process.env);
    if (revisionConfig === undefined) {
      throw new GatewayError("INVALID_INPUT", "managed runtime configuration rejected safely");
    }
    const runtime = await buildManagedRuntime(revisionConfig, process.env);
    const server = new ManagedHttpServer({
      config: revisionConfig,
      verifier: runtime.verifier,
      executor: runtime.executor,
      host: process.env.APEX_MCP_LISTEN_HOST?.trim() || "127.0.0.1",
      port: parseListenPort(process.env.APEX_MCP_LISTEN_PORT),
    });
    try {
      await server.start();
    } catch (error) {
      await server.close().catch(() => undefined);
      throw error;
    }
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

main().catch((error: unknown) => {
  const message =
    error instanceof GatewayError ? error.message : "GOVERNANCE_UNAVAILABLE: gateway startup failed";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
