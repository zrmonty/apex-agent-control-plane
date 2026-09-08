import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { GatewayError } from "./contracts.js";
import { GatewayExecutor } from "./execution.js";
import { runManagedProcess } from "./managed/process.js";
import { createMcpServer } from "./server.js";
import { selectStartupProfile } from "./startup-profile.js";
import { buildGatewayDependencies } from "./wiring.js";

async function main(): Promise<void> {
  const profile = selectStartupProfile(process.env);
  if (profile === "managed") {
    process.exitCode = await runManagedProcess(process.env);
    return;
  }
  const executor = new GatewayExecutor(buildGatewayDependencies());
  const server = createMcpServer(executor);
  const transport = new StdioServerTransport();

  await server.connect(transport);
}

main().catch((error: unknown) => {
  const message =
    error instanceof GatewayError ? error.message : "GOVERNANCE_UNAVAILABLE: gateway startup failed";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
