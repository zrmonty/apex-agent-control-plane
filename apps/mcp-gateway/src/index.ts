import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { LocalPortfolioAdapter } from "./adapters/portfolio.js";
import { GatewayError } from "./contracts.js";
import { parseAuthenticatedContext } from "./context.js";
import { GatewayExecutor } from "./execution.js";
import { StaticLocalApex } from "./governance/local.js";
import { createMcpServer } from "./server.js";

function parseAllowedPortfolios(value: string | undefined): readonly string[] {
  if (value === undefined || value.trim().length === 0) {
    return ["northstar-401k"];
  }

  return value
    .split(",")
    .map((portfolioId) => portfolioId.trim())
    .filter((portfolioId) => portfolioId.length > 0);
}

async function main(): Promise<void> {
  const context = parseAuthenticatedContext(process.env);
  const apex = new StaticLocalApex({
    allowedPortfolios: parseAllowedPortfolios(process.env.APEX_MCP_ALLOWED_PORTFOLIOS),
  });
  const executor = new GatewayExecutor({
    context,
    governance: apex,
    events: apex,
    portfolio: new LocalPortfolioAdapter(),
  });
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
