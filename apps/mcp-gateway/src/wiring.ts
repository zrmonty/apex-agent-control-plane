import { LocalPortfolioAdapter } from "./adapters/portfolio.js";
import { GatewayError } from "./contracts.js";
import { parseAuthenticatedContext } from "./context.js";
import type { GatewayDependencies } from "./execution.js";
import { createLiveEventsClient } from "./live/events.js";
import { loadLiveConfig } from "./live/config.js";
import { createLiveGovernanceClient } from "./live/governance.js";
import { StaticLocalApex } from "./governance/local.js";

export function buildGatewayDependencies(
  env: NodeJS.ProcessEnv = process.env,
): GatewayDependencies {
  const context = parseAuthenticatedContext(env);
  const mode = env.APEX_MCP_GOVERNANCE_MODE?.trim() || "local";
  if (mode === "live") {
    const config = loadLiveConfig(env);
    return {
      context,
      governance: createLiveGovernanceClient(config.governance, config.trustedSecretBase),
      events: createLiveEventsClient(config.events, config.trustedSecretBase),
      portfolio: new LocalPortfolioAdapter(),
      backend: "local-portfolio",
    };
  }
  if (mode !== "local") {
    throw new GatewayError("INVALID_INPUT", "request rejected safely");
  }
  const apex = new StaticLocalApex({
    allowedPortfolios: parseAllowedPortfolios(env.APEX_MCP_ALLOWED_PORTFOLIOS),
  });
  return {
    context,
    governance: apex,
    events: apex,
    portfolio: new LocalPortfolioAdapter(),
    backend: "local-portfolio",
  };
}

function parseAllowedPortfolios(value: string | undefined): readonly string[] {
  if (value === undefined || value.trim().length === 0) {
    return ["northstar-401k"];
  }
  return value
    .split(",")
    .map((portfolioId) => portfolioId.trim())
    .filter((portfolioId) => portfolioId.length > 0);
}
