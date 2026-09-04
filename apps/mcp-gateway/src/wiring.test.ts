import assert from "node:assert/strict";
import test from "node:test";

import { GatewayError } from "./contracts.js";
import { buildGatewayDependencies } from "./wiring.js";

const context = {
  APEX_MCP_PRINCIPAL: "spiffe://apex/agent/research",
  APEX_MCP_AGENT_ID: "research-agent",
  APEX_MCP_WORKSPACE_ID: "northstar",
  APEX_MCP_NAMESPACE_ID: "research",
  APEX_MCP_TRACE_ID: "trace-001",
};

test("live mode refuses incomplete client configuration", () => {
  assert.throws(
    () => buildGatewayDependencies({ ...context, APEX_MCP_GOVERNANCE_MODE: "live" }),
    (error: unknown) => error instanceof GatewayError && error.code === "GOVERNANCE_UNAVAILABLE",
  );
});

test("local mode remains explicit and supplies the deterministic adapter", () => {
  const dependencies = buildGatewayDependencies(context);
  assert.equal(dependencies.backend, "local-portfolio");
  assert.equal(dependencies.context.agentId, "research-agent");
});
