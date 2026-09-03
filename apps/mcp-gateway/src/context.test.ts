import assert from "node:assert/strict";
import test from "node:test";

import {
  GatewayError,
  buildPortfolioReadAuthorizationRequest,
  parseAuthenticatedContext,
} from "./context.js";

test("context parser requires authenticated identity and exact scope", () => {
  assert.deepEqual(
    parseAuthenticatedContext({
      APEX_MCP_PRINCIPAL: "spiffe://apex/agent/research",
      APEX_MCP_AGENT_ID: "research-agent",
      APEX_MCP_WORKSPACE_ID: "northstar",
      APEX_MCP_NAMESPACE_ID: "research",
      APEX_MCP_TRACE_ID: "trace-001",
    }),
    {
      principal: "spiffe://apex/agent/research",
      agentId: "research-agent",
      workspaceId: "northstar",
      namespaceId: "research",
      traceId: "trace-001",
    },
  );
});

test("context parser rejects missing or malformed variables without echoing values", () => {
  assert.throws(
    () =>
      parseAuthenticatedContext({
        APEX_MCP_PRINCIPAL: "spiffe://apex/agent/research",
        APEX_MCP_AGENT_ID: "research-agent",
        APEX_MCP_WORKSPACE_ID: "",
        APEX_MCP_NAMESPACE_ID: "research",
        APEX_MCP_TRACE_ID: "trace secret value",
      }),
    (error: unknown) => {
      assert.ok(error instanceof GatewayError);
      assert.equal(error.code, "INVALID_INPUT");
      assert.match(error.message, /^INVALID_INPUT: /);
      assert.equal(error.message.includes("trace secret value"), false);
      assert.equal(error.message.includes("APEX_MCP_WORKSPACE_ID"), true);
      return true;
    },
  );
});

test("context parser rejects an oversized principal without echoing its value", () => {
  const oversizedPrincipal = `spiffe://apex/${"a".repeat(256)}`;

  assert.throws(
    () =>
      parseAuthenticatedContext({
        APEX_MCP_PRINCIPAL: oversizedPrincipal,
        APEX_MCP_AGENT_ID: "research-agent",
        APEX_MCP_WORKSPACE_ID: "northstar",
        APEX_MCP_NAMESPACE_ID: "research",
        APEX_MCP_TRACE_ID: "trace-001",
      }),
    (error: unknown) => {
      assert.ok(error instanceof GatewayError);
      assert.equal(error.code, "INVALID_INPUT");
      assert.equal(error.message.includes(oversizedPrincipal), false);
      assert.equal(error.message.includes("APEX_MCP_PRINCIPAL"), true);
      return true;
    },
  );
});

test("authorization request injects caller scope and portfolio resource metadata", () => {
  const caller = parseAuthenticatedContext({
    APEX_MCP_PRINCIPAL: "spiffe://apex/agent/research",
    APEX_MCP_AGENT_ID: "research-agent",
    APEX_MCP_WORKSPACE_ID: "northstar",
    APEX_MCP_NAMESPACE_ID: "research",
    APEX_MCP_TRACE_ID: "trace-001",
  });

  assert.deepEqual(
    buildPortfolioReadAuthorizationRequest(
      caller,
      { portfolioId: "northstar-growth", asOf: "2026-09-01" },
      "span-001",
    ),
    {
      caller,
      scope: {
        workspaceId: "northstar",
        namespaceId: "research",
      },
      tool: "portfolio.read",
      action: "read",
      resource: "portfolio:northstar/research/northstar-growth",
      classification: "confidential",
      trace: {
        traceId: "trace-001",
        spanId: "span-001",
      },
    },
  );
});
