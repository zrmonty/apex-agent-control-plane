import assert from "node:assert/strict";
import test from "node:test";

import type { AuthorizationRequest } from "../contracts.js";
import { loadLiveConfig } from "./config.js";
import { toGovernanceWireRequest } from "./governance.js";

const request: AuthorizationRequest = {
  caller: {
    principal: "spiffe://apex/agent/research",
    agentId: "research-agent",
    workspaceId: "northstar",
    namespaceId: "research",
    traceId: "trace-001",
  },
  scope: { workspaceId: "northstar", namespaceId: "research" },
  tool: "portfolio.read",
  action: "read",
  resource: "portfolio:sha256:8994d7d97baa4a58a0fbc8192815c60605caa16a9106d50af6548810f52eaf31",
  classification: "confidential",
  trace: { traceId: "trace-001", spanId: "span-001" },
};

const liveEnvironment = {
  APEX_MCP_GOVERNANCE_ENDPOINT: "https://control-plane-api:9443",
  APEX_MCP_GOVERNANCE_CA_FILE: "ca.pem",
  APEX_MCP_GOVERNANCE_CLIENT_CERT_FILE: "gateway.pem",
  APEX_MCP_GOVERNANCE_CLIENT_KEY_FILE: "gateway.key",
  APEX_MCP_GOVERNANCE_TOKEN_FILE: "gateway-token",
  APEX_MCP_EVENT_ENDPOINT: "https://event-ingest:8443",
  APEX_MCP_EVENT_CA_FILE: "ca.pem",
  APEX_MCP_EVENT_CLIENT_CERT_FILE: "event.pem",
  APEX_MCP_EVENT_CLIENT_KEY_FILE: "event.key",
  APEX_MCP_EVENT_TOKEN_FILE: "event-token",
  APEX_MCP_TRUSTED_SECRET_BASE: ".",
} as const;

test("live configuration rejects a half-configured governance client", () => {
  assert.throws(
    () => loadLiveConfig({ APEX_MCP_GOVERNANCE_ENDPOINT: liveEnvironment.APEX_MCP_GOVERNANCE_ENDPOINT }),
    /GOVERNANCE_UNAVAILABLE/,
  );
});

test("governance request mapping preserves the authenticated scope and trace", () => {
  assert.deepEqual(toGovernanceWireRequest(request), {
    caller: {
      principal: request.caller.principal,
      agent_id: request.caller.agentId,
    },
    scope: {
      workspace_id: request.scope.workspaceId,
      namespace_id: request.scope.namespaceId,
    },
    tool: request.tool,
    action: request.action,
    resource: request.resource,
    classification: request.classification,
    trace: {
      trace_id: request.trace.traceId,
      span_id: request.trace.spanId,
    },
  });
});
