import assert from "node:assert/strict";
import test from "node:test";

import type { AuthenticatedContext } from "../contracts.js";
import { portfolioResourceReference } from "../context.js";
import type { ProxyRevisionConfig } from "./config.js";
import { ManagedExecutor, type ManagedAuthorizationRequest, type ManagedEvidenceEvent, type ManagedGovernance } from "./managed-executor.js";
import type { InboundTokenClaims } from "./auth.js";
import type { UpstreamSession } from "./upstream.js";

const proxyId = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84";
const tool = { upstreamId: "portfolio", toolName: "portfolio.read", alias: "portfolio.read", classification: "read" } as const;
const config = {
  proxyId,
  revisionId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e85",
  configHash: "a".repeat(64),
  ingress: { transport: "stdio", allowedOrigins: [] },
  upstreams: [{ upstreamId: "portfolio", transport: "streamable-http", endpointOrCommandRef: "https://portfolio.example.test/mcp", credentialRef: "secret://portfolio/read" }],
  exposedTools: [tool],
  cliProfiles: [],
  authBindings: [{ bindingId: "inbound", direction: "inbound", issuer: "https://issuer.example.test", audience: "apex-mcp-proxy" }],
  governance: { policyId: "policy-read", approvalMode: "none", classification: "confidential" },
  runtime: { imageDigest: "sha256:" + "b".repeat(64), cpuMillis: 500, memoryBytes: 268_435_456, pidLimit: 128, readOnlyRootfs: true, networkMode: "declared-egress", noNewPrivileges: true, droppedCapabilities: ["ALL"] },
} as unknown as ProxyRevisionConfig;

const caller: AuthenticatedContext = {
  principal: "spiffe://apex/agent/research",
  agentId: "research-agent",
  workspaceId: "workspace-a",
  namespaceId: "namespace-a",
  traceId: "trace-001",
};

const claims: InboundTokenClaims = {
  issuer: "https://issuer.example.test",
  audience: "apex-mcp-proxy",
  subject: "operator:alice",
  expiresAt: Math.floor(Date.now() / 1000) + 300,
  scope: "mcp:proxy:invoke",
  proxyId,
};

class Session implements UpstreamSession {
  calls = 0;
  async discover() { return { upstreamId: "portfolio", schemaHash: "a", tools: [] } as const; }
  async call() { this.calls += 1; return { value: "safe" }; }
  async close() {}
}

class Governance implements ManagedGovernance {
  lastRequest: ManagedAuthorizationRequest | undefined;
  constructor(public outcome: "allowed" | "denied" | "requires_approval" = "allowed") {}
  async authorize(request: ManagedAuthorizationRequest) { this.lastRequest = request; return { outcome: this.outcome, policyId: "policy-read", reasonCode: "policy.allow", fieldRestrictions: [] } as const; }
  async getPolicy(_scope: Readonly<{ workspaceId: string; namespaceId: string }>) { return { policyId: "policy-read", revision: 1 } as const; }
}

function executor(overrides: Partial<ConstructorParameters<typeof ManagedExecutor>[0]> = {}) {
  const session = new Session();
  const sessions = new Map<string, UpstreamSession>([["portfolio", session]]);
  const evidence: ManagedEvidenceEvent[] = [];
  const order: string[] = [];
  const governance = new Governance();
  const instance = new ManagedExecutor({
    config,
    caller,
    verifier: { async verify() { order.push("authenticate"); return claims; } },
    governance: {
      async authorize(request) { order.push("authorize"); return governance.authorize(request); },
      async getPolicy(scope) { order.push("policy"); return governance.getPolicy(scope); },
    },
    approve: async () => { order.push("approval"); return true; },
    admit: async () => { order.push("rate-budget"); return true; },
    checkEgress: async () => { order.push("egress"); },
    validateInput: (input) => { order.push("schema"); return input; },
    filterOutput: (output) => { order.push("filter"); return { output, removedFields: ["secret"], sourceBytes: 20, filteredBytes: 10 }; },
    sessions,
    emitEvidence: async (event) => { order.push("evidence"); evidence.push(event); },
    ...overrides,
  });
  return { instance, session, evidence, order, governance };
}

const headers = { authorization: ["Bearer signed-token"] } as const;

test("executes managed calls in the governed order and emits metadata only", async () => {
  const { instance, order, evidence, session, governance } = executor();
  const result = await instance.execute("portfolio.read", { portfolioId: "northstar-401k" }, headers);

  assert.deepEqual(result, { value: "safe" });
  assert.deepEqual(order, ["authenticate", "schema", "authorize", "policy", "rate-budget", "egress", "filter", "evidence"]);
  assert.equal(session.calls, 1);
  assert.equal(governance.lastRequest?.action, "read");
  assert.equal(governance.lastRequest?.resource, portfolioResourceReference("northstar-401k"));
  assert.equal("output" in evidence[0], false);
  assert.equal(evidence[0].status, "succeeded");
  assert.deepEqual(evidence[0].fieldRestrictions, []);
});

test("uses the filter's measured output size without serializing the output again", async () => {
  const { instance, evidence } = executor({
    filterOutput: (output) => ({ output, removedFields: [], sourceBytes: 20, filteredBytes: 10, outputBytes: 10 }),
  });

  await instance.execute("portfolio.read", { portfolioId: "northstar-401k" }, headers);

  assert.equal(evidence[0].outputBytes, 10);
});

test("denials and approval failures never call the upstream", async () => {
  const approved = executor();
  approved.governance.outcome = "requires_approval";
  await approved.instance.execute("portfolio.read", {}, headers);
  assert.equal(approved.session.calls, 1);
  assert.equal(approved.order.includes("approval"), true);

  const denied = executor();
  denied.governance.outcome = "denied";
  await assert.rejects(() => denied.instance.execute("portfolio.read", {}, headers));
  assert.equal(denied.session.calls, 0);
  assert.equal(denied.evidence[0].status, "denied");

  const approval = executor({ approve: async () => false });
  approval.governance.outcome = "requires_approval";
  await assert.rejects(() => approval.instance.execute("portfolio.read", {}, headers));
  assert.equal(approval.session.calls, 0);
  assert.equal(approval.evidence[0].status, "denied");
});

test("evidence admission failure prevents an allowed result", async () => {
  const { instance, session } = executor({ emitEvidence: async () => { throw new Error("sink detail"); } });
  await assert.rejects(() => instance.execute("portfolio.read", {}, headers), /EVENT_ADMISSION_FAILED/);
  assert.equal(session.calls, 1);
});

test("routes each exposed alias to its configured upstream session", async () => {
  const primary = new Session();
  const secondary = new Session();
  const multiConfig = {
    ...config,
    upstreams: [
      ...config.upstreams,
      { upstreamId: "secondary", transport: "streamable-http", endpointOrCommandRef: "https://secondary.example.test/mcp" },
    ],
    exposedTools: [
      ...config.exposedTools,
      { upstreamId: "secondary", toolName: "portfolio.read", alias: "secondary.read", classification: "read" },
    ],
  } as unknown as ProxyRevisionConfig;
  const evidence: ManagedEvidenceEvent[] = [];
  const instance = new ManagedExecutor({
    config: multiConfig,
    caller,
    verifier: { async verify() { return claims; } },
    governance: new Governance(),
    approve: async () => true,
    admit: async () => true,
    checkEgress: async () => {},
    validateInput: (input) => input,
    filterOutput: (output) => ({ output, removedFields: [], sourceBytes: 1, filteredBytes: 1 }),
    sessions: new Map([["portfolio", primary], ["secondary", secondary]]),
    emitEvidence: async (event) => { evidence.push(event); },
  });

  await instance.execute("secondary.read", {}, headers);

  assert.equal(primary.calls, 0);
  assert.equal(secondary.calls, 1);
  assert.equal(evidence[0].upstreamId, "secondary");
});

test("a missing upstream session fails closed without fallback", async () => {
  const { instance, session } = executor({ sessions: new Map() });

  await assert.rejects(() => instance.execute("portfolio.read", {}, headers), /ADAPTER_FAILED/);
  assert.equal(session.calls, 0);
});
