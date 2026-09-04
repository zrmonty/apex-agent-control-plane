import assert from "node:assert/strict";

import { GatewayError } from "../dist/contracts.js";
import { parseProxyRevisionConfig } from "../dist/managed/config.js";
import { ManagedExecutor } from "../dist/managed/managed-executor.js";

const proxyId = "0191b7f1-7f2c-7c13-9a61-2f29f2be1001";
const revisionId = "0191b7f1-7f2c-7c13-9a61-2f29f2be1002";
const config = parseProxyRevisionConfig({
  proxyId,
  revisionId,
  configHash: "a".repeat(64),
  ingress: { transport: "stdio", allowedOrigins: [] },
  upstreams: [{ upstreamId: "portfolio", transport: "streamable-http", endpointOrCommandRef: "https://portfolio.example.test/mcp", credentialRef: "secret://proof/portfolio" }],
  exposedTools: [{ upstreamId: "portfolio", toolName: "portfolio.read", alias: "portfolio.read", classification: "read" }],
  cliProfiles: [],
  authBindings: [{ bindingId: "inbound", direction: "inbound", issuer: "https://issuer.example.test", audience: "apex-mcp-proxy" }],
  governance: { policyId: "proof-read-only", approvalMode: "none", classification: "confidential" },
  runtime: { imageDigest: "sha256:" + "b".repeat(64), cpuMillis: 500, memoryBytes: 268435456, pidLimit: 128, readOnlyRootfs: true, networkMode: "isolated", noNewPrivileges: true, droppedCapabilities: ["ALL"] },
});

const claims = { issuer: "https://issuer.example.test", audience: "apex-mcp-proxy", subject: "proof-agent", expiresAt: Math.floor(Date.now() / 1000) + 300, scope: "mcp:proxy:invoke", proxyId };
const evidence = [];
let calls = 0;
const session = { async discover() { return { upstreamId: "portfolio", schemaHash: "proof", tools: ["portfolio.read"] }; }, async call() { calls += 1; return { value: "safe", secret: "never-print-this-canary" }; }, async close() {} };
const executor = new ManagedExecutor({
  config,
  caller: { principal: "spiffe://apex/proof", agentId: "proof-agent", workspaceId: "northstar", namespaceId: "research", traceId: "proof-trace" },
  verifier: { async verify() { return claims; } },
  governance: { async authorize() { return { outcome: "allowed", policyId: "proof-read-only", reasonCode: "proof.allowed", fieldRestrictions: [] }; }, async getPolicy() { return { policyId: "proof-read-only", revision: 1 }; } },
  approve: async () => true,
  admit: async () => true,
  checkEgress: async () => undefined,
  validateInput: (input) => input,
  filterOutput: (output) => ({ output: { value: output.value }, removedFields: ["secret"], sourceBytes: 64, filteredBytes: 18 }),
  sessions: new Map([["portfolio", session]]),
  emitEvidence: async (event) => evidence.push(event),
});

const result = await executor.execute("portfolio.read", { portfolioId: "bounded-id" }, { authorization: ["Bearer proof-token"] });
assert.deepEqual(result, { value: "safe" });
assert.equal(calls, 1);
assert.equal(evidence.length, 1);
assert.equal("output" in evidence[0], false);
assert.equal(evidence[0].status, "succeeded");

await assert.rejects(
  () => executor.execute("not-exposed", {}, { authorization: ["Bearer proof-token"] }),
  (error) => error instanceof GatewayError && error.code === "INVALID_INPUT",
);

console.log(JSON.stringify({ status: "passed", proxy: "redacted", calls, evidenceEvents: evidence.length, rawOutput: "redacted" }));
