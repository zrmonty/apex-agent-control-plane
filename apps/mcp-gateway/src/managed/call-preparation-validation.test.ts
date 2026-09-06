import assert from "node:assert/strict";
import { test } from "node:test";
import { McpProxyPrivateDestinationAllowance, McpProxyToolClassification, McpProxyTransport,
  ProxyApprovalMode, type RuntimeConfiguration } from "@apex/contracts";
import { CompiledCallPreparer, type CallPreparationOptions } from "./call-preparation.js";
import { fixture } from "./call-preparation/fixture.js";
import { runtimeManifestHash } from "./runtime-config.js";
import { freezeTree } from "./runtime-config/boundary.js";

const refused = /^Error: managed call preparation refused safely$/;
function configCase(change: (config: RuntimeConfiguration) => void, resign = true) {
  const f = fixture(), config = f.mutableConfig(); change(config);
  if (resign) config.runtimeManifestHash = runtimeManifestHash(config);
  return { ...f.options, config: freezeTree(config) };
}
const invalidConfig: [string, (config: RuntimeConfiguration) => void][] = [
  ["scope", c => { c.workspaceId = "other"; }], ["namespace", c => { c.namespaceId = "other"; }],
  ["proxy", c => { c.proxyId = c.revisionId; }], ["revision", c => { c.revisionId = c.proxyId; }],
  ["generation", c => { c.generation++; }], ["config hash", c => { c.configHash = "d".repeat(64); }],
  ["alias", c => { c.spec!.exposedTools[0].alias = "portfolio.other"; }],
  ["tool", c => { c.spec!.exposedTools[0].toolName = c.toolSchemas[0].toolName = "other.read"; }],
  ["classification", c => { c.spec!.exposedTools[0].classification = McpProxyToolClassification.BUSINESS_WRITE; }],
  ["profile", c => { c.toolSchemas[0].outputProfileId = "portfolio-read-v2"; }],
  ["input schema extra field", c => { c.toolSchemas[0].inputSchemaJson = '{"type":"object","properties":{"portfolioId":{"type":"string"},"asOf":{"type":"string"}},"required":["portfolioId"],"additionalProperties":false}'; }],
  ["input schema unconstrained", c => { c.toolSchemas[0].inputSchemaJson = '{"type":"object"}'; }],
  ["input schema duplicate keys", c => { c.toolSchemas[0].inputSchemaJson = '{"type":"object","type":"object"}'; }],
  ["output schema", c => { c.toolSchemas[0].outputSchemaJson = '{"type":"object","additionalProperties":false}'; }],
  ["approval", c => { c.approvalMode = ProxyApprovalMode.OPERATOR; c.spec!.governanceBinding!.approvalMode = "operator"; }],
  ["CLI", c => { c.spec!.cliProfiles = [{} as never]; }],
  ["protocol", c => { c.spec!.ingress!.protocolRevision = "2024-11-05"; }],
  ["transport", c => { c.spec!.ingress!.transport = McpProxyTransport.UNSPECIFIED; }],
  ["upstream transport", c => { c.spec!.upstreams[0].transport = McpProxyTransport.UNSPECIFIED; }],
  ["no tool", c => { c.spec!.exposedTools = []; c.toolSchemas = []; }],
  ["duplicate alias", c => { c.spec!.exposedTools.push(c.spec!.exposedTools[0]); }],
  ["schema hash", c => { c.toolSchemas[0].schemaHash = "bad"; }],
];
for (const [label, change] of invalidConfig) test(`constructor rejects mismatched/unsupported ${label}`, () => {
  // CLI's intentionally incomplete generated item cannot be serialized; keep the
  // old digest so constructor itself rejects its descriptor, not the fixture.
  const options = configCase(change, label !== "CLI");
  assert.throws(() => new CompiledCallPreparer(options), refused);
});
test("manifest integrity and already-frozen configuration are required", () => {
  assert.throws(() => new CompiledCallPreparer(configCase(c => { c.runtimeManifestHash = "e".repeat(64); }, false)), refused);
  const f = fixture(); assert.throws(() => new CompiledCallPreparer({ ...f.options, config: f.mutableConfig() }), refused);
  const shallow = Object.freeze(f.mutableConfig());
  assert.throws(() => new CompiledCallPreparer({ ...f.options, config: shallow }), refused);
});
test("approved private CIDRs are not refused or represented as protected socket enforcement", () => {
  const options = configCase(c => {
    c.networkGrants[0].privateDestination = true; c.networkGrants[0].approvedCidrs = ["10.20.0.0/16"];
    c.spec!.runtimeProfile!.egressDestinations[0].privateDestinationAllowance = McpProxyPrivateDestinationAllowance.ALLOWED;
  });
  assert.doesNotThrow(() => new CompiledCallPreparer(options));
});
for (const key of ["workspaceId", "namespaceId", "proxyId", "revisionId", "generation", "configHash"] as const) {
  test(`exact installed binding mismatch ${key} rejects`, () => {
    const f = fixture(), binding = { ...f.options.binding };
    if (key === "generation") binding[key]++;
    else if (key === "proxyId" || key === "revisionId") binding[key] = f.options.binding.processInstanceId;
    else if (key === "configHash") binding[key] = "d".repeat(64);
    else binding[key] = "other";
    assert.throws(() => new CompiledCallPreparer({ ...f.options, binding }), refused);
  });
}
for (const change of [{ installationId: "not-uuid" }, { processInstanceId: "not-uuid" }, { fencingToken: 0n },
  { generation: 9007199254740992 }, { launchContextHash: "invalid" }, { surprise: true }]) {
  test(`binding shape refuses ${Object.keys(change)[0]}`, () => {
    const f = fixture(); assert.throws(() => new CompiledCallPreparer({ ...f.options,
      binding: { ...f.options.binding, ...change } } as CallPreparationOptions), refused);
  });
}
for (const change of [{ evidenceAgentId: "" }, { evidenceAgentId: "actor@invalid" }, { evidenceAgentId: "actor\n" },
  { dataClassification: "internal" }, { dataClassification: "1" }]) {
  test(`protected profile refuses ${JSON.stringify(change)}`, () => {
    const f = fixture(); assert.throws(() => new CompiledCallPreparer({ ...f.options, ...change }), refused);
  });
}
for (const subject of ["alice@example.test", "spiffe://apex//actor", "spiffe://apex/../actor", "alice/actor", "..", "alice\n", "é", "a".repeat(257)]) {
  test(`unsupported authenticated subject refuses unchanged ${JSON.stringify(subject).slice(0, 48)}`, () => {
    const f = fixture(), preparer = new CompiledCallPreparer(f.options);
    assert.throws(() => preparer.prepare({ ...f.identity, subject }, "portfolio.read", { portfolioId: "p" }, f.original, f.deadline), refused);
  });
}
test("supported principal and protected actor/classification remain exact", () => {
  const f = fixture(), p = new CompiledCallPreparer(f.options);
  for (const subject of ["research-agent", "User.Name:123", "spiffe://example.test/AgentGroup/agent_1"]) {
    const result = p.prepare({ ...f.identity, subject }, "portfolio.read", { portfolioId: "p" }, f.original, f.deadline);
    assert.equal(result.request.caller!.principal, subject);
    assert.equal(result.request.caller!.agentId, "managed-evidence"); assert.equal(result.request.classification, "confidential");
  }
});
test("proxy mismatch and unexposed alias refuse", () => {
  const f = fixture(), p = new CompiledCallPreparer(f.options);
  assert.throws(() => p.prepare({ ...f.identity, proxyId: f.options.binding.revisionId }, "portfolio.read", { portfolioId: "p" }, f.original, f.deadline), refused);
  for (const alias of ["Portfolio.Read", "other", "portfolio.read\n"]) {
    assert.throws(() => p.prepare(f.identity, alias, { portfolioId: "p" }, f.original, f.deadline), refused);
  }
});
for (const input of [null, [], {}, { portfolioId: 1 }, { portfolioId: "A" }, { portfolioId: "a".repeat(65) },
  { portfolioId: "p", asOf: "2026-09-06" }, { portfolioId: "p", classification: "public" },
  { portfolioId: "p", agentId: "user-actor" }, { portfolioId: "p", traceId: "f".repeat(32) }]) {
  test(`published input intersection rejects ${JSON.stringify(input).slice(0, 80)}`, () => {
    const f = fixture(), p = new CompiledCallPreparer(f.options);
    assert.throws(() => p.prepare(f.identity, "portfolio.read", input, f.original, f.deadline), refused);
  });
}
