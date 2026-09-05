import assert from "node:assert/strict";
import test from "node:test";
import type { RuntimeConfiguration } from "@apex/contracts";
import { authenticateInbound } from "./auth.js";
import { buildProtectedResourceMetadata, validateHttpIngressRequest } from "./http.js";
import { compileExposedToolIndexes, createUpstreamSessions } from "./upstream.js";
import { buildManagedToolCatalog } from "./http-server.js";
import { buildManagedRuntime } from "../live/managed-runtime.js";
import { claims, rustConfig, runtimeFixture } from "./testing/runtime-fixture.js";
import { GatewayError } from "../contracts.js";

test("active authentication accepts the real Rust manifest resource audience and configured scope", async () => {
  const identity = await authenticateInbound({ authorization: ["Bearer fixture-token"] }, rustConfig,
    { async verify() { return claims; } });
  assert.equal(identity.subject, "operator:alice");
  assert.equal(identity.proxyId, rustConfig.proxyId);
});

test("the generated portfolio catalog advertises its exact approved input and output schemas", () => {
  const catalog = buildManagedToolCatalog(rustConfig);
  assert.equal(catalog.length, 1);
  assert.deepEqual(catalog[0].inputSchema, { type: "object", properties: { portfolioId: { type: "string" } },
    required: ["portfolioId"], additionalProperties: false });
  assert.deepEqual(catalog[0].outputSchema, { type: "object" });
  assert.ok(Object.isFrozen(catalog));
});

test("production managed construction refuses missing enforcement before reading key/client settings", async () => {
  const touched: string[] = [];
  const env = new Proxy({ APEX_MCP_GOVERNANCE_MODE: "live", APEX_MCP_PRINCIPAL: "spiffe://apex/agent/research",
    APEX_MCP_AGENT_ID: "research-agent", APEX_MCP_WORKSPACE_ID: "acme", APEX_MCP_NAMESPACE_ID: "prod",
    APEX_MCP_TRACE_ID: "trace-001" }, {
    get(target, key: string) { touched.push(key); return Reflect.get(target, key); },
  });
  await assert.rejects(() => buildManagedRuntime(rustConfig, env), (error: unknown) =>
    error instanceof GatewayError && error.code === "GOVERNANCE_UNAVAILABLE" &&
    error.message === "GOVERNANCE_UNAVAILABLE: managed runtime enforcement is unavailable safely");
  assert.ok(touched.every(key => ["APEX_MCP_GOVERNANCE_MODE", "APEX_MCP_PRINCIPAL", "APEX_MCP_AGENT_ID",
    "APEX_MCP_WORKSPACE_ID", "APEX_MCP_NAMESPACE_ID", "APEX_MCP_TRACE_ID"].includes(key)));
});

test("the catalog rejects general tools, alias substitution and unsupported output profiles", () => {
  for (const change of [
    (config: RuntimeConfiguration) => { config.spec!.exposedTools[0].alias = "other.read"; },
    (config: RuntimeConfiguration) => {
      config.spec!.exposedTools[0].toolName = "other.read"; config.toolSchemas[0].toolName = "other.read";
    },
    (config: RuntimeConfiguration) => { config.toolSchemas[0].outputProfileId = "unapproved-profile"; },
  ]) {
    assert.throws(() => buildManagedToolCatalog(runtimeFixture(change)), (error: unknown) => error instanceof GatewayError && error.code === "INVALID_INPUT");
  }
});

test("active HTTP ingress and metadata read the complete generated Rust configuration", () => {
  assert.deepEqual(validateHttpIngressRequest({ method: "POST", url: "https://proxy.apex.test/mcp",
    headers: { host: ["proxy.apex.test"], origin: ["https://console.apex.test"] }, bodyBytes: 0 }, rustConfig),
  { sessionId: undefined });
  assert.deepEqual(buildProtectedResourceMetadata(rustConfig), { resource: "https://proxy.apex.test/mcp",
    authorization_servers: ["https://issuer.example.test"], bearer_methods_supported: ["header"], scopes_supported: ["mcp:tools"] });
});

test("active upstream wiring retains original generated entries and frozen enforcement metadata", async () => {
  const tool = rustConfig.spec!.exposedTools[0];
  const upstream = rustConfig.spec!.upstreams[0];
  assert.equal(compileExposedToolIndexes(rustConfig).byAlias.get("portfolio.read"), tool);
  const observed: unknown[] = [];
  const sessions = createUpstreamSessions(rustConfig, {
    async discover(value) { observed.push(value); return { tools: [{ name: "portfolio.read" }] }; },
    async call(value, name) { observed.push(value); return { name }; },
    async close(value) { observed.push(value); },
  });
  const session = sessions.get("portfolio-upstream")!;
  await session.discover();
  assert.deepEqual(await session.call(tool, {}), { name: "portfolio.read" });
  await session.close();
  assert.ok(observed.every(value => value === upstream));
  assert.equal(rustConfig.generation, 1n);
  assert.equal(rustConfig.memoryBytes, 268435456n);
  assert.equal(rustConfig.telemetry!.maxExportQueueBytes, 8388608n);
  assert.equal(rustConfig.configHash, "a".repeat(64));
  assert.equal(rustConfig.runtimeManifestHash, "db5ddc4670e5f901240e1c2910d9f78dd8a65237c86f197d13938be967afe5da");
  assert.ok(Object.isFrozen(rustConfig) && Object.isFrozen(upstream) && Object.isFrozen(rustConfig.networkGrants));
});
