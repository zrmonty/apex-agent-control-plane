import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { RuntimeConfigurationSchema, decodeStrict, encodeJson, type RuntimeConfiguration } from "@apex/contracts";
import { parseRuntimeConfiguration, runtimeManifestHash } from "../runtime-config.js";

const path = process.env.APEX_RUNTIME_FIXTURE_PATH;
assert.ok(path, "APEX_RUNTIME_FIXTURE_PATH must identify the actual Rust export; no fallback fixture");
export const artifactText = readFileSync(path, "utf8");
export const artifactPath = path;
export const rustConfig = parseRuntimeConfiguration(artifactText);

/** Component variants start from the real generated message, never a second wire
 * model. Re-sign intentional test mutations; the original artifact stays intact. */
export function runtimeFixture(change?: (config: RuntimeConfiguration) => void) {
  const config = decodeStrict(RuntimeConfigurationSchema, artifactText);
  change?.(config);
  config.runtimeManifestHash = runtimeManifestHash(config);
  return parseRuntimeConfiguration(JSON.stringify(encodeJson(RuntimeConfigurationSchema, config)));
}

/** Preserve existing component-test identities while migrating their full wire
 * fixture to generated data. Not used by the unmodified Rust golden-chain tests. */
export function componentFixture(change?: (config: RuntimeConfiguration) => void) {
  return runtimeFixture(config => {
    config.proxyId = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84";
    config.revisionId = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e85";
    config.workspaceId = "workspace-a"; config.namespaceId = "namespace-a";
    config.resourceUrl = "https://proxy.example.test/mcp";
    config.auth!.audience = config.resourceUrl;
    config.auth!.requiredScopes = ["mcp:proxy:invoke"];
    config.spec!.ingress!.host = "proxy.example.test";
    config.spec!.ingress!.allowedOrigins = ["https://console.example.test"];
    Object.assign(config.spec!.upstreams[0], { upstreamId: "portfolio", endpointOrCommandRef: "https://portfolio.example.test/mcp",
      credentialRef: "secret://portfolio/read", serverIdentity: "portfolio.example.test" });
    config.spec!.exposedTools[0].upstreamId = "portfolio";
    config.spec!.governanceBinding!.policyId = "policy-read";
    config.spec!.runtimeProfile!.egressDestinations[0].host = "portfolio.example.test";
    config.networkGrants[0].host = "portfolio.example.test";
    config.toolSchemas[0].upstreamId = "portfolio";
    config.secretRefs = ["secret://portfolio/read"];
    change?.(config);
  });
}

export const caller = { principal: "spiffe://apex/agent/research", agentId: "research-agent",
  workspaceId: "acme", namespaceId: "prod", traceId: "trace-001" } as const;
export const claims = { issuer: "https://issuer.example.test", audience: "https://proxy.apex.test/mcp",
  subject: "operator:alice", expiresAt: Math.floor(Date.now() / 1000) + 300,
  scope: "mcp:tools", proxyId: rustConfig.proxyId } as const;
