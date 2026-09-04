import assert from "node:assert/strict";
import test from "node:test";

import { GatewayError } from "../contracts.js";
import type { ProxyRevisionConfig } from "./config.js";
import {
  authenticateInbound,
  buildBearerChallenge,
  createOutboundCredentialProvider,
  normalizeHeaderValues,
  validatePkceState,
  type InboundTokenClaims,
} from "./auth.js";

const proxyId = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84";
const config = {
  proxyId,
  revisionId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e85",
  configHash: "a".repeat(64),
  ingress: { transport: "streamable-http", endpoint: "https://proxy.example.test/mcp", allowedOrigins: ["https://console.example.test"] },
  upstreams: [{ upstreamId: "portfolio", transport: "streamable-http", endpointOrCommandRef: "https://portfolio.example.test/mcp", credentialRef: "secret://portfolio/read" }],
  exposedTools: [{ upstreamId: "portfolio", toolName: "portfolio.read", alias: "portfolio.read", classification: "read" }],
  cliProfiles: [],
  authBindings: [{ bindingId: "inbound", direction: "inbound", issuer: "https://issuer.example.test", audience: "apex-mcp-proxy" }],
  governance: { policyId: "policy-read", approvalMode: "none", classification: "confidential" },
  runtime: { imageDigest: "sha256:" + "b".repeat(64), cpuMillis: 500, memoryBytes: 268_435_456, pidLimit: 128, readOnlyRootfs: true, networkMode: "declared-egress", noNewPrivileges: true, droppedCapabilities: ["ALL"] },
} as unknown as ProxyRevisionConfig;

const claims: InboundTokenClaims = {
  issuer: "https://issuer.example.test",
  audience: "apex-mcp-proxy",
  subject: "operator:alice",
  expiresAt: Math.floor(Date.now() / 1000) + 300,
  scope: "mcp:proxy:invoke",
  proxyId,
};

class FakeVerifier {
  constructor(private readonly result: InboundTokenClaims | Error = claims) {}

  async verify(): Promise<InboundTokenClaims> {
    if (this.result instanceof Error) throw this.result;
    return this.result;
  }
}

test("authenticates one bearer token only when claims bind to the revision", async () => {
  const context = await authenticateInbound(
    { authorization: ["Bearer signed-token"] },
    config,
    new FakeVerifier(),
  );

  assert.equal(context.subject, "operator:alice");
  assert.equal(context.proxyId, proxyId);
});

test("rejects missing or duplicate authorization headers and invalid claims", async () => {
  await assert.rejects(() => authenticateInbound({}, config, new FakeVerifier()));
  await assert.rejects(() => authenticateInbound({ authorization: ["Bearer a", "Bearer b"] }, config, new FakeVerifier()));
  for (const invalid of [
    { ...claims, issuer: "https://other.example.test" },
    { ...claims, audience: "other-service" },
    { ...claims, expiresAt: 1 },
    { ...claims, scope: "mcp:proxy:other" },
    { ...claims, proxyId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e86" },
  ]) {
    await assert.rejects(() => authenticateInbound({ authorization: ["Bearer signed-token"] }, config, new FakeVerifier(invalid)));
  }
});

test("outbound credentials resolve only by secret reference", async () => {
  const calls: string[] = [];
  const provider = createOutboundCredentialProvider({
    async resolve(reference) {
      calls.push(reference);
      return "outbound-only-token";
    },
  });
  const credential = await provider.resolve("secret://portfolio/read");

  assert.equal(credential, "outbound-only-token");
  assert.deepEqual(calls, ["secret://portfolio/read"]);
});

test("uses constant-time PKCE state comparison and safe bearer challenges", () => {
  assert.equal(validatePkceState("state-value", "state-value"), true);
  assert.equal(validatePkceState("state-value", "other-value"), false);
  assert.match(buildBearerChallenge("https://proxy.example.test/.well-known/oauth-protected-resource"), /^Bearer resource_metadata=/);
});

test("normalizes verifier and credential failures without exposing their messages", async () => {
  await assert.rejects(
    () => authenticateInbound({ authorization: ["Bearer signed-token"] }, config, new FakeVerifier(new Error("private verifier detail"))),
    (error: unknown) => error instanceof GatewayError && !error.message.includes("private verifier detail"),
  );
});

test("normalizes header names once and preserves duplicate values", () => {
  const headers = normalizeHeaderValues({
    Authorization: "Bearer signed-token",
    authorization: ["Bearer duplicate-token"],
    Origin: "https://console.example.test",
  });

  assert.deepEqual(headers.authorization, ["Bearer signed-token", "Bearer duplicate-token"]);
  assert.deepEqual(headers.origin, ["https://console.example.test"]);
  assert.equal(Object.hasOwn(headers, "Authorization"), false);
});
