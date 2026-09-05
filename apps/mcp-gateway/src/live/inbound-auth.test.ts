import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { exportJWK, generateKeyPair, SignJWT } from "jose";

import { componentFixture } from "../managed/testing/runtime-fixture.js";
import { createInboundTokenVerifier } from "./inbound-auth.js";

const config = componentFixture();

test("verifies local-JWKS inbound tokens and returns only bounded claims", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "apex-mcp-auth-"));
  try {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    jwk.kid = "fixture";
    await writeFile(path.join(root, "jwks.json"), JSON.stringify({ keys: [jwk] }), "utf8");
    const verifier = await createInboundTokenVerifier(config, root, "jwks.json");
    const token = await new SignJWT({ scope: "mcp:proxy:invoke", proxy_id: "proxy-1" })
      .setProtectedHeader({ alg: "RS256", kid: "fixture" })
      .setIssuer("https://issuer.example.test")
      .setAudience("https://proxy.example.test/mcp")
      .setSubject("operator:alice")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);

    const claims = await verifier.verify(token);

    assert.equal(claims.issuer, "https://issuer.example.test");
    assert.equal(claims.audience, "https://proxy.example.test/mcp");
    assert.equal(claims.subject, "operator:alice");
    assert.equal(claims.scope, "mcp:proxy:invoke");
    assert.equal(claims.proxyId, "proxy-1");
    assert.equal(Number.isSafeInteger(claims.expiresAt), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects tokens that cannot be verified by the configured local keys", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "apex-mcp-auth-"));
  try {
    const { publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    jwk.kid = "fixture";
    await writeFile(path.join(root, "jwks.json"), JSON.stringify({ keys: [jwk] }), "utf8");
    const verifier = await createInboundTokenVerifier(config, root, "jwks.json");
    await assert.rejects(() => verifier.verify("not-a-jwt"), /INVALID_INPUT/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
