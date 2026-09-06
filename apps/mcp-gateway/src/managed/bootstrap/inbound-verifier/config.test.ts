import assert from "node:assert/strict";
import test from "node:test";
import { createManagedInboundVerifier } from "../inbound-verifier.js";
import { runtimeManifestHash } from "../../runtime-config.js";
import type { RuntimeConfiguration } from "@apex/contracts";
import { configuration } from "../../call-preparation/fixture.js";
import { config, jwks, claims, rawToken, refused } from "./fixture.js";
const header = '{"alg":"ES256","kid":"fixture-ec"}';
test("factory revalidates generated message, full metadata and original manifest", () => {
  for (const change of [
    (c: RuntimeConfiguration) => { c.auth!.issuer = "http://wrong.example"; },
    (c: RuntimeConfiguration) => { c.auth!.requiredScopes = []; },
    (c: RuntimeConfiguration) => { c.auth!.requiredScopes = ["duplicate", "duplicate"]; },
    (c: RuntimeConfiguration) => { c.spec!.runtimeProfile!.rootless = false; },
  ]) {
    const value = structuredClone(config) as RuntimeConfiguration; change(value); value.runtimeManifestHash = runtimeManifestHash(value);
    assert.throws(() => createManagedInboundVerifier(jwks(), value), refused);
  }
  const stale = structuredClone(config) as RuntimeConfiguration; stale.auth!.issuer = "https://other.example/";
  assert.throws(() => createManagedInboundVerifier(jwks(), stale), refused);
  const wrongAudience = structuredClone(config) as RuntimeConfiguration; wrongAudience.auth!.audience = "https://wrong.example/";
  // Generated encoding itself refuses this relationship, so do not fabricate a
  // newly sealed generated message for it. The factory still must reject it.
  assert.throws(() => createManagedInboundVerifier(jwks(), wrongAudience), refused);
  for (const value of [{}, { ...config, $typeName: "wrong" }, { ...config, other: 1 }, { ...config, generation: 1 }, { ...config, generation: 0n }])
    assert.throws(() => createManagedInboundVerifier(jwks(), value as RuntimeConfiguration), refused);
});
test("active config getters/proxies cannot run or supply issuer defaults", () => {
  let hooks = 0; const bad = () => { hooks++; throw Error("CONFIG-CANARY"); };
  const value = structuredClone(config); Object.defineProperty(value.auth, "issuer", { get: bad, enumerable: true });
  for (const input of [value, new Proxy(config, { get: bad, ownKeys: bad, getPrototypeOf: bad })])
    assert.throws(() => createManagedInboundVerifier(jwks(), input), refused);
  assert.equal(hooks, 0);
});
test("binding is copied at construction and every published required scope is required", async () => {
  const value = structuredClone(configuration(c => { c.auth!.requiredScopes = ["mcp:tools", "extra:read"]; })) as RuntimeConfiguration;
  const verifier = createManagedInboundVerifier(jwks(), value);
  value.auth!.issuer = "https://changed.example/"; value.auth!.requiredScopes.length = 0; value.proxyId = "changed";
  try {
    await assert.rejects(verifier.verify(rawToken(header, JSON.stringify(claims()))), refused);
    assert.equal((await verifier.verify(rawToken(header, JSON.stringify({ ...claims(), scope: "extra:read mcp:tools" })))).subject, "operator:alice");
    await assert.rejects(verifier.verify(rawToken(header, JSON.stringify({ ...claims(), scope: "extra:read mcp:tools", iss: value.auth!.issuer }))), refused);
  } finally { await verifier.close(); }
});
