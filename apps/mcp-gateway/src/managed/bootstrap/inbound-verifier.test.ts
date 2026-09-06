import { test } from "node:test";
import assert from "node:assert/strict";
import { createManagedInboundVerifier } from "./inbound-verifier.js";
import { config, jwks, token, claims } from "./inbound-verifier/fixture.js";
test("staged local key verifies exact published issuer/resource/proxy and returns only immutable claims", async () => {
  const verifier = createManagedInboundVerifier(jwks(), config), input = claims();
  const result = await verifier.verify(await token(input));
  assert.deepEqual(result, { issuer: input.iss, audience: input.aud, subject: input.sub,
    expiresAt: input.exp, scope: input.scope, proxyId: input.proxy_id });
  assert.ok(Object.isFrozen(result)); await verifier.close();
  await assert.rejects(() => verifier.verify(awaitToken), /managed inbound verifier refused safely/);
});
const awaitToken = "unused-after-closed";
