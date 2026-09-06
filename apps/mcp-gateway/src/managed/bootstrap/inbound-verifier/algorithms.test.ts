import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { jwtVerify } from "jose";
import { createManagedInboundVerifier } from "../inbound-verifier.js";
import { authenticateInbound } from "../../auth.js";
import { config, claims, pair, rawToken, refused } from "./fixture.js";

const pairs = { ES256: pair, RS256: generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 65537 }),
  EdDSA: generateKeyPairSync("ed25519") };
for (const alg of ["ES256", "RS256", "EdDSA"] as const) {
  test(`actual ${alg} native signing/verifying and inbound defense-in-depth`, async () => {
    const key = pairs[alg], jwk = { ...key.publicKey.export({ format: "jwk" }), alg, kid: alg, use: "sig", key_ops: ["verify"] };
    const bytes = Buffer.from(JSON.stringify({ keys: [jwk] })), verifier = createManagedInboundVerifier(bytes, config);
    bytes.fill(0); // Import/copy is independent of caller-owned staged bytes.
    const payload = { ...claims(), aud: [config.auth!.audience], ignored: { canary: "NOT-RETURNED" } };
    const signed = rawToken(JSON.stringify({ alg, kid: alg, typ: "at+jwt" }), JSON.stringify(payload), key.privateKey, alg);
    try {
      const result = await verifier.verify(signed);
      assert.deepEqual(result, { issuer: payload.iss, audience: payload.aud, subject: payload.sub,
        expiresAt: payload.exp, scope: payload.scope, proxyId: payload.proxy_id });
      assert(Object.isFrozen(result) && Object.isFrozen(result.audience));
      assert(!JSON.stringify(result).includes("NOT-RETURNED"));
      const identity = await authenticateInbound({ authorization: [`Bearer ${signed}`] }, config, verifier);
      assert.equal(identity.subject, "operator:alice");
      const parts = signed.split("."), changed = Buffer.from(parts[2], "base64url"); changed[0] ^= 1;
      await assert.rejects(verifier.verify(`${parts[0]}.${parts[1]}.${changed.toString("base64url")}`), refused);
      await assert.rejects(verifier.verify(rawToken(JSON.stringify({ alg, kid: "missing" }), JSON.stringify(payload), key.privateKey, alg)), refused);
    } finally { await verifier.close(); }
  });
}
test("rotation resolves exact kid/algorithm among mixed staged keys, no first-key fallback", async () => {
  const keys = Object.entries(pairs).map(([alg, p]) => ({ ...p.publicKey.export({ format: "jwk" }), kid: alg, alg }));
  const verifier = createManagedInboundVerifier(Buffer.from(JSON.stringify({ keys })), config);
  try {
    for (const [alg, p] of Object.entries(pairs)) {
      const signed = rawToken(JSON.stringify({ alg, kid: alg }), JSON.stringify(claims()), p.privateKey, alg);
      assert.equal((await verifier.verify(signed)).subject, "operator:alice");
      const wrongKid = alg === "ES256" ? "RS256" : "ES256";
      await assert.rejects(verifier.verify(rawToken(JSON.stringify({ alg, kid: wrongKid }), JSON.stringify(claims()), p.privateKey, alg)), refused);
    }
    const replacement = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    await assert.rejects(verifier.verify(rawToken('{"alg":"ES256","kid":"ES256"}', JSON.stringify(claims()), replacement.privateKey)), refused);
  } finally { await verifier.close(); }
});
test("correctly signed duplicate JWT payload is rejected despite native JOSE accepting last-wins JSON", async () => {
  const payload = JSON.stringify(claims()).replace('"sub":"operator:alice"', '"sub":"wrong","sub":"operator:alice"');
  const signed = rawToken('{"alg":"ES256","kid":"fixture-ec"}', payload);
  assert.equal((await jwtVerify(signed, pair.publicKey)).payload.sub, "operator:alice");
  const verifier = createManagedInboundVerifier(Buffer.from(JSON.stringify({ keys: [
    { ...pair.publicKey.export({ format: "jwk" }), alg: "ES256", kid: "fixture-ec" },
  ] })), config);
  try { await assert.rejects(verifier.verify(signed), refused); } finally { await verifier.close(); }
});
test("32 independently generated Ed25519 public keys retain native signature compatibility", async () => {
  const generated = Array.from({ length: 32 }, () => generateKeyPairSync("ed25519"));
  const keys = generated.map((p, i) => ({ ...p.publicKey.export({ format: "jwk" }), alg: "EdDSA", kid: `key-${i}` }));
  const verifier = createManagedInboundVerifier(Buffer.from(JSON.stringify({ keys })), config);
  try {
    for (let i = 0; i < generated.length; i++) assert.equal((await verifier.verify(rawToken(
      JSON.stringify({ alg: "EdDSA", kid: `key-${i}` }), JSON.stringify(claims()), generated[i].privateKey, "EdDSA"))).subject, "operator:alice");
  } finally { await verifier.close(); }
});
