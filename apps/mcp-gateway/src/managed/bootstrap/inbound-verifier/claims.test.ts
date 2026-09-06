import assert from "node:assert/strict";
import test from "node:test";
import { createManagedInboundVerifier } from "../inbound-verifier.js";
import { config, claims, jwks, rawToken, refused } from "./fixture.js";
const header = '{"alg":"ES256","kid":"fixture-ec"}';
const cases: [string, unknown][] = [
  ["iss", "https://wrong.example"], ["iss", [config.auth!.issuer]], ["aud", "wrong"], ["aud", []],
  ["aud", [config.auth!.audience, "other"]], ["aud", [[config.auth!.audience]]], ["aud", [config.auth!.audience, config.auth!.audience]],
  ["sub", ""], ["sub", "a".repeat(257)], ["sub", " leading"], ["sub", "subject\n"], ["sub", "é"], ["sub", ["alice"]],
  ["proxy_id", "wrong"], ["proxy_id", [config.proxyId]], ["proxyId", config.proxyId],
  ["exp", 0], ["exp", -1], ["exp", "9999999999"], ["exp", 253402300800], ["exp", 9007199254740992], ["exp", 9999999999.5],
  ["nbf", "1"], ["nbf", 253402300799], ["nbf", -1], ["nbf", 0.5], ["iat", 253402300799], ["iat", null], ["iat", -1],
  ["scope", ""], ["scope", "other"], ["scope", ` ${config.auth!.requiredScopes.join(" ")}`],
  ["scope", `${config.auth!.requiredScopes.join(" ")} `], ["scope", `${config.auth!.requiredScopes.join(" ")}\n`],
  ["scope", `${config.auth!.requiredScopes.join(" ")}\tother`], ["scope", `${config.auth!.requiredScopes.join(" ")} é`],
  ["scope", "a".repeat(4097)], ["scope", config.auth!.requiredScopes],
  ["scope", `${config.auth!.requiredScopes.join(" ")} ${config.auth!.requiredScopes[0]}`],
];
for (const [field, value] of cases) test(`signed claim ${field} rejects ${JSON.stringify(value).slice(0, 60)}`, async () => {
  const verifier = createManagedInboundVerifier(jwks(), config);
  try { await assert.rejects(verifier.verify(rawToken(header, JSON.stringify({ ...claims(), [field]: value }))), refused); }
  finally { await verifier.close(); }
});
for (const field of ["iss", "aud", "sub", "exp", "proxy_id", "scope"]) test(`signed missing ${field} refuses`, async () => {
  const payload: Record<string, unknown> = claims(); delete payload[field];
  const verifier = createManagedInboundVerifier(jwks(), config);
  try { await assert.rejects(verifier.verify(rawToken(header, JSON.stringify(payload))), refused); } finally { await verifier.close(); }
});
test("bounded unrelated claims and exact maximum subject/scope remain metadata-only", async () => {
  const verifier = createManagedInboundVerifier(jwks(), config), base = claims();
  const scope = `${base.scope} ${"a".repeat(4096 - base.scope.length - 1)}`;
  const payload = { ...base, sub: `a${"._:/@-".repeat(42)}abc`, scope, nbf: 0, iat: 0, other: { list: [1, true, null, "extra"] } };
  assert.equal(payload.sub.length, 256);
  try {
    const result = await verifier.verify(rawToken(header, JSON.stringify(payload)));
    assert.equal(result.subject, payload.sub); assert.equal(result.scope.length, 4096);
    assert.deepEqual(Object.keys(result).sort(), ["audience", "expiresAt", "issuer", "proxyId", "scope", "subject"]);
  } finally { await verifier.close(); }
});
