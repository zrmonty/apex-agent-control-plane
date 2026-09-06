import assert from "node:assert/strict";
import test from "node:test";
import { jwtVerify } from "jose";
import { createVerifier } from "./owner.js";
import { config, claims, jwks, rawToken, refused } from "./fixture.js";
const header = { alg: "ES256", kid: "fixture-ec" };
for (const [name, change] of [
  ["none", { alg: "none" }], ["HS256", { alg: "HS256" }], ["no kid", { kid: undefined }], ["empty kid", { kid: "" }],
  ["array kid", { kid: ["fixture-ec"] }], ["array alg", { alg: ["ES256"] }], ["long kid", { kid: "a".repeat(129) }],
  ["bad typ", { typ: "jwt" }], ["array typ", { typ: ["JWT"] }], ["empty crit", { crit: [] }], ["b64", { b64: true }],
  ["jku", { jku: "https://never.example/jwks" }], ["x5u", { x5u: "https://never.example/key" }],
  ["jwk", { jwk: {} }], ["unknown", { other: "CANARY" }],
] as const) test(`correctly signed JWT header ${name} refuses before crypto`, async () => {
  let jobs = 0;
  const verifier = createVerifier(jwks(), config, { monoNs: () => 0n, wallMs: Date.now,
    verify: ((...args: Parameters<typeof jwtVerify>) => { jobs++; return jwtVerify(...args); }) as typeof jwtVerify });
  await assert.rejects(verifier.verify(rawToken(JSON.stringify({ ...header, ...change }), JSON.stringify(claims()))), refused);
  assert.equal(jobs, 0); await verifier.close();
});
test("correctly signed raw duplicate/UTF8/shape ambiguities refuse before JOSE", async () => {
  const payload = JSON.stringify(claims()), normal = JSON.stringify(header);
  const inputs: [string | Buffer, string | Buffer][] = [
    ['{"alg":"ES256","kid":"fixture-ec","kid":"fixture-ec"}', payload],
    ['{"alg":"none","alg":"ES256","kid":"fixture-ec"}', payload],
    ['{"alg":"ES256","kid":"fixture-ec","k\\u0069d":"fixture-ec"}', payload],
    [normal, payload.replace('"sub":"operator:alice"', '"sub":"wrong","s\\u0075b":"operator:alice"')],
    [normal, payload.slice(0, -1) + ',"extra":{"same":1,"same":2}}'],
    [normal, payload.slice(0, -1) + ',"extra":"\\ud800"}'],
    [normal, payload.slice(0, -1) + ',"extra":{"__proto__":{}}}'],
    [normal, Buffer.concat([Buffer.from(payload.slice(0, -1) + ',"extra":"'), Buffer.from([255]), Buffer.from('"}')])],
    [Buffer.concat([Buffer.from('{"alg":"ES256","kid":"'), Buffer.from([255]), Buffer.from('"}')]), payload],
    [normal, Buffer.concat([Buffer.from([239, 187, 191]), Buffer.from(payload)])],
    ["[]", payload], [normal, "[]"], [normal, "null"], [normal, '{"exp":1e999}'],
    [normal, payload.slice(0, -1) + ',"extra":' + '['.repeat(34) + '0' + ']'.repeat(34) + '}'],
  ];
  let jobs = 0;
  const verifier = createVerifier(jwks(), config, { monoNs: () => 0n, wallMs: Date.now,
    verify: ((...args: Parameters<typeof jwtVerify>) => { jobs++; return jwtVerify(...args); }) as typeof jwtVerify });
  for (const [h, p] of inputs) await assert.rejects(verifier.verify(rawToken(h, p)), refused);
  assert.equal(jobs, 0); await verifier.close();
});
test("compact canonical unpadded parts and component/whole caps fail before crypto", async () => {
  const good = rawToken(JSON.stringify(header), JSON.stringify(claims())), parts = good.split(".");
  const largeHeader = JSON.stringify(header).padEnd(1025), largePayload = JSON.stringify(claims()).padEnd(6145);
  const inputs = ["", "a.b", `${good}.extra`, ` ${good}`, `${good}\n`, "a".repeat(8193),
    ...[0, 1, 2].flatMap(i => ["", `${parts[i]}=`, `${parts[i]}+`, `${parts[i]}/`, ` ${parts[i]}`].map(p => parts.map((s, j) => j === i ? p : s).join("."))),
    rawToken(largeHeader, JSON.stringify(claims())), rawToken(JSON.stringify(header), largePayload),
    `${parts[0]}.${parts[1]}.${Buffer.alloc(1025, 7).toString("base64url")}`];
  // Nonzero unused base64 bits have the same decoded signature but are not canonical.
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  inputs.push(good.slice(0, -1) + alphabet[alphabet.indexOf(good.at(-1)!) + 1]);
  let jobs = 0;
  const verifier = createVerifier(jwks(), config, { monoNs: () => 0n, wallMs: Date.now,
    verify: ((...args: Parameters<typeof jwtVerify>) => { jobs++; return jwtVerify(...args); }) as typeof jwtVerify });
  for (const input of inputs) await assert.rejects(verifier.verify(input), refused);
  assert.equal(jobs, 0); await verifier.close();
});
test("non-string JWT objects never invoke caller coercion/proxy hooks", async () => {
  let hooks = 0;
  const bad = () => { hooks++; throw Error("TOKEN-CANARY"); };
  const verifier = createVerifier(jwks(), config, { monoNs: () => 0n, wallMs: Date.now, verify: jwtVerify });
  for (const value of [null, undefined, ["jwt"], { toString: bad }, new String("jwt"), new Proxy({}, { get: bad })])
    await assert.rejects(verifier.verify(value as string), refused);
  assert.equal(hooks, 0); await verifier.close();
});
test("correctly signed fractional NumericDates cannot round into accepted integers", async () => {
  const verifier = createVerifier(jwks(), config, { monoNs: () => 0n, wallMs: () => 1000000000000, verify: jwtVerify });
  try {
    for (const [field, original] of [["exp", "10000000000.0000001"], ["nbf", "999999999.00000001"], ["iat", "999999999.00000001"]]) {
      const payload = { ...claims(), exp: 10000000000, [field]: 1 };
      const raw = JSON.stringify(payload).replace(`"${field}":1`, `"${field}":${original}`);
      await assert.rejects(verifier.verify(rawToken(JSON.stringify(header), raw)), refused);
    }
  } finally { await verifier.close(); }
});
test("integer-equivalent decimal/exponent NumericDates remain valid; fractional unrelated claims stay ignored", async () => {
  const verifier = createVerifier(jwks(), config, { monoNs: () => 0n, wallMs: () => 1000000000000, verify: jwtVerify });
  try {
    for (const original of ["10000000000", "10000000000.0", "1e10", "100000000000e-1", "1.000e10"]) {
      const raw = JSON.stringify({ ...claims(), exp: 1, other: { exp: 1.5, number: 2.3 } }).replace('"exp":1,', `"exp":${original},`);
      assert.equal((await verifier.verify(rawToken(JSON.stringify(header), raw))).expiresAt, 10000000000);
    }
    const raw = JSON.stringify({ ...claims(), exp: 1 }).replace('"exp":1,', '"exp":1e-999999,');
    await assert.rejects(verifier.verify(rawToken(JSON.stringify(header), raw)), refused);
  } finally { await verifier.close(); }
});
test("original whole-token 8192 cap admits an exact-bound signed JWT and rejects 8193", async () => {
  const normal = JSON.stringify(header), payload = JSON.stringify(claims()); let exact = "", large = "";
  for (let padding = 0; padding < 3 && !exact; padding++) {
    const h = normal + " ".repeat(padding);
    const remaining = 8192 - Buffer.from(h).toString("base64url").length - 88;
    const size = Math.floor(remaining * 3 / 4);
    const candidate = rawToken(h, payload.padEnd(size));
    if (candidate.length === 8192) { exact = candidate; large = rawToken(h, payload.padEnd(size + 1)); }
  }
  assert.equal(exact.length, 8192); assert.equal(large.length, 8193);
  const verifier = createVerifier(jwks(), config, { monoNs: () => 0n, wallMs: Date.now, verify: jwtVerify });
  assert.equal((await verifier.verify(exact)).subject, "operator:alice");
  await assert.rejects(verifier.verify(large), refused); await verifier.close();
});
