import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { runInNewContext } from "node:vm";
import { createManagedInboundVerifier } from "../inbound-verifier.js";
import { config, jwk, jwks, pair, token, refused } from "./fixture.js";
const encoded = (keys: unknown[]) => Buffer.from(JSON.stringify({ keys }));
const reject = (keys: unknown[]) => assert.throws(() => createManagedInboundVerifier(encoded(keys), config), refused);
for (const [name, value] of [
  ["missing kid", { ...jwk, kid: undefined }], ["empty kid", { ...jwk, kid: "" }], ["long kid", { ...jwk, kid: "x".repeat(129) }],
  ["coercible kid", { ...jwk, kid: ["fixture-ec"] }], ["newline kid", { ...jwk, kid: "kid\n" }],
  ["missing alg", { ...jwk, alg: undefined }], ["none", { ...jwk, alg: "none" }], ["HS256", { ...jwk, alg: "HS256" }],
  ["RSA EC mismatch", { ...jwk, alg: "RS256" }], ["lowercase", { ...jwk, alg: "es256" }],
  ["use enc", { ...jwk, use: "enc" }], ["use null", { ...jwk, use: null }], ["empty ops", { ...jwk, key_ops: [] }],
  ["sign ops", { ...jwk, key_ops: ["sign"] }], ["duplicate ops", { ...jwk, key_ops: ["verify", "verify"] }],
  ["scalar ops", { ...jwk, key_ops: "verify" }], ["unknown", { ...jwk, unknown: "CANARY" }],
  ["remote x5u", { ...jwk, x5u: "https://never.example" }], ["x5c", { ...jwk, x5c: [] }],
  ["private", { ...pair.privateKey.export({ format: "jwk" }), alg: "ES256", kid: "private" }],
  ["symmetric", { kty: "oct", k: "c2VjcmV0", alg: "HS256", kid: "secret" }],
  ["wrong curve", { ...jwk, crv: "P-384" }], ["extra RSA fields", { ...jwk, n: "AQAB", e: "AQAB" }],
  ["short x", { ...jwk, x: Buffer.alloc(31).toString("base64url") }], ["long y", { ...jwk, y: Buffer.alloc(33).toString("base64url") }],
  ["padded x", { ...jwk, x: `${jwk.x}=` }], ["invalid x", { ...jwk, x: "!" }],
  ["off curve", { ...jwk, x: Buffer.alloc(32).toString("base64url"), y: Buffer.alloc(32).toString("base64url") }],
] as const) test(`staged key rejects ${name}`, () => reject([value]));

test("RSA strength, exponent and native key shape are enforced", () => {
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "jwk" });
  for (const value of [
    { ...rsa, n: Buffer.alloc(255, 255).toString("base64url") },
    { ...rsa, n: Buffer.concat([Buffer.from([0]), Buffer.alloc(256, 255)]).toString("base64url") },
    { ...rsa, n: Buffer.concat([Buffer.from([127]), Buffer.alloc(255, 255)]).toString("base64url") },
    { ...rsa, n: Buffer.alloc(1025, 255).toString("base64url") }, { ...rsa, e: "Aw" },
    { ...rsa, e: "AAEAAQ" }, { ...rsa, d: "AQAB" }, { ...rsa, p: "AQAB" }, { ...rsa, oth: [] },
  ]) reject([{ ...value, kid: "rsa", alg: "RS256" }]);
});
test("even RSA modulus is not a native public RSA key", () => {
  const n = Buffer.alloc(256); n[0] = 128;
  reject([{ kty: "RSA", kid: "even", alg: "RS256", n: n.toString("base64url"), e: "AQAB" }]);
});
test("exact JWKS inventory, duplicates, UTF8 and original 64KiB bound", async () => {
  for (const bytes of [Buffer.from("{}"), encoded([]), encoded(Array.from({ length: 33 }, (_, i) => ({ ...jwk, kid: `k${i}` }))),
    encoded([jwk, jwk]), Buffer.from(JSON.stringify({ keys: [jwk], other: 1 })),
    Buffer.from(`{"keys":[],"keys":[${JSON.stringify(jwk)}]}`),
    Buffer.from(`{"keys":[${JSON.stringify(jwk).replace('"alg":"ES256"', '"alg":"ES256","alg":"ES256"')}]}`),
    Buffer.from([255]), Buffer.concat([Buffer.from([239, 187, 191]), jwks()]), Buffer.alloc(65537, 32)]) {
    assert.throws(() => createManagedInboundVerifier(bytes, config), refused);
  }
  const input = jwks(), max = Buffer.concat([input, Buffer.alloc(65536 - input.length, 32)]);
  const verifier = createManagedInboundVerifier(max, config); assert.equal((await verifier.verify(await token())).subject, "operator:alice");
  await verifier.close();
});
test("cross-realm byte views are copied natively; hooks and backing neighbours are never read", async () => {
  const bytes = jwks(); let hooks = 0;
  const bad = () => { hooks++; throw Error("BYTE-CANARY"); };
  const foreign = runInNewContext("new Uint8Array(values)", { values: [...bytes] }) as Uint8Array;
  const slab = Buffer.concat([Buffer.from("INVALID"), bytes, Buffer.from("INVALID")]);
  const bounded = slab.subarray(7, 7 + bytes.length);
  for (const input of [foreign, bounded]) {
    for (const key of ["length", "byteLength", "byteOffset", "buffer", "slice", "subarray", "copy", "toString", "valueOf"])
      Object.defineProperty(input, key, { get: bad });
    Object.defineProperty(input, Symbol.iterator, { get: bad });
    const verifier = createManagedInboundVerifier(input, config);
    assert.equal((await verifier.verify(await token())).subject, "operator:alice"); await verifier.close();
  }
  for (const input of [null, {}, [], new Uint16Array(10), new DataView(new ArrayBuffer(10)),
    new Uint8Array(new SharedArrayBuffer(bytes.length)), new Proxy(bytes, { get: bad, getPrototypeOf: bad })]) {
    assert.throws(() => createManagedInboundVerifier(input as Uint8Array, config), refused);
  }
  const detached = new Uint8Array(bytes); structuredClone(detached.buffer, { transfer: [detached.buffer] });
  assert.throws(() => createManagedInboundVerifier(detached, config), refused); assert.equal(hooks, 0);
});
