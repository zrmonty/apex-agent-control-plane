import assert from "node:assert/strict";
import test from "node:test";
import { createManagedInboundVerifier } from "../inbound-verifier.js";
import { config, claims } from "./fixture.js";
const refused = (e: unknown) => e instanceof Error && e.message === "managed inbound verifier refused safely" && e.cause === undefined;

test("Ed25519 identity key cannot authenticate an unsigned identity-point JWT", async () => {
  const x = Buffer.alloc(32); x[0] = 1;
  const bytes = Buffer.from(JSON.stringify({ keys: [{ kty: "OKP", crv: "Ed25519", alg: "EdDSA", kid: "identity", x: x.toString("base64url") }] }));
  const signature = Buffer.alloc(64); signature[0] = 1;
  const forged = [Buffer.from('{"alg":"EdDSA","kid":"identity"}').toString("base64url"),
    Buffer.from(JSON.stringify(claims())).toString("base64url"), signature.toString("base64url")].join(".");
  // Before the fix the public constructor accepts this key and the real JOSE /
  // native crypto path authenticates the forged compact JWT. No crypto seam.
  let verifier: ReturnType<typeof createManagedInboundVerifier> | undefined;
  try {
    try { verifier = createManagedInboundVerifier(bytes, config); }
    catch (error) { assert(refused(error)); return; }
    await assert.rejects(verifier.verify(forged), refused);
    assert.fail("invalid staged key must refuse at construction, not only verification");
  } finally { await verifier?.close(); }
});

for (const [name, first, last] of [["order-four", 0, 0], ["noncanonical-y", 237, 127], ["invalid-sign-identity", 1, 128]] as const) {
  test(`Ed25519 ${name} public point refuses at factory`, () => {
    const x = name === "noncanonical-y" ? Buffer.alloc(32, 255) : Buffer.alloc(32);
    x[0] = first; x[31] = last;
    assert.throws(() => createManagedInboundVerifier(Buffer.from(JSON.stringify({ keys: [
      { kty: "OKP", crv: "Ed25519", alg: "EdDSA", kid: name, x: x.toString("base64url") },
    ] })), config), refused);
  });
}
test("Ed25519 noncurve, order-two and mixed-torsion points refuse, RFC public keys import", async () => {
  const p = (1n << 255n) - 19n;
  const encode = (y: bigint, sign = 0) => {
    const out = Buffer.alloc(32); for (let i = 0; i < 32; i++, y >>= 8n) out[i] = Number(y & 255n);
    out[31] |= sign << 7; return out.toString("base64url");
  };
  // B encodes y=4/5. Adding (0,-1) gives (-x,-y), a valid curve
  // point with nonzero torsion component, not a generated public key.
  const baseY = BigInt(`0x${"66".repeat(31)}58`);
  for (const x of [encode(2n), encode(p - 1n), encode(p - baseY, 1)]) {
    assert.throws(() => createManagedInboundVerifier(Buffer.from(JSON.stringify({ keys: [
      { kty: "OKP", crv: "Ed25519", alg: "EdDSA", kid: "invalid", x },
    ] })), config), refused);
  }
  for (const hex of ["d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"]) {
    const verifier = createManagedInboundVerifier(Buffer.from(JSON.stringify({ keys: [
      { kty: "OKP", crv: "Ed25519", alg: "EdDSA", kid: "RFC8032", x: Buffer.from(hex, "hex").toString("base64url") },
    ] })), config); await verifier.close();
  }
});
