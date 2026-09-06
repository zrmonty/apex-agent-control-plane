import { test } from "node:test";
import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { fixture } from "./tls-role-fixture.js";
import { parseManagedUpstreamCredential, upstreamCredentialMaterial, disposeUpstreamCredential } from "./upstream-material.js";
const now = 1783123456123456n;
const token = "synthetic-upstream-test-token";
const bundle = () => ({ schema_version: 1, authentication: "bearer", server_ca: fixture.ca, token });
const bytes = (value: unknown) => Buffer.from(JSON.stringify(value));
const client = () => ({ ca: fixture.ca, ...fixture.governance });
const refused = /^Error: managed upstream material refused safely$/;
test("explicit bearer bundle owns server trust and token without exposing them in metadata", () => {
  const input = bytes(bundle()), owner = parseManagedUpstreamCredential(input, now);
  assert.equal(owner.authentication, "bearer");
  assert.ok(owner.notAfterUnixUs > now);
  assert.equal(JSON.stringify(owner, (_, value) => typeof value === "bigint" ? String(value) : value).includes(token), false);
  const material = upstreamCredentialMaterial(owner);
  assert.equal(material.serverCa.toString(), fixture.ca);
  assert.equal(material.token?.toString(), token);
  input.fill(0); material.serverCa.fill(0); material.token?.fill(0);
  assert.equal(upstreamCredentialMaterial(owner).token?.toString(), token);
  disposeUpstreamCredential(owner);
  assert.throws(() => upstreamCredentialMaterial(owner), /managed upstream material refused safely/);
});

for (const authentication of ["server_tls", "bearer", "mtls", "mtls_bearer"] as const) {
  test(`explicit ${authentication} has exactly its selected material`, () => {
    const mutual = authentication.includes("mtls"), bearer = authentication.includes("bearer");
    const owner = parseManagedUpstreamCredential(bytes({ schema_version: 1, authentication, server_ca: fixture.ca,
      ...(bearer ? { token } : {}), ...(mutual ? { client: client() } : {}) }), now);
    const material = upstreamCredentialMaterial(owner);
    assert.deepEqual(Object.keys(material).sort(), ["serverCa", ...(bearer ? ["token"] : []),
      ...(mutual ? ["clientCert", "clientKey"] : [])].sort());
    assert.ok(Object.isFrozen(owner)); assert.ok(Object.isFrozen(material));
    if (mutual) {
      assert.match(owner.clientCertificateSha256!, /^[a-f0-9]{64}$/);
      assert.match(owner.clientPublicKeySha256!, /^[a-f0-9]{64}$/);
      assert.equal(material.clientKey?.toString(), fixture.governance.key);
    } else assert.equal(Object.hasOwn(owner, "clientPublicKeySha256"), false);
    disposeUpstreamCredential(owner); disposeUpstreamCredential(owner);
    assert.throws(() => upstreamCredentialMaterial(owner), refused);
    // Consumer copies survive owner disposal; consumer is responsible for wipe.
    assert.equal(material.serverCa.toString(), fixture.ca);
    for (const buffer of Object.values(material)) buffer.fill(0);
  });
}

const invalid: ReadonlyArray<readonly [string, unknown]> = [
  ["null", null], ["array", []], ["schema missing", { ...bundle(), schema_version: undefined }],
  ["schema zero", { ...bundle(), schema_version: 0 }], ["schema text", { ...bundle(), schema_version: "1" }],
  ["mode absent", { ...bundle(), authentication: undefined }], ["mode null", { ...bundle(), authentication: null }],
  ["mode alias", { ...bundle(), authentication: "mutual_tls" }], ["mode object", { ...bundle(), authentication: { bearer: null } }],
  ["unknown field", { ...bundle(), authorization: "Bearer canary" }], ["arbitrary header", { ...bundle(), headers: {} }],
  ["arbitrary path", { ...bundle(), path: "/secrets/key" }], ["ambient ca", { ...bundle(), server_ca: undefined }],
  ["empty ca", { ...bundle(), server_ca: "" }], ["null ca", { ...bundle(), server_ca: null }],
  ["CA bundle", { ...bundle(), server_ca: fixture.ca + fixture.ca }],
  ["CA leading text", { ...bundle(), server_ca: "canary\n" + fixture.ca }],
  ["CA trailing text", { ...bundle(), server_ca: fixture.ca + "canary" }],
  ["leaf as CA", { ...bundle(), server_ca: fixture.ingress.cert }],
  ["CA wrong PEM", { ...bundle(), server_ca: fixture.ca.replaceAll("CERTIFICATE", "TRUSTED CERTIFICATE") }],
  ["missing bearer", { ...bundle(), token: undefined }], ["null bearer", { ...bundle(), token: null }],
  ["TLS only token", { ...bundle(), authentication: "server_tls" }],
  ["bearer client", { ...bundle(), client: client() }],
  ["mtls absent client", { ...bundle(), authentication: "mtls", token: undefined }],
  ["mtls token", { ...bundle(), authentication: "mtls", client: client() }],
  ["combined absent token", { ...bundle(), authentication: "mtls_bearer", token: undefined, client: client() }],
  ["client extra", { ...bundle(), authentication: "mtls_bearer", client: { ...client(), servername: "attacker.test" } }],
  ["client missing key", { ...bundle(), authentication: "mtls_bearer", client: { ...client(), key: undefined } }],
  ["client mismatched key", { ...bundle(), authentication: "mtls_bearer", client: { ...client(), key: fixture.evidence.key } }],
  ["client wrong purpose", { ...bundle(), authentication: "mtls_bearer", client: { ca: fixture.ca, ...fixture.ingress } }],
];
for (const [name, value] of invalid) test(`refuses ${name} with static error`, () => {
  assert.throws(() => parseManagedUpstreamCredential(bytes(value), now), refused);
});
for (const value of ["", "a".repeat(15), "a".repeat(4097), token + "\n", token + "\r", token + "\0",
  token + "\u2028", "Bearer " + token, token + ":", "x=" + token, token + "===", token + "é", token + "\t"]) {
  test(`rejects malformed bearer ${JSON.stringify(value.slice(-20))}`, () => {
    assert.throws(() => parseManagedUpstreamCredential(bytes({ ...bundle(), token: value }), now), refused);
  });
}
test("bearer grammar exact endpoints including optional trailing padding", () => {
  for (const value of ["a".repeat(16), "a".repeat(4096), "a".repeat(4096) + "==", "AZaz09._~+/-AZaz09=="]) {
    const owner = parseManagedUpstreamCredential(bytes({ ...bundle(), token: value }), now);
    assert.equal(upstreamCredentialMaterial(owner).token?.toString(), value); disposeUpstreamCredential(owner);
  }
});
test("original duplicate/UTF8/JSON defects cannot become valid objects", () => {
  const text = JSON.stringify(bundle());
  for (const value of [Buffer.from(text.replace('"schema_version":1', '"schema_version":0,"schema_version":1')),
    Buffer.from(text.replace('"schema_version":1', '"schema_version":0,"schema_\\u0076ersion":1')),
    Buffer.from(text + "null"), Buffer.from(text.replace(token, "\\ud800")),
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text)]),
    Buffer.concat([Buffer.from([0xff]), Buffer.from(text)])]) {
    assert.throws(() => parseManagedUpstreamCredential(value, now), refused);
  }
  const owner = parseManagedUpstreamCredential(Buffer.from(JSON.stringify(bundle(), null, 2)), now);
  disposeUpstreamCredential(owner);
});
test("original input bounded exactly at 64KiB before parsing", () => {
  const text = JSON.stringify(bundle());
  const owner = parseManagedUpstreamCredential(Buffer.from(text.padEnd(65536)), now); disposeUpstreamCredential(owner);
  for (const source of [Buffer.alloc(0), Buffer.from(text.padEnd(65537))]) {
    assert.throws(() => parseManagedUpstreamCredential(source, now), refused);
  }
});
test("native byte capture ignores hooks and rejects shared, detached and proxy buffers", () => {
  let hooks = 0; const source = bytes(bundle());
  for (const property of ["length", "byteLength", "buffer", "slice", "toString", "valueOf", Symbol.iterator]) {
    Object.defineProperty(source, property, { get() { hooks++; throw new Error("canary"); } });
  }
  disposeUpstreamCredential(parseManagedUpstreamCredential(source, now));
  const backing = new ArrayBuffer(8), detached = new Uint8Array(backing);
  structuredClone(backing, { transfer: [backing] });
  const proxy = new Proxy(bytes(bundle()), { get() { hooks++; throw new Error("canary"); } });
  const revoked = Proxy.revocable(bytes(bundle()), {}); revoked.revoke();
  for (const value of [proxy, revoked.proxy, new Uint8Array(new SharedArrayBuffer(65536)), detached,
    {} as Uint8Array, new Uint16Array(10) as unknown as Uint8Array]) {
    assert.throws(() => parseManagedUpstreamCredential(value, now), refused);
  }
  assert.equal(hooks, 0);
});
test("opaque forgery and active imitation cannot access material", () => {
  const owner = parseManagedUpstreamCredential(bytes(bundle()), now); let hooks = 0;
  for (const value of [{ ...owner }, new Proxy(owner, { get() { hooks++; throw new Error("canary"); } }),
    { get authentication() { hooks++; return "bearer"; } }]) {
    assert.throws(() => upstreamCredentialMaterial(value as typeof owner), refused);
  }
  assert.equal(hooks, 0); disposeUpstreamCredential(owner);
});
test("inclusive CA start and exclusive expiry preserve integer microseconds", () => {
  const ca = new X509Certificate(fixture.ca), start = BigInt(ca.validFromDate.getTime()) * 1000n,
    end = BigInt(ca.validToDate.getTime()) * 1000n;
  for (const at of [start, start + 1n, end - 1n]) {
    const owner = parseManagedUpstreamCredential(bytes(bundle()), at);
    assert.equal(owner.notAfterUnixUs, end); disposeUpstreamCredential(owner);
  }
  for (const at of [start - 1n, end, end + 1n, -1n, 253402300800000000n, 1.5, undefined]) {
    assert.throws(() => parseManagedUpstreamCredential(bytes(bundle()), at as bigint), refused);
  }
});
