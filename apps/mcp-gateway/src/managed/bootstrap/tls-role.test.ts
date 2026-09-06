import assert from "node:assert/strict";
import test from "node:test";
import { X509Certificate } from "node:crypto";
import { once } from "node:events";
import { connect, createServer, type TLSSocket } from "node:tls";
import type { AddressInfo } from "node:net";
import { preflightTlsRole, tlsRoleMaterial, disposeTlsRole, assertDistinctTlsRoles, type TlsRoleInput } from "./tls-role.js";
import { fixture } from "./tls-role-fixture.js";

const now = 1_783_123_456_123_456n;
function input(role: "governance" | "evidence" | "ingress"): TlsRoleInput {
  return { ca: Buffer.from(fixture.ca), cert: Buffer.from(fixture[role].cert), key: Buffer.from(fixture[role].key),
    purpose: role === "ingress" ? "server" : "client", ...(role === "ingress" ? { serverName: "gateway.test" } : {}) };
}

test("purpose-specific staged TLS identities produce distinct owned usable material", () => {
  const roles = (["governance", "evidence", "ingress"] as const).map(name => {
    const source = input(name), role = preflightTlsRole(source, now);
    assert.match(role.certificateSha256, /^[0-9a-f]{64}$/); assert.match(role.publicKeySha256, /^[0-9a-f]{64}$/);
    assert.ok(role.notAfterUnixUs > now); assert.ok(Object.isFrozen(role));
    const bytes = tlsRoleMaterial(role); assert.deepEqual(bytes, { ca: source.ca, cert: source.cert, key: source.key });
    source.key.fill(0); assert.ok(tlsRoleMaterial(role).key.some(byte => byte !== 0)); return role;
  });
  assertDistinctTlsRoles(roles); for (const role of roles) disposeTlsRole(role);
});

for (const failure of ["wrong-key", "wrong-purpose", "no-eku", "no-san", "wrong-san", "cn-fallback", "ca-as-leaf",
  "leaf-as-ca", "certificate-bundle", "private-key-bundle", "extra-text", "non-ascii", "encrypted", "empty", "oversize",
  "invalid-time", "fraction-time", "server-name-for-client"]) test(`TLS material refuses ${failure} statically`, () => {
    const value = { ...input("ingress") }; let at: unknown = now;
    if (failure === "wrong-key") value.key = Buffer.from(fixture.evidence.key);
    if (failure === "wrong-purpose") value.purpose = "client";
    if (failure === "no-eku") value.cert = Buffer.from(fixture.noEku.cert);
    if (failure === "no-san" || failure === "cn-fallback") value.cert = Buffer.from(fixture.noSan.cert);
    if (failure === "wrong-san") value.serverName = "other.test";
    if (failure === "ca-as-leaf") value.cert = value.ca;
    if (failure === "leaf-as-ca") value.ca = value.cert;
    if (failure === "certificate-bundle") value.cert = Buffer.concat([value.cert, value.ca]);
    if (failure === "private-key-bundle") value.key = Buffer.concat([value.key, value.key]);
    if (failure === "extra-text") value.cert = Buffer.concat([value.cert, Buffer.from("private canary")]);
    if (failure === "non-ascii") value.cert[0] |= 128;
    if (failure === "encrypted") value.key = Buffer.from(value.key.toString().replaceAll("PRIVATE KEY", "ENCRYPTED PRIVATE KEY"));
    if (failure === "empty") value.key = Buffer.alloc(0);
    if (failure === "oversize") value.ca = Buffer.alloc(65537);
    if (failure === "invalid-time") at = -1n;
    if (failure === "fraction-time") at = 1.5;
    if (failure === "server-name-for-client") Object.assign(value, input("governance"), { serverName: "gateway.test" });
    assert.throws(() => preflightTlsRole(value, at as bigint), /^Error: managed TLS material refused safely$/);
  });

test("validity uses inclusive start and exclusive microsecond expiry", () => {
  const source = input("ingress"), leaf = new X509Certificate(source.cert);
  const from = BigInt(leaf.validFromDate.getTime()) * 1000n, until = BigInt(leaf.validToDate.getTime()) * 1000n;
  for (const at of [from - 1n, until, until + 1n]) assert.throws(() => preflightTlsRole(source, at), /managed TLS material refused safely/);
  for (const at of [from, from + 1n, until - 1n]) disposeTlsRole(preflightTlsRole(source, at));
});

test("reissued certificates cannot share a role private key", () => {
  const gov = preflightTlsRole(input("governance"), now), ingress = preflightTlsRole(input("ingress"), now);
  const reused = preflightTlsRole({ ...input("governance"), cert: Buffer.from(fixture.reissued.cert), key: Buffer.from(fixture.reissued.key) }, now);
  assert.notEqual(gov.certificateSha256, reused.certificateSha256); assert.equal(gov.publicKeySha256, reused.publicKeySha256);
  assert.throws(() => assertDistinctTlsRoles([gov, reused, ingress]), /managed TLS material refused safely/);
  assert.throws(() => assertDistinctTlsRoles([gov, gov, ingress]), /managed TLS material refused safely/);
  for (const role of [gov, reused, ingress]) disposeTlsRole(role);
});

test("opaque material handles reject imitation and cannot be used after disposal", () => {
  const source = input("governance"), role = preflightTlsRole(source, now);
  const first = tlsRoleMaterial(role); first.key.fill(0);
  assert.deepEqual(tlsRoleMaterial(role).key, source.key);
  assert.throws(() => tlsRoleMaterial({ ...role }), /managed TLS material refused safely/);
  disposeTlsRole(role); disposeTlsRole(role);
  assert.throws(() => tlsRoleMaterial(role), /managed TLS material refused safely/);
  assert.throws(() => assertDistinctTlsRoles([role, role, role]), /managed TLS material refused safely/);
});

test("passive metadata and native buffer copies never invoke caller hooks", () => {
  let hooks = 0; const source = input("ingress");
  const getter = { ...source, get key(): Buffer { hooks++; throw new Error("private canary"); } };
  const proxy = new Proxy(source, { ownKeys() { hooks++; throw new Error("private canary"); } });
  for (const value of [getter, proxy]) assert.throws(() => preflightTlsRole(value, now), /managed TLS material refused safely/);
  Object.defineProperty(source.key, "valueOf", { get() { hooks++; throw new Error("private canary"); } });
  disposeTlsRole(preflightTlsRole(source, now)); assert.equal(hooks, 0);
});

test("validated separate roles complete an actual TLS1.3 mutual-authentication round trip", { timeout: 5000 }, async t => {
  const ingress = preflightTlsRole(input("ingress"), now), governance = preflightTlsRole(input("governance"), now);
  const sockets = new Set<TLSSocket>();
  const server = createServer({ ...tlsRoleMaterial(ingress), minVersion: "TLSv1.3", maxVersion: "TLSv1.3",
    requestCert: true, rejectUnauthorized: true }, socket => {
    sockets.add(socket); socket.on("error", () => {}); socket.once("close", () => sockets.delete(socket));
    assert.equal(socket.authorized, true); socket.end("purpose fixture");
  });
  server.on("tlsClientError", () => {});
  t.after(async () => { for (const socket of sockets) socket.destroy();
    await new Promise<void>(done => server.close(() => done())); disposeTlsRole(ingress); disposeTlsRole(governance); });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const socket = connect({ ...tlsRoleMaterial(governance), host: "127.0.0.1", port: (server.address() as AddressInfo).port,
    servername: "gateway.test", rejectUnauthorized: true, minVersion: "TLSv1.3", maxVersion: "TLSv1.3" });
  sockets.add(socket); socket.on("error", () => {}); const closed = new Promise<void>(done => socket.once("close", () => { sockets.delete(socket); done(); }));
  await once(socket, "secureConnect"); assert.equal(socket.authorized, true); assert.equal(socket.getProtocol(), "TLSv1.3");
  const chunks: Buffer[] = []; for await (const chunk of socket) chunks.push(Buffer.from(chunk));
  assert.equal(Buffer.concat(chunks).toString(), "purpose fixture"); socket.destroy(); await closed;
});
