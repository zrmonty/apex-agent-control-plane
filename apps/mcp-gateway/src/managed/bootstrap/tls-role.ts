import { createHash, createPrivateKey, X509Certificate, type KeyObject } from "node:crypto";
import { createSecureContext } from "node:tls";
import { types } from "node:util";
import { record } from "../call-preparation/boundary.js";
export type TlsRoleInput = Readonly<{ ca: Buffer; cert: Buffer; key: Buffer;
  purpose: "client" | "server"; serverName?: string }>;
export type TlsRole = Readonly<{ certificateSha256: string; publicKeySha256: string; notAfterUnixUs: bigint }>;
type Material = Readonly<{ ca: Buffer; cert: Buffer; key: Buffer }>;
const owned = new WeakMap<TlsRole, Material>();
const refused = () => new Error("managed TLS material refused safely");
const byteLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), "byteLength")!.get!;
const signatures = new Set(["1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13",
  "1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4", "1.3.101.112"]);
/** Purpose/key/signature preflight only; actual TLS must still enforce PKIX. */
export function preflightTlsRole(input: TlsRoleInput, nowUnixUs: bigint): TlsRole {
  const copies: Buffer[] = [];
  try {
    record(input, ["ca", "cert", "key", "purpose", "serverName"]);
    if (typeof nowUnixUs !== "bigint" || nowUnixUs < 0n || nowUnixUs >= 253_402_300_800_000_000n ||
      !["client", "server"].includes(input.purpose)) throw refused();
    const copy = (value: Buffer) => { const bytes = copyBytes(value); copies.push(bytes); return bytes; };
    const ca = copy(input.ca), cert = copy(input.cert), key = copy(input.key);
    const issuer = new X509Certificate(pem(ca, "CERTIFICATE")), leaf = new X509Certificate(pem(cert, "CERTIFICATE"));
    const keyDer = pem(key, "PRIVATE KEY");
    let privateKey: KeyObject;
    try {
      privateKey = createPrivateKey({ key: keyDer, format: "der", type: "pkcs8" });
      const exported = privateKey.export({ format: "der", type: "pkcs8" });
      try { if (!exported.equals(keyDer)) throw refused(); } finally { exported.fill(0); }
    } finally { keyDer.fill(0); }
    const expiry = [issuer, leaf].map(certificate => {
      strong(certificate.publicKey);
      const from = certificate.validFromDate.getTime(), until = certificate.validToDate.getTime();
      if (!Number.isSafeInteger(from) || !Number.isSafeInteger(until) || from >= until ||
        nowUnixUs < BigInt(from) * 1000n || nowUnixUs >= BigInt(until) * 1000n ||
        !signatures.has(certificate.signatureAlgorithmOid)) throw refused();
      return BigInt(until) * 1000n;
    });
    if (!issuer.ca || leaf.ca || !issuer.checkIssued(issuer) || !issuer.verify(issuer.publicKey) ||
      !leaf.checkIssued(issuer) || !leaf.verify(issuer.publicKey) || !leaf.checkPrivateKey(privateKey)) throw refused();
    const usages = leaf.keyUsage, wanted = input.purpose === "server" ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2";
    if (!Array.isArray(usages) || !usages.includes(wanted) || usages.length > 2 || new Set(usages).size !== usages.length ||
      usages.some(usage => !["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"].includes(usage))) throw refused();
    if (input.purpose === "server") {
      if (!dnsName(input.serverName) || leaf.checkHost(input.serverName!, { subject: "never", wildcards: false }) !== input.serverName) throw refused();
    } else if (input.serverName !== undefined) throw refused();
    // OpenSSL checks that the material can construct a context. This is not
    // path/critical-extension/revocation verification or a peer handshake.
    createSecureContext({ ca, cert, key, minVersion: "TLSv1.3", maxVersion: "TLSv1.3" });
    const result = Object.freeze({ certificateSha256: sha256(leaf.raw),
      publicKeySha256: sha256(leaf.publicKey.export({ format: "der", type: "spki" })),
      notAfterUnixUs: expiry[0] < expiry[1] ? expiry[0] : expiry[1] });
    owned.set(result, Object.freeze({ ca, cert, key })); return result;
  } catch { for (const bytes of copies) bytes.fill(0); throw refused(); }
}
export function tlsRoleMaterial(role: TlsRole): Material {
  const value = owned.get(role); if (!value) throw refused();
  return Object.freeze({ ca: copyBytes(value.ca), cert: copyBytes(value.cert), key: copyBytes(value.key) });
}
export function disposeTlsRole(role: TlsRole): void {
  const value = owned.get(role); if (!value) return;
  owned.delete(role); for (const bytes of Object.values(value)) bytes.fill(0);
}
export function assertDistinctTlsRoles(roles: readonly TlsRole[]): void {
  if (types.isProxy(roles) || !Array.isArray(roles) || roles.length !== 3) throw refused();
  const certificates = new Set<string>(), keys = new Set<string>();
  for (let i = 0; i < 3; i++) {
    const item = Object.getOwnPropertyDescriptor(roles, String(i));
    if (!item || !("value" in item) || !owned.has(item.value)) throw refused();
    certificates.add(item.value.certificateSha256); keys.add(item.value.publicKeySha256);
  }
  if (certificates.size !== 3 || keys.size !== 3) throw refused();
}
function copyBytes(value: Buffer): Buffer {
  if (types.isProxy(value) || !Buffer.isBuffer(value)) throw refused();
  const size = Reflect.apply(byteLength, value, []) as number;
  if (size < 1 || size > 65_536) throw refused();
  const copy = Buffer.alloc(size); Uint8Array.prototype.set.call(copy, value); return copy;
}
function pem(bytes: Buffer, kind: "CERTIFICATE" | "PRIVATE KEY"): Buffer {
  if (bytes.some(byte => byte > 127)) throw refused();
  const expression = new RegExp(`^-----BEGIN ${kind}-----\\r?\\n([A-Za-z0-9+/=\\r\\n]+)-----END ${kind}-----\\r?\\n?$`);
  const match = expression.exec(bytes.toString("ascii"));
  if (!match || match[0].length !== bytes.length) throw refused();
  const body = match[1].replace(/\r?\n/g, ""), der = Buffer.from(body, "base64");
  if (der.toString("base64") !== body) { der.fill(0); throw refused(); }
  if (kind === "CERTIFICATE" && !new X509Certificate(der).raw.equals(der)) throw refused();
  return der;
}
function strong(key: KeyObject): void {
  if (key.asymmetricKeyType === "ed25519") return;
  if (key.asymmetricKeyType === "ec" && ["prime256v1", "secp384r1"].includes(key.asymmetricKeyDetails?.namedCurve ?? "")) return;
  const bits = key.asymmetricKeyDetails?.modulusLength;
  if (key.asymmetricKeyType === "rsa" && bits !== undefined && bits >= 2048 && bits <= 8192) return;
  throw refused();
}
function dnsName(value: unknown): value is string {
  return typeof value === "string" && value.length <= 253 && /^[a-z0-9.-]+$/.test(value) &&
    !/[^a-z0-9.-]/.test(value) && value.split(".").every(label => label.length >= 1 && label.length <= 63 && !label.startsWith("-") && !label.endsWith("-"));
}
function sha256(bytes: Buffer): string { return createHash("sha256").update(bytes).digest("hex"); }
