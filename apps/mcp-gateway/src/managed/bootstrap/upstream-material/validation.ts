import { X509Certificate, type KeyObject } from "node:crypto";
import { createSecureContext } from "node:tls";
import { types } from "node:util";
export const refused = () => new Error("managed upstream material refused safely");
const prototype = Object.getPrototypeOf(Uint8Array.prototype);
const byteLength = Object.getOwnPropertyDescriptor(prototype, "byteLength")!.get!;
const backing = Object.getOwnPropertyDescriptor(prototype, "buffer")!.get!;
const signatures = new Set(["1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13",
  "1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4", "1.3.101.112"]);

/** Intrinsic native-byte capture: no user iterator, length, slice or coercion. */
export function copyBytes(value: Uint8Array): Buffer {
  if (types.isProxy(value) || !types.isUint8Array(value)) throw refused();
  const size: number = byteLength.call(value);
  if (size < 1 || size > 65536 || types.isSharedArrayBuffer(backing.call(value))) throw refused();
  const result = Buffer.alloc(size); Uint8Array.prototype.set.call(result, value); return result;
}

/** Bounded single-anchor profile preflight; real peer TLS still performs PKIX. */
export function serverTrust(bytes: Buffer, nowUnixUs: bigint): bigint {
  if (typeof nowUnixUs !== "bigint" || nowUnixUs < 0n || nowUnixUs >= 253402300800000000n || bytes.some(byte => byte > 127)) throw refused();
  const text = bytes.toString("ascii");
  const match = /^-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END CERTIFICATE-----\r?\n?$/.exec(text);
  if (!match || match[0].length !== bytes.length) throw refused();
  const body = match[1].replace(/\r?\n/g, ""), der = Buffer.from(body, "base64");
  if (der.toString("base64") !== body) throw refused();
  const issuer = new X509Certificate(der);
  if (!issuer.raw.equals(der) || !issuer.ca || !issuer.checkIssued(issuer) || !issuer.verify(issuer.publicKey) ||
    !signatures.has(issuer.signatureAlgorithmOid)) throw refused();
  strong(issuer.publicKey);
  const from = issuer.validFromDate.getTime(), until = issuer.validToDate.getTime();
  if (!Number.isSafeInteger(from) || !Number.isSafeInteger(until) || from >= until ||
    nowUnixUs < BigInt(from) * 1000n || nowUnixUs >= BigInt(until) * 1000n) throw refused();
  createSecureContext({ ca: bytes, minVersion: "TLSv1.3", maxVersion: "TLSv1.3" });
  return BigInt(until) * 1000n;
}
function strong(key: KeyObject): void {
  if (key.asymmetricKeyType === "ed25519") return;
  if (key.asymmetricKeyType === "ec" && ["prime256v1", "secp384r1"].includes(key.asymmetricKeyDetails?.namedCurve ?? "")) return;
  const bits = key.asymmetricKeyDetails?.modulusLength;
  if (key.asymmetricKeyType === "rsa" && bits !== undefined && bits >= 2048 && bits <= 8192) return;
  throw refused();
}
