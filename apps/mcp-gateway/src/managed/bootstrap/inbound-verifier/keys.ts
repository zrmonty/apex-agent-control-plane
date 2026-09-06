import { createPublicKey, type KeyObject, type JsonWebKey } from "node:crypto";
import { types } from "node:util";
import { record } from "../../call-preparation/boundary.js";
import { parseWireJson } from "../../upstream-wire/json.js";
import { strongEd25519Point } from "./ed25519.js";
export const refused = () => new Error("managed inbound verifier refused safely");
const prototype = Object.getPrototypeOf(Uint8Array.prototype);
const byteLength = Object.getOwnPropertyDescriptor(prototype, "byteLength")!.get!;
const backing = Object.getOwnPropertyDescriptor(prototype, "buffer")!.get!;
export const kid = (value: unknown): value is string => typeof value === "string" && value.length >= 1 && value.length <= 128 && !/[^A-Za-z0-9._:-]/.test(value);
export function base64(value: unknown, cap: number): Buffer {
  if (typeof value !== "string" || !value.length || value.length > Math.ceil(cap * 4 / 3) || /[^A-Za-z0-9_-]/.test(value)) throw refused();
  const bytes = Buffer.from(value, "base64url");
  if (!bytes.length || bytes.length > cap || bytes.toString("base64url") !== value) throw refused();
  return bytes;
}
export function publicKeys(value: Uint8Array): Map<string, Readonly<{ alg: string; key: KeyObject }>> {
  if (types.isProxy(value) || !types.isUint8Array(value)) throw refused();
  const size: number = byteLength.call(value);
  if (!size || size > 65536 || types.isSharedArrayBuffer(backing.call(value))) throw refused();
  const bytes = Buffer.alloc(size); Uint8Array.prototype.set.call(bytes, value);
  try {
    const jwks = record(parseWireJson(bytes), ["keys"]);
    if (!Array.isArray(jwks.keys) || jwks.keys.length < 1 || jwks.keys.length > 32) throw refused();
    const result = new Map<string, Readonly<{ alg: string; key: KeyObject }>>();
    for (const item of jwks.keys) {
      const jwk = record(item, ["kty", "kid", "alg", "use", "key_ops", "n", "e", "crv", "x", "y"]);
      if (!kid(jwk.kid) || result.has(jwk.kid) ||
        Object.hasOwn(jwk, "use") && jwk.use !== "sig" || Object.hasOwn(jwk, "key_ops") &&
        (!Array.isArray(jwk.key_ops) || jwk.key_ops.length !== 1 || jwk.key_ops[0] !== "verify")) throw refused();
      const common = ["kty", "kid", "alg", ...(Object.hasOwn(jwk, "use") ? ["use"] : []),
        ...(Object.hasOwn(jwk, "key_ops") ? ["key_ops"] : [])];
      let fields: string[];
      if (jwk.kty === "RSA" && jwk.alg === "RS256") {
        fields = ["n", "e"]; const modulus = base64(jwk.n, 1024);
        if (modulus.length < 256 || modulus[0] === 0 || !(modulus[modulus.length - 1] & 1) || jwk.e !== "AQAB") throw refused();
      } else if (jwk.kty === "EC" && jwk.alg === "ES256" && jwk.crv === "P-256") {
        fields = ["crv", "x", "y"]; if (base64(jwk.x, 32).length !== 32 || base64(jwk.y, 32).length !== 32) throw refused();
      } else if (jwk.kty === "OKP" && jwk.alg === "EdDSA" && jwk.crv === "Ed25519") {
        fields = ["crv", "x"]; if (!strongEd25519Point(base64(jwk.x, 32))) throw refused();
      } else throw refused();
      record(jwk, [...common, ...fields]);
      if (Object.keys(jwk).length !== common.length + fields.length) throw refused();
      const key = createPublicKey({ key: jwk as JsonWebKey, format: "jwk" });
      if (jwk.kty === "RSA" && (key.asymmetricKeyType !== "rsa" ||
        (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048 || (key.asymmetricKeyDetails?.modulusLength ?? 99999) > 8192)) throw refused();
      result.set(jwk.kid, Object.freeze({ alg: jwk.alg as string, key }));
    }
    return result;
  } finally { bytes.fill(0); }
}
