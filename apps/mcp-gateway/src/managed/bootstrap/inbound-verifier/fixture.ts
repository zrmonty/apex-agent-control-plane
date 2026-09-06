import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { SignJWT } from "jose";
import { configuration } from "../../call-preparation/fixture.js";
export const config = configuration();
export const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
export const jwk = { ...pair.publicKey.export({ format: "jwk" }), kid: "fixture-ec", alg: "ES256" };
export const jwks = () => Buffer.from(JSON.stringify({ keys: [jwk] }));
export function claims() { return { iss: config.auth!.issuer, aud: config.auth!.audience, sub: "operator:alice",
  exp: Math.floor(Date.now() / 1000) + 300, proxy_id: config.proxyId, scope: config.auth!.requiredScopes.join(" ") }; }
export function token(payload = claims()) { return new SignJWT(payload).setProtectedHeader({ alg: "ES256", kid: jwk.kid }).sign(pair.privateKey); }
export const refused = (error: unknown) => error instanceof Error &&
  error.message === "managed inbound verifier refused safely" && error.cause === undefined;
export const tick = () => new Promise<void>(resolve => setImmediate(resolve));
export function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
export function rawToken(header: string | Buffer, payload: string | Buffer, key: KeyObject = pair.privateKey, alg = "ES256") {
  const input = `${Buffer.from(header).toString("base64url")}.${Buffer.from(payload).toString("base64url")}`;
  const signature = sign(alg === "EdDSA" ? null : "sha256", Buffer.from(input),
    alg === "ES256" ? { key, dsaEncoding: "ieee-p1363" } : key);
  return `${input}.${signature.toString("base64url")}`;
}
