import { timingSafeEqual } from "node:crypto";
import { GatewayError } from "../contracts.js";

export function healthError(): GatewayError {
  return new GatewayError("INVALID_INPUT", "health transport rejected safely");
}
export function copyToken(value: Uint8Array): Buffer {
  if (!(value instanceof Uint8Array) || value.byteLength !== 32) throw healthError();
  return Buffer.from(value);
}
export function authenticates(value: string | undefined, expected: Buffer): boolean {
  if (value === undefined || !/^Bearer [A-Za-z0-9_-]{43}$/.test(value)) return false;
  const text = value.slice(7), decoded = Buffer.from(text, "base64url");
  try { return decoded.length === 32 && decoded.toString("base64url") === text && timingSafeEqual(decoded, expected); }
  finally { decoded.fill(0); }
}
