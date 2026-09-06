import { record } from "../../call-preparation/boundary.js";
import { parseWireJson } from "../../upstream-wire/json.js";
import { assertDataTree } from "../../runtime-config/boundary.js";
import type { InboundTokenClaims } from "../../auth.js";
import { base64, kid, refused } from "./keys.js";
import { exactNumericDates } from "./numeric-dates.js";
export type Binding = Readonly<{ issuer: string; audience: string; proxyId: string; scopes: readonly string[] }>;
export function compact(token: string) {
  if (typeof token !== "string" || token.length > 8192) throw refused();
  const pieces = token.split("."); if (pieces.length !== 3) throw refused();
  const header = record(parseWireJson(base64(pieces[0], 1024)), ["alg", "kid", "typ"]);
  if (!kid(header.kid) || !["RS256", "ES256", "EdDSA"].includes(header.alg as string) ||
    Object.hasOwn(header, "typ") && !["JWT", "at+jwt"].includes(header.typ as string)) throw refused();
  const payloadBytes = base64(pieces[1], 6144), raw = parseWireJson(payloadBytes); assertDataTree(raw, false);
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw refused();
  exactNumericDates(payloadBytes);
  base64(pieces[2], 1024);
  return { header: header as { alg: string; kid: string }, payload: raw as Record<string, unknown> };
}
export function claims(raw: Record<string, unknown>, binding: Binding, nowMs: number): InboundTokenClaims {
  const audience = raw.aud, now = Math.floor(nowMs / 1000);
  const numeric = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= 253402300799;
  if (raw.iss !== binding.issuer || !(audience === binding.audience || Array.isArray(audience) &&
    audience.length === 1 && audience[0] === binding.audience) || typeof raw.sub !== "string" ||
    raw.sub.length < 1 || raw.sub.length > 256 || !/^[A-Za-z0-9]/.test(raw.sub) || /[^A-Za-z0-9._:/@-]/.test(raw.sub) ||
    !numeric(raw.exp) || raw.exp <= now || raw.proxy_id !== binding.proxyId || Object.hasOwn(raw, "proxyId") ||
    typeof raw.scope !== "string" || raw.scope.length < 1 || raw.scope.length > 4096 || /[^A-Za-z0-9_.: /-]/.test(raw.scope)) throw refused();
  for (const name of ["nbf", "iat"]) if (Object.hasOwn(raw, name) && (!numeric(raw[name]) || raw[name] > now)) throw refused();
  const scopes = raw.scope.split(" ");
  if (scopes.some(scope => !scope.length) || new Set(scopes).size !== scopes.length ||
    !binding.scopes.every(scope => scopes.includes(scope))) throw refused();
  return Object.freeze({ issuer: binding.issuer, audience: typeof audience === "string" ? audience : Object.freeze([binding.audience]),
    subject: raw.sub, expiresAt: raw.exp, scope: raw.scope, proxyId: binding.proxyId });
}
