import { timingSafeEqual } from "node:crypto";

import { GatewayError } from "../contracts.js";
import type { ReadonlyRuntimeConfiguration } from "./runtime-config.js";
import { runtimeAuth } from "./runtime-types.js";

const SUBJECT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$/;
const SECRET_REF_PATTERN = /^secret:\/\/[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$/;
const SESSION_TOKEN_PATTERN = /^[A-Za-z0-9._~+/=-]{1,8192}$/;

export type HeaderValues = Readonly<Record<string, readonly string[] | undefined>>;

export function normalizeHeaderValues(
  headers: Readonly<Record<string, string | readonly string[] | undefined>>,
): HeaderValues {
  const normalized: Record<string, readonly string[] | undefined> = {};
  for (const [name, value] of Object.entries(headers)) {
    const key = name.toLowerCase();
    const values = value === undefined ? [] : Array.isArray(value) ? value : [value];
    const previous = normalized[key];
    normalized[key] = previous === undefined ? [...values] : [...previous, ...values];
  }
  return normalized;
}

export type InboundTokenClaims = Readonly<{
  issuer: string;
  audience: string | readonly string[];
  subject: string;
  expiresAt: number;
  scope: string;
  proxyId: string;
}>;

export interface InboundTokenVerifier {
  verify(token: string): Promise<InboundTokenClaims>;
}

export type InboundIdentity = Readonly<{
  subject: string;
  proxyId: string;
  scopes: readonly string[];
}>;

export interface SecretCredentialResolver {
  resolve(reference: string): Promise<string>;
}

export interface OutboundCredentialProvider {
  resolve(reference: string): Promise<string>;
}

export async function authenticateInbound(
  headers: HeaderValues,
  config: ReadonlyRuntimeConfiguration,
  verifier: InboundTokenVerifier,
): Promise<InboundIdentity> {
  const binding = runtimeAuth(config);
  const token = extractBearerToken(headers);
  let claims: InboundTokenClaims;
  try {
    claims = await verifier.verify(token);
  } catch {
    throw rejected();
  }
  if (
    claims.issuer !== binding.issuer ||
    !audienceMatches(claims.audience, binding.audience) ||
    !Number.isSafeInteger(claims.expiresAt) ||
    claims.expiresAt <= Math.floor(Date.now() / 1000) ||
    !SUBJECT_PATTERN.test(claims.subject) ||
    claims.proxyId !== config.proxyId ||
    !binding.requiredScopes.every(scope => hasScope(claims.scope, scope))
  ) {
    throw rejected();
  }
  return { subject: claims.subject, proxyId: claims.proxyId, scopes: binding.requiredScopes };
}

export function createOutboundCredentialProvider(
  resolver: SecretCredentialResolver,
): OutboundCredentialProvider {
  return {
    async resolve(reference: string): Promise<string> {
      if (!SECRET_REF_PATTERN.test(reference)) {
        throw rejected();
      }
      let credential: string;
      try {
        credential = await resolver.resolve(reference);
      } catch {
        throw unavailable();
      }
      if (credential.length === 0 || credential.length > 8192 || /[\u0000-\u001f\u007f]/.test(credential)) {
        throw unavailable();
      }
      return credential;
    },
  };
}

export function buildBearerChallenge(resourceMetadataUrl: string): string {
  let url: URL;
  try {
    url = new URL(resourceMetadataUrl);
  } catch {
    throw rejected();
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash) {
    throw rejected();
  }
  return `Bearer resource_metadata=${JSON.stringify(url.toString())}`;
}

export function validatePkceState(expected: string, received: string): boolean {
  const expectedBytes = Buffer.from(expected, "utf8");
  const receivedBytes = Buffer.from(received, "utf8");
  return (
    expectedBytes.length > 0 &&
    expectedBytes.length === receivedBytes.length &&
    timingSafeEqual(expectedBytes, receivedBytes)
  );
}

function extractBearerToken(headers: HeaderValues): string {
  const authorization = readHeader(headers, "authorization");
  if (authorization === undefined) {
    throw rejected();
  }
  const match = /^Bearer ([A-Za-z0-9._~+/=-]+)$/.exec(authorization);
  if (match === null || !SESSION_TOKEN_PATTERN.test(match[1])) {
    throw rejected();
  }
  return match[1];
}

function readHeader(headers: HeaderValues, name: string): string | undefined {
  const values = readHeaderValues(headers, name);
  if (values.length !== 1 || values[0].length === 0) {
    return undefined;
  }
  return values[0];
}

export function readHeaderValues(headers: HeaderValues, name: string): readonly string[] {
  const direct = headers[name];
  if (direct !== undefined) {
    return direct;
  }
  return Object.entries(headers)
    .filter(([key]) => key.toLowerCase() === name)
    .flatMap(([, value]) => value ?? []);
}

function audienceMatches(audience: string | readonly string[], expected: string): boolean {
  return typeof audience === "string" ? audience === expected : audience.length === 1 && audience[0] === expected;
}

function hasScope(scope: string, expected: string): boolean {
  return scope.split(/\s+/).includes(expected);
}

function rejected(): GatewayError {
  return new GatewayError("INVALID_INPUT", "authentication rejected safely");
}

function unavailable(): GatewayError {
  return new GatewayError("GOVERNANCE_UNAVAILABLE", "credential provider unavailable");
}
