import {
  createLocalJWKSet,
  jwtVerify,
  type JSONWebKeySet,
  type JWTPayload,
} from "jose";

import { GatewayError } from "../contracts.js";
import type { InboundTokenClaims, InboundTokenVerifier } from "../managed/auth.js";
import type { ProxyRevisionConfig } from "../managed/config.js";
import { loadTrustedJson } from "./secrets.js";

const ALLOWED_ALGORITHMS = ["RS256", "ES256", "EdDSA"] as const;

export async function createInboundTokenVerifier(
  config: ProxyRevisionConfig,
  trustedSecretBase: string,
  jwksFile: string,
): Promise<InboundTokenVerifier> {
  const binding = config.authBindings.find((candidate) => candidate.direction === "inbound");
  if (binding === undefined) {
    throw unavailable();
  }
  const raw = await loadTrustedJson(jwksFile, trustedSecretBase);
  if (!isRecord(raw) || !Array.isArray(raw.keys) || raw.keys.length === 0) {
    throw unavailable();
  }
  const keySet = createLocalJWKSet(raw as unknown as JSONWebKeySet);
  return {
    async verify(token: string): Promise<InboundTokenClaims> {
      try {
        const result = await jwtVerify(token, keySet, {
          issuer: binding.issuer,
          audience: binding.audience,
          algorithms: [...ALLOWED_ALGORITHMS],
          requiredClaims: ["iss", "aud", "sub", "exp"],
        });
        return claimsFromPayload(result.payload);
      } catch (error: unknown) {
        if (error instanceof GatewayError) {
          throw error;
        }
        throw rejected();
      }
    },
  };
}

function claimsFromPayload(payload: JWTPayload): InboundTokenClaims {
  const issuer = payload.iss;
  const audience = payload.aud;
  const subject = payload.sub;
  const expiresAt = payload.exp;
  const scope = payload.scope;
  const proxyId = payload.proxy_id ?? payload.proxyId;
  const validAudience = typeof audience === "string"
    ? audience
    : Array.isArray(audience) && audience.every((value): value is string => typeof value === "string")
      ? audience
      : undefined;
  if (
    typeof issuer !== "string" ||
    validAudience === undefined ||
    typeof subject !== "string" ||
    typeof expiresAt !== "number" ||
    typeof scope !== "string" ||
    typeof proxyId !== "string"
  ) {
    throw rejected();
  }
  return { issuer, audience: validAudience, subject, expiresAt, scope, proxyId };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function rejected(): GatewayError {
  return new GatewayError("INVALID_INPUT", "authentication rejected safely");
}

function unavailable(): GatewayError {
  return new GatewayError("GOVERNANCE_UNAVAILABLE", "request rejected safely");
}
