import { createHash } from "node:crypto";

import { CallerPrincipalSchema, type PortfolioReadInput } from "./schemas.js";
import {
  GatewayError,
  type AuthenticatedContext,
  type AuthorizationRequest,
} from "./contracts.js";

const PRINCIPAL_PATTERN = /^spiffe:\/\/[\x00-\x7f]+$/;
const MAX_PRINCIPAL_LENGTH = 256;
const IDENTIFIER_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const TRACE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

type AuthenticatedContextSource = Record<string, string | undefined>;

function requireBoundedValue(
  source: AuthenticatedContextSource,
  key: string,
  pattern: RegExp,
  maxLength = Number.POSITIVE_INFINITY,
): string {
  const value = source[key];

  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength ||
    !pattern.test(value)
  ) {
    throw new GatewayError("INVALID_INPUT", `missing or malformed ${key}`);
  }

  return value;
}

export function portfolioResourceReference(portfolioId: string): string {
  const digest = createHash("sha256").update(portfolioId, "utf8").digest("hex");
  return `portfolio:sha256:${digest}`;
}

export function parseAuthenticatedContext(
  source: AuthenticatedContextSource,
): AuthenticatedContext {
  const principal = requireBoundedValue(
    source,
    "APEX_MCP_PRINCIPAL",
    PRINCIPAL_PATTERN,
    MAX_PRINCIPAL_LENGTH,
  );
  if (!CallerPrincipalSchema.safeParse(principal).success) {
    throw new GatewayError("INVALID_INPUT", "missing or malformed APEX_MCP_PRINCIPAL");
  }

  return {
    principal,
    agentId: requireBoundedValue(source, "APEX_MCP_AGENT_ID", IDENTIFIER_PATTERN),
    workspaceId: requireBoundedValue(source, "APEX_MCP_WORKSPACE_ID", IDENTIFIER_PATTERN),
    namespaceId: requireBoundedValue(source, "APEX_MCP_NAMESPACE_ID", IDENTIFIER_PATTERN),
    traceId: requireBoundedValue(source, "APEX_MCP_TRACE_ID", TRACE_PATTERN),
  };
}

export function buildPortfolioReadAuthorizationRequest(
  caller: AuthenticatedContext,
  input: PortfolioReadInput,
  spanId: string,
): AuthorizationRequest {
  const scope = {
    workspaceId: caller.workspaceId,
    namespaceId: caller.namespaceId,
  } as const;

  return {
    caller,
    scope,
    tool: "portfolio.read",
    action: "read",
    resource: portfolioResourceReference(input.portfolioId),
    classification: "confidential",
    trace: {
      traceId: caller.traceId,
      spanId,
    },
  };
}

export { GatewayError };
