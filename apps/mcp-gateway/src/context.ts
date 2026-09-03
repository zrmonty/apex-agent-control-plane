import type { PortfolioReadInput } from "./schemas.js";
import {
  GatewayError,
  type AuthenticatedContext,
  type AuthorizationRequest,
} from "./contracts.js";

const PRINCIPAL_PATTERN = /^spiffe:\/\/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=-]+$/;
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

function buildScopeKey(context: AuthenticatedContext): string {
  return `${context.workspaceId}/${context.namespaceId}`;
}

export function parseAuthenticatedContext(
  source: AuthenticatedContextSource,
): AuthenticatedContext {
  return {
    principal: requireBoundedValue(
      source,
      "APEX_MCP_PRINCIPAL",
      PRINCIPAL_PATTERN,
      MAX_PRINCIPAL_LENGTH,
    ),
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
  const scopeKey = buildScopeKey(caller);

  return {
    caller,
    scope,
    tool: "portfolio.read",
    action: "read",
    resource: `portfolio:${scopeKey}/${input.portfolioId}`,
    classification: "confidential",
    trace: {
      traceId: caller.traceId,
      spanId,
    },
  };
}

export { GatewayError };
