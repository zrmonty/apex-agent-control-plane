import { GatewayError, type ApexEvents, type ApexGovernance, type AuthorizationRequest, type ToolExecutionEvent } from "../contracts.js";
import { parseAuthenticatedContext } from "../context.js";
import { filterPortfolioRecord, type RawPortfolioRecord } from "../filtering.js";
import { parsePortfolioReadInput } from "../schemas.js";
import { createUpstreamSessions } from "../managed/upstream.js";
import { createFileSecretCredentialResolver } from "./secrets.js";
import { createLiveEventsClient } from "./events.js";
import { loadLiveConfig } from "./config.js";
import { createLiveGovernanceClient } from "./governance.js";
import { createInboundTokenVerifier } from "./inbound-auth.js";
import type { ProxyRevisionConfig } from "../managed/config.js";
import {
  ManagedExecutor,
  type ManagedAuthorizationDecision,
  type ManagedAuthorizationRequest,
  type ManagedEvidenceEvent,
  type ManagedGovernance,
} from "../managed/managed-executor.js";
import { McpHttpUpstreamTransport } from "../managed/mcp-http-transport.js";

const MAX_DISCOVERY_CONCURRENCY = 8;

export type ManagedRuntime = Readonly<{
  executor: ManagedExecutor;
  verifier: Awaited<ReturnType<typeof createInboundTokenVerifier>>;
}>;

export async function buildManagedRuntime(
  config: ProxyRevisionConfig,
  env: NodeJS.ProcessEnv = process.env,
): Promise<ManagedRuntime> {
  if (env.APEX_MCP_GOVERNANCE_MODE?.trim() !== "live") {
    throw new GatewayError("GOVERNANCE_UNAVAILABLE", "managed HTTP runtime requires live Apex dependencies");
  }
  const live = loadLiveConfig(env);
  const context = parseAuthenticatedContext(env);
  const jwksFile = required(env, "APEX_MCP_INBOUND_JWKS_FILE");
  const verifier = await createInboundTokenVerifier(config, live.trustedSecretBase, jwksFile);
  const governance = createLiveGovernanceClient(live.governance, live.trustedSecretBase);
  const events = createLiveEventsClient(live.events, live.trustedSecretBase);
  const transport = McpHttpUpstreamTransport.fromSecretResolver(
    createFileSecretCredentialResolver(live.trustedSecretBase),
  );
  const sessions = createUpstreamSessions(config, transport);
  try {
    await discoverUpstreams(sessions, MAX_DISCOVERY_CONCURRENCY);
  } catch (error: unknown) {
    await closeSessions(sessions);
    if (error instanceof GatewayError) {
      throw error;
    }
    throw new GatewayError("ADAPTER_FAILED", "managed upstream discovery failed safely");
  }

  const managedGovernance = adaptGovernance(governance);
  const executor = new ManagedExecutor({
    config,
    caller: context,
    verifier,
    governance: managedGovernance,
    approve: async (request) => request.action === "read" && config.governance.approvalMode === "none",
    admit: async () => true,
    checkEgress: async () => {},
    validateInput: (input) => parsePortfolioInput(input),
    filterOutput: (output, tool, decision) => filterManagedOutput(output, tool.alias, decision),
    sessions,
    emitEvidence: (event) => emitManagedEvidence(events, context, event),
  });
  return { executor, verifier };
}

export async function discoverUpstreams(
  sessions: ReadonlyMap<string, { discover(): Promise<unknown> }>,
  maxConcurrency: number,
): Promise<void> {
  if (!Number.isSafeInteger(maxConcurrency) || maxConcurrency < 1) {
    throw new GatewayError("INVALID_INPUT", "upstream discovery concurrency rejected safely");
  }
  const pending = [...sessions.values()];
  let next = 0;
  const failures: Array<{ index: number; error: unknown }> = [];
  const workerCount = Math.min(maxConcurrency, pending.length);
  const worker = async (): Promise<void> => {
    while (true) {
      const index = next;
      next += 1;
      const session = pending[index];
      if (session === undefined) {
        return;
      }
      try {
        await session.discover();
      } catch (error: unknown) {
        failures.push({ index, error });
      }
    }
  };
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  if (failures.length > 0) {
    failures.sort((left, right) => left.index - right.index);
    throw failures[0].error;
  }
}

function adaptGovernance(governance: ApexGovernance): ManagedGovernance {
  return {
    async authorize(request: ManagedAuthorizationRequest) {
      if (request.tool !== "portfolio.read" || request.action !== "read") {
        return deniedDecision();
      }
      const authorization: AuthorizationRequest = {
        caller: {
          principal: request.caller.principal,
          agentId: request.caller.agentId,
          workspaceId: request.caller.workspaceId,
          namespaceId: request.caller.namespaceId,
          traceId: request.caller.traceId,
        },
        scope: request.scope,
        tool: "portfolio.read",
        action: "read",
        resource: request.resource,
        classification: "confidential",
        trace: { traceId: request.traceId, spanId: request.traceId },
      };
      return governance.authorize(authorization);
    },
    async getPolicy(scope) {
      const policy = await governance.getPolicy(scope);
      return { policyId: policy.policyId, revision: policy.revision };
    },
  };
}

function parsePortfolioInput(input: unknown): unknown {
  if (!isRecord(input) || typeof input.portfolioId !== "string") {
    throw new GatewayError("INVALID_INPUT", "managed proxy input rejected safely");
  }
  return parsePortfolioReadInput(input);
}

function filterManagedOutput(
  output: unknown,
  alias: string,
  decision: ManagedAuthorizationDecision,
) {
  if (alias !== "portfolio.read") {
    throw new GatewayError("FILTERING_FAILED", "managed proxy output rejected safely");
  }
  const raw = extractPortfolioRecord(output);
  const policy = {
    outcome: decision.outcome,
    policyId: decision.policyId,
    reasonCode: decision.reasonCode,
    fieldRestrictions: decision.fieldRestrictions,
  } as const;
  const filtered = filterPortfolioRecord(raw, policy);
  return {
    output: filtered.view,
    removedFields: filtered.removedFields,
    sourceBytes: filtered.sourceBytes,
    filteredBytes: filtered.filteredBytes,
    outputBytes: filtered.filteredBytes,
  };
}

async function emitManagedEvidence(
  events: ApexEvents,
  context: ReturnType<typeof parseAuthenticatedContext>,
  event: ManagedEvidenceEvent,
): Promise<void> {
  if (event.tool !== "portfolio.read" || event.action !== "read") {
    throw new GatewayError("EVENT_ADMISSION_FAILED", "request rejected safely");
  }
  const policy = {
    outcome: event.status === "succeeded" ? "allowed" : "denied",
    policyId: event.policyId,
    reasonCode: event.reasonCode,
    fieldRestrictions: event.fieldRestrictions,
  } as const;
  const toolEvent: ToolExecutionEvent = {
    caller: { principal: context.principal, agentId: context.agentId },
    scope: { workspaceId: context.workspaceId, namespaceId: context.namespaceId },
    tool: "portfolio.read",
    action: "read",
    resource: event.resource,
    backend: "mcp-http-upstream",
    status: event.status,
    latencyMs: event.latencyMs,
    retryCount: 0,
    sizes: {
      inputBytes: event.inputBytes,
      sourceBytes: event.sourceBytes,
      filteredBytes: event.filteredBytes,
      outputBytes: event.outputBytes,
    },
    filtering: { removedFields: event.removedFields },
    policy,
    trace: { traceId: event.traceId, spanId: event.traceId },
  };
  await events.emit(toolEvent);
}

function extractPortfolioRecord(output: unknown): RawPortfolioRecord {
  if (isRecord(output) && isRecord(output.structuredContent)) {
    return output.structuredContent as unknown as RawPortfolioRecord;
  }
  if (isRecord(output) && Array.isArray(output.content)) {
    const text = output.content.find((item) => isRecord(item) && item.type === "text");
    if (isRecord(text) && typeof text.text === "string") {
      try {
        return JSON.parse(text.text) as RawPortfolioRecord;
      } catch {
        // Fall through to the safe filtering failure below.
      }
    }
  }
  throw new GatewayError("FILTERING_FAILED", "managed proxy output rejected safely");
}

async function closeSessions(sessions: ReadonlyMap<string, { close(): Promise<void> }>): Promise<void> {
  await Promise.allSettled([...sessions.values()].map((session) => session.close()));
}

function deniedDecision(): ManagedAuthorizationDecision {
  return {
    outcome: "denied",
    policyId: "managed-proxy-denied",
    reasonCode: "policy.denied",
    fieldRestrictions: [],
  };
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim();
  if (value === undefined || value.length === 0) {
    throw new GatewayError("GOVERNANCE_UNAVAILABLE", "managed HTTP runtime configuration rejected safely");
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
