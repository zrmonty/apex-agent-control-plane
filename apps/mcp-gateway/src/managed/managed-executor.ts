import { authenticateInbound, type HeaderValues, type InboundTokenVerifier } from "./auth.js";
import { McpProxyToolClassification } from "@apex/contracts";
import type { ReadonlyRuntimeConfiguration } from "./runtime-config.js";
import { assertRuntimeScope, runtimeSpec, type RuntimeTool as ExposedTool } from "./runtime-types.js";
import { compileExposedToolIndexes, type ExposedToolIndexes, type UpstreamSession } from "./upstream.js";
import { portfolioResourceReference } from "../context.js";
import { GatewayError, type AuthenticatedContext } from "../contracts.js";
import { createClock, durationUs, type Clock } from "../telemetry/clock.js";

export type ManagedAuthorizationRequest = Readonly<{
  caller: AuthenticatedContext & { readonly subject: string };
  proxyId: string;
  revisionId: string;
  upstreamId: string;
  tool: string;
  action: "read" | "execute";
  resource: string;
  classification: ExposedTool["classification"];
  scope: Readonly<{ workspaceId: string; namespaceId: string }>;
  traceId: string;
}>;

export type ManagedAuthorizationDecision = Readonly<{
  outcome: "allowed" | "denied" | "requires_approval";
  policyId: string;
  reasonCode: string;
  fieldRestrictions: readonly string[];
}>;

export type ManagedPolicySnapshot = Readonly<{
  policyId: string;
  revision: number;
}>;

export interface ManagedGovernance {
  authorize(request: ManagedAuthorizationRequest): Promise<ManagedAuthorizationDecision>;
  getPolicy(scope: Readonly<{ workspaceId: string; namespaceId: string }>): Promise<ManagedPolicySnapshot>;
}

export type ManagedEvidenceEvent = Readonly<{
  proxyId: string;
  revisionId: string;
  upstreamId: string;
  tool: string;
  action: "read" | "execute";
  resource: string;
  status: "succeeded" | "denied" | "failed";
  subject: string;
  traceId: string;
  policyId: string;
  reasonCode: string;
  /** Monotonic integer microseconds; replaces the old rounded latencyMs API. */
  latencyUs: bigint;
  inputBytes: number;
  sourceBytes: number;
  filteredBytes: number;
  outputBytes: number;
  removedFields: readonly string[];
  fieldRestrictions: readonly string[];
}>;

export type ManagedFilteredOutput = Readonly<{
  output: unknown;
  removedFields: readonly string[];
  sourceBytes: number;
  filteredBytes: number;
  outputBytes?: number;
}>;

type ManagedExecutorOptions = Readonly<{
  config: ReadonlyRuntimeConfiguration;
  caller: AuthenticatedContext;
  clock?: Clock;
  verifier: InboundTokenVerifier;
  governance: ManagedGovernance;
  /** Legacy component injection only: never consumed; requires_approval refuses. */
  approve: (request: ManagedAuthorizationRequest) => Promise<boolean>;
  admit: (request: ManagedAuthorizationRequest) => Promise<boolean>;
  checkEgress: (tool: ExposedTool) => Promise<void>;
  validateInput: (input: unknown) => unknown;
  filterOutput: (
    output: unknown,
    tool: ExposedTool,
    decision: ManagedAuthorizationDecision,
  ) => ManagedFilteredOutput;
  sessions: ReadonlyMap<string, UpstreamSession>;
  emitEvidence: (event: ManagedEvidenceEvent) => Promise<void>;
}>;

export class ManagedExecutor {
  private readonly toolIndexes: ExposedToolIndexes;
  private readonly clock: Clock;

  constructor(private readonly options: ManagedExecutorOptions) {
    assertRuntimeScope(options.config, options.caller);
    this.clock = options.clock ?? createClock();
    this.toolIndexes = compileExposedToolIndexes(options.config);
  }

  async execute(toolAlias: string, input: unknown, headers: HeaderValues): Promise<unknown> {
    const startedAt = this.clock.now().monotonicNs;
    const identity = await authenticateInbound(headers, this.options.config, this.options.verifier);
    const parsedInput = this.parseInput(input);
    const tool = this.findTool(toolAlias);
    const request = this.authorizationRequest(tool, identity.subject, parsedInput);
    const inputBytes = jsonSize(parsedInput);
    const decision = await this.authorize(request);
    if (decision.outcome === "denied") {
      await this.emitDenied(request, decision, startedAt, inputBytes);
      throw new GatewayError("AUTHORIZATION_DENIED", "request rejected safely");
    }
    if (decision.outcome === "requires_approval") {
      // No staged runtime can consume real approval authority yet. In particular,
      // configuration NONE never turns an Apex approval decision into approval.
      await this.emitDenied(request, decision, startedAt, inputBytes);
      throw new GatewayError("APPROVAL_REQUIRED", "request rejected safely");
    }
    const policy = await this.loadPolicy(request, decision);
    let admitted: boolean;
    try {
      admitted = await this.options.admit(request);
    } catch {
      await this.emitDenied(request, decision, startedAt, inputBytes);
      throw new GatewayError("GOVERNANCE_UNAVAILABLE", "request rejected safely");
    }
    if (!admitted) {
      await this.emitDenied(request, decision, startedAt, inputBytes);
      throw new GatewayError("AUTHORIZATION_DENIED", "request rejected safely");
    }
    try {
      const session = this.sessionFor(tool);
      await this.options.checkEgress(tool);
      const rawOutput = await session.call(tool, parsedInput);
      const filtered = this.filter(rawOutput, tool, decision);
      try {
        await this.options.emitEvidence({
          proxyId: request.proxyId,
          revisionId: request.revisionId,
          upstreamId: request.upstreamId,
          tool: request.tool,
          action: request.action,
          resource: request.resource,
          status: "succeeded",
          subject: request.caller.subject,
          traceId: request.traceId,
          policyId: policy.policyId,
          reasonCode: decision.reasonCode,
          latencyUs: durationUs(startedAt, this.clock.now().monotonicNs),
          inputBytes,
          sourceBytes: filtered.sourceBytes,
          filteredBytes: filtered.filteredBytes,
          outputBytes: filtered.outputBytes ?? jsonSize(filtered.output),
          removedFields: filtered.removedFields,
          fieldRestrictions: decision.fieldRestrictions,
        });
      } catch {
        throw new GatewayError("EVENT_ADMISSION_FAILED", "request rejected safely");
      }
      return filtered.output;
    } catch (error: unknown) {
      if (
        error instanceof GatewayError &&
        ["EVENT_ADMISSION_FAILED", "FILTERING_FAILED", "INVALID_INPUT"].includes(error.code)
      ) {
        throw error;
      }
      throw new GatewayError("ADAPTER_FAILED", "managed proxy execution failed safely");
    }
  }

  async close(): Promise<void> {
    const sessions = [...new Set(this.options.sessions.values())];
    await Promise.allSettled(sessions.map((session) => session.close()));
  }

  private parseInput(input: unknown): unknown {
    try {
      return this.options.validateInput(input);
    } catch {
      throw new GatewayError("INVALID_INPUT", "managed proxy input rejected safely");
    }
  }

  private findTool(alias: string): ExposedTool {
    const tool = this.toolIndexes.byAlias.get(alias);
    if (tool === undefined) {
      throw new GatewayError("INVALID_INPUT", "managed proxy tool is not exposed");
    }
    return tool;
  }

  private sessionFor(tool: ExposedTool): UpstreamSession {
    const session = this.options.sessions.get(tool.upstreamId);
    if (session === undefined) {
      throw new GatewayError("ADAPTER_FAILED", "managed proxy upstream is unavailable safely");
    }
    return session;
  }

  private authorizationRequest(
    tool: ExposedTool,
    subject: string,
    input: unknown,
  ): ManagedAuthorizationRequest {
    const action = tool.classification === McpProxyToolClassification.READ ? "read" : "execute";
    return {
      caller: { ...this.options.caller, subject },
      proxyId: this.options.config.proxyId,
      revisionId: this.options.config.revisionId,
      upstreamId: tool.upstreamId,
      tool: tool.alias,
      action,
      resource: resourceReference(this.options.config.proxyId, tool, input),
      classification: tool.classification,
      scope: {
        workspaceId: this.options.caller.workspaceId,
        namespaceId: this.options.caller.namespaceId,
      },
      traceId: this.options.caller.traceId,
    };
  }

  private async authorize(request: ManagedAuthorizationRequest): Promise<ManagedAuthorizationDecision> {
    try {
      const decision = await this.options.governance.authorize(request);
      if (!isDecision(decision)) throw new Error("invalid decision");
      return decision;
    } catch {
      throw new GatewayError("GOVERNANCE_UNAVAILABLE", "request rejected safely");
    }
  }

  private async loadPolicy(
    request: ManagedAuthorizationRequest,
    decision: ManagedAuthorizationDecision,
  ): Promise<ManagedPolicySnapshot> {
    try {
      const policy = await this.options.governance.getPolicy(request.scope);
      if (!isPolicy(policy) || policy.policyId !== decision.policyId || policy.policyId !== runtimeSpec(this.options.config).governanceBinding!.policyId) {
        throw new Error("policy mismatch");
      }
      return policy;
    } catch {
      throw new GatewayError("GOVERNANCE_UNAVAILABLE", "request rejected safely");
    }
  }

  private filter(
    output: unknown,
    tool: ExposedTool,
    decision: ManagedAuthorizationDecision,
  ): ManagedFilteredOutput {
    try {
      const filtered = this.options.filterOutput(output, tool, decision);
      if (
        !Number.isSafeInteger(filtered.sourceBytes) ||
        !Number.isSafeInteger(filtered.filteredBytes) ||
        (filtered.outputBytes !== undefined && !Number.isSafeInteger(filtered.outputBytes)) ||
        filtered.sourceBytes < filtered.filteredBytes
      ) {
        throw new Error("invalid filtered output");
      }
      return filtered;
    } catch {
      throw new GatewayError("FILTERING_FAILED", "managed proxy output rejected safely");
    }
  }

  private async emitDenied(
    request: ManagedAuthorizationRequest,
    decision: ManagedAuthorizationDecision,
    startedAt: bigint,
    inputBytes: number,
  ): Promise<void> {
    try {
      await this.options.emitEvidence({
        proxyId: request.proxyId,
        revisionId: request.revisionId,
        upstreamId: request.upstreamId,
        tool: request.tool,
        action: request.action,
        resource: request.resource,
        status: "denied",
        subject: request.caller.subject,
        traceId: request.traceId,
        policyId: decision.policyId,
        reasonCode: decision.reasonCode,
        latencyUs: durationUs(startedAt, this.clock.now().monotonicNs),
        inputBytes,
        sourceBytes: 0,
        filteredBytes: 0,
        outputBytes: 0,
        removedFields: [],
        fieldRestrictions: decision.fieldRestrictions,
      });
    } catch {
      // A denial remains a denial when evidence admission is unavailable.
    }
  }
}

function resourceReference(
  proxyId: string,
  tool: ExposedTool,
  input: unknown,
): string {
  if (
    tool.alias === "portfolio.read" &&
    isRecord(input) &&
    typeof input.portfolioId === "string"
  ) {
    return portfolioResourceReference(input.portfolioId);
  }
  return `mcp:${proxyId}:${tool.upstreamId}:${tool.toolName}`;
}

function isDecision(value: ManagedAuthorizationDecision): boolean {
  return (
    value !== null &&
    ["allowed", "denied", "requires_approval"].includes(value.outcome) &&
    typeof value.policyId === "string" &&
    typeof value.reasonCode === "string" &&
    Array.isArray(value.fieldRestrictions)
  );
}

function isPolicy(value: ManagedPolicySnapshot): boolean {
  return value !== null && typeof value.policyId === "string" && Number.isSafeInteger(value.revision) && value.revision > 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function jsonSize(value: unknown): number {
  try {
    return Buffer.byteLength(JSON.stringify(value) ?? "null", "utf8");
  } catch {
    throw new GatewayError("INVALID_INPUT", "managed proxy input rejected safely");
  }
}
