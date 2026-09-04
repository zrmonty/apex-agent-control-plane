import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { PortfolioAdapter } from "./adapters/portfolio.js";
import {
  type AuthenticatedContext,
  type ApexEvents,
  type ApexGovernance,
  GatewayError,
  type GatewayErrorCode,
  type PolicySnapshot,
  type SafeTelemetry,
  type AuthorizationDecision,
} from "./contracts.js";
import {
  buildPortfolioReadAuthorizationRequest,
} from "./context.js";
import { filterPortfolioRecord, type FilterResult, type RawPortfolioRecord } from "./filtering.js";
import {
  AuthorizationDecisionSchema,
  PolicySnapshotSchema,
  parsePortfolioReadInput,
} from "./schemas.js";
import {
  NullSafeTelemetry,
  createToolExecutionEvent,
  createTraceMetadata,
  safeJsonSizeBytes,
} from "./telemetry.js";

type PortfolioFilter = (
  raw: RawPortfolioRecord,
  decision: AuthorizationDecision,
) => FilterResult;

export type GatewayDependencies = {
  readonly context: AuthenticatedContext;
  readonly governance: ApexGovernance;
  readonly events: ApexEvents;
  readonly portfolio: PortfolioAdapter;
  readonly filter?: PortfolioFilter;
  readonly telemetry?: SafeTelemetry;
  readonly backend?: string;
};

const SAFE_EXPLANATIONS: Record<GatewayErrorCode, string> = {
  INVALID_INPUT: "request rejected safely",
  AUTHORIZATION_DENIED: "request rejected safely",
  APPROVAL_REQUIRED: "request rejected safely",
  GOVERNANCE_UNAVAILABLE: "request rejected safely",
  ADAPTER_FAILED: "request rejected safely",
  FILTERING_FAILED: "request rejected safely",
  EVENT_ADMISSION_FAILED: "request rejected safely",
};

function latencyMs(startedAt: number): number {
  return Math.max(0, Date.now() - startedAt);
}

function toGatewayError(
  error: unknown,
  code: GatewayErrorCode,
): GatewayError {
  if (error instanceof GatewayError && error.code === code) {
    return error;
  }

  return new GatewayError(code, SAFE_EXPLANATIONS[code]);
}

function toErrorResult(code: GatewayErrorCode): CallToolResult {
  return {
    isError: true,
    content: [{ type: "text", text: `${code}: ${SAFE_EXPLANATIONS[code]}` }],
  };
}

function toSuccessResult(view: FilterResult["view"]): CallToolResult {
  return {
    content: [{ type: "text", text: "portfolio.read completed" }],
    structuredContent: view,
  };
}

function matchesPolicySnapshot(
  policy: PolicySnapshot,
  request: ReturnType<typeof buildPortfolioReadAuthorizationRequest>,
  decision: AuthorizationDecision,
): boolean {
  return (
    policy.policyId === decision.policyId &&
    policy.scope.workspaceId === request.scope.workspaceId &&
    policy.scope.namespaceId === request.scope.namespaceId &&
    policy.tool === request.tool &&
    policy.action === request.action &&
    policy.classification === request.classification
  );
}

export class GatewayExecutor {
  readonly dependencies: Readonly<Required<GatewayDependencies>>;

  constructor(dependencies: GatewayDependencies) {
    this.dependencies = {
      ...dependencies,
      filter: dependencies.filter ?? filterPortfolioRecord,
      telemetry: dependencies.telemetry ?? new NullSafeTelemetry(),
      backend: dependencies.backend ?? "local-portfolio",
    };
  }

  async executePortfolioRead(input: unknown): Promise<CallToolResult> {
    const startedAt = Date.now();

    let parsedInput;
    try {
      parsedInput = parsePortfolioReadInput(input);
    } catch (error: unknown) {
      return toErrorResult(toGatewayError(error, "INVALID_INPUT").code);
    }

    const trace = createTraceMetadata(this.dependencies.context);
    const request = buildPortfolioReadAuthorizationRequest(
      this.dependencies.context,
      parsedInput,
      trace.spanId,
    );
    const inputBytes = safeJsonSizeBytes(parsedInput);

    let decision: AuthorizationDecision;
    try {
      const response = await this.dependencies.governance.authorize(request);
      const parsedDecision = AuthorizationDecisionSchema.safeParse(response);
      if (!parsedDecision.success) {
        return toErrorResult("GOVERNANCE_UNAVAILABLE");
      }
      decision = parsedDecision.data;
    } catch (error: unknown) {
      return toErrorResult(toGatewayError(error, "GOVERNANCE_UNAVAILABLE").code);
    }

    if (decision.outcome !== "allowed") {
      try {
        await this.dependencies.events.emit(
          createToolExecutionEvent({
            request,
            backend: this.dependencies.backend,
            status: "denied",
            latencyMs: latencyMs(startedAt),
            retryCount: 0,
            inputBytes,
            sourceBytes: 0,
            filteredBytes: 0,
            outputBytes: 0,
            removedFields: [],
            policy: {
              outcome: decision.outcome,
              policyId: decision.policyId,
              reasonCode: decision.reasonCode,
              revision: 0,
            },
          }),
        );
      } catch {
        this.dependencies.telemetry.record("EVENT_ADMISSION_FAILED");
      }

      return toErrorResult(
        decision.outcome === "denied"
          ? "AUTHORIZATION_DENIED"
          : "APPROVAL_REQUIRED",
      );
    }

    let policy: PolicySnapshot;
    try {
      const response = await this.dependencies.governance.getPolicy(request.scope);
      const parsedPolicy = PolicySnapshotSchema.safeParse(response);
      if (!parsedPolicy.success) {
        return toErrorResult("GOVERNANCE_UNAVAILABLE");
      }
      policy = parsedPolicy.data;
    } catch (error: unknown) {
      return toErrorResult(toGatewayError(error, "GOVERNANCE_UNAVAILABLE").code);
    }

    if (!matchesPolicySnapshot(policy, request, decision)) {
      return toErrorResult("GOVERNANCE_UNAVAILABLE");
    }

    let rawRecord: RawPortfolioRecord;
    try {
      rawRecord = await this.dependencies.portfolio.read(parsedInput);
    } catch (error: unknown) {
      return toErrorResult(toGatewayError(error, "ADAPTER_FAILED").code);
    }

    let filtered: FilterResult;
    try {
      filtered = this.dependencies.filter(rawRecord, decision);
    } catch (error: unknown) {
      return toErrorResult(toGatewayError(error, "FILTERING_FAILED").code);
    }

    try {
      await this.dependencies.events.emit(
        createToolExecutionEvent({
          request,
          backend: this.dependencies.backend,
          status: "succeeded",
          latencyMs: latencyMs(startedAt),
          retryCount: 0,
          inputBytes,
          sourceBytes: filtered.sourceBytes,
          filteredBytes: filtered.filteredBytes,
          outputBytes: safeJsonSizeBytes(filtered.view),
          removedFields: filtered.removedFields,
          policy: {
            outcome: decision.outcome,
            policyId: decision.policyId,
            reasonCode: decision.reasonCode,
            revision: policy.revision,
          },
        }),
      );
    } catch (error: unknown) {
      return toErrorResult(toGatewayError(error, "EVENT_ADMISSION_FAILED").code);
    }

    return toSuccessResult(filtered.view);
  }
}
