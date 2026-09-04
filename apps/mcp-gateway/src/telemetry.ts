import { randomUUID } from "node:crypto";

import type {
  AuthenticatedContext,
  AuthorizationDecision,
  AuthorizationRequest,
  SafeTelemetry,
  ToolExecutionEvent,
} from "./contracts.js";

const textEncoder = new TextEncoder();

export class NullSafeTelemetry implements SafeTelemetry {
  record(): void {}
}

export function safeJsonSizeBytes(value: unknown): number {
  const serialized = JSON.stringify(value) ?? "null";
  return textEncoder.encode(serialized).length;
}

export function createTraceMetadata(
  context: AuthenticatedContext,
): AuthorizationRequest["trace"] {
  return {
    traceId: context.traceId,
    spanId: `span-${randomUUID()}`,
  };
}

export function createToolExecutionEvent(options: {
  request: AuthorizationRequest;
  backend: string;
  status: ToolExecutionEvent["status"];
  latencyMs: number;
  retryCount: number;
  inputBytes: number;
  sourceBytes: number;
  filteredBytes: number;
  outputBytes: number;
  removedFields: readonly string[];
  policy: {
    outcome: AuthorizationDecision["outcome"];
    policyId: string;
    reasonCode: string;
    revision: number;
  };
}): ToolExecutionEvent {
  const {
    request,
    backend,
    status,
    latencyMs,
    retryCount,
    inputBytes,
    sourceBytes,
    filteredBytes,
    outputBytes,
    removedFields,
    policy,
  } = options;

  return {
    caller: {
      principal: request.caller.principal,
      agentId: request.caller.agentId,
    },
    scope: request.scope,
    tool: request.tool,
    action: request.action,
    resource: request.resource,
    backend,
    status,
    latencyMs,
    retryCount,
    sizes: {
      inputBytes,
      sourceBytes,
      filteredBytes,
      outputBytes,
    },
    filtering: {
      removedFields: [...removedFields],
    },
    policy: {
      outcome: policy.outcome,
      policyId: policy.policyId,
      reasonCode: policy.reasonCode,
      revision: policy.revision,
    },
    trace: request.trace,
  };
}
