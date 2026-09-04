export type AuthenticatedContext = {
  readonly principal: string;
  readonly agentId: string;
  readonly workspaceId: string;
  readonly namespaceId: string;
  readonly traceId: string;
};

export type AuthorizationRequest = {
  readonly caller: AuthenticatedContext;
  readonly scope: {
    readonly workspaceId: string;
    readonly namespaceId: string;
  };
  readonly tool: "portfolio.read";
  readonly action: "read";
  readonly resource: string;
  readonly classification: "confidential";
  readonly trace: {
    readonly traceId: string;
    readonly spanId: string;
  };
};

export type AuthorizationDecision = {
  readonly outcome: "allowed" | "denied" | "requires_approval";
  readonly policyId: string;
  readonly reasonCode: string;
  readonly fieldRestrictions: readonly string[];
};

export type PolicySnapshot = {
  readonly scope: AuthorizationRequest["scope"];
  readonly policyId: string;
  readonly revision: number;
};

export type EventReceipt = {
  readonly eventId: string;
};

export type ToolExecutionEvent = {
  readonly caller: {
    readonly principal: string;
    readonly agentId: string;
  };
  readonly scope: AuthorizationRequest["scope"];
  readonly tool: AuthorizationRequest["tool"];
  readonly action: AuthorizationRequest["action"];
  readonly resource: string;
  readonly backend: string;
  readonly status: "succeeded" | "denied" | "failed";
  readonly latencyMs: number;
  readonly retryCount: number;
  readonly sizes: {
    readonly inputBytes: number;
    readonly sourceBytes: number;
    readonly filteredBytes: number;
    readonly outputBytes: number;
  };
  readonly filtering: {
    readonly removedFields: readonly string[];
  };
  readonly policy: {
    readonly outcome: AuthorizationDecision["outcome"];
    readonly policyId: string;
    readonly reasonCode: string;
    readonly revision: number;
  };
  readonly trace: AuthorizationRequest["trace"];
};

export interface ApexGovernance {
  authorize(request: AuthorizationRequest): Promise<AuthorizationDecision>;
  getPolicy(scope: AuthorizationRequest["scope"]): Promise<PolicySnapshot>;
}

export interface ApexEvents {
  emit(event: ToolExecutionEvent): Promise<EventReceipt>;
}

export interface SafeTelemetry {
  record(code: GatewayErrorCode): void;
}

export type GatewayErrorCode =
  | "INVALID_INPUT"
  | "AUTHORIZATION_DENIED"
  | "APPROVAL_REQUIRED"
  | "GOVERNANCE_UNAVAILABLE"
  | "ADAPTER_FAILED"
  | "FILTERING_FAILED"
  | "EVENT_ADMISSION_FAILED";

export class GatewayError extends Error {
  readonly code: GatewayErrorCode;

  constructor(code: GatewayErrorCode, safeExplanation: string) {
    super(`${code}: ${safeExplanation}`);
    this.name = "GatewayError";
    this.code = code;
  }
}
