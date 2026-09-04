import type {
  ApexGovernance,
  AuthorizationDecision,
  AuthorizationRequest,
  PolicySnapshot,
} from "../contracts.js";
import { GatewayError } from "../contracts.js";
import type { LiveGrpcConfig } from "./config.js";
import { createGrpcClient, protoPath, unaryCall } from "./grpc.js";
import { loadClientMaterial } from "./secrets.js";

export type GovernanceWireRequest = {
  readonly caller: { readonly principal: string; readonly agent_id: string };
  readonly scope: { readonly workspace_id: string; readonly namespace_id: string };
  readonly tool: string;
  readonly action: string;
  readonly resource: string;
  readonly classification: string;
  readonly trace: { readonly trace_id: string; readonly span_id: string };
};

export function toGovernanceWireRequest(request: AuthorizationRequest): GovernanceWireRequest {
  return {
    caller: { principal: request.caller.principal, agent_id: request.caller.agentId },
    scope: {
      workspace_id: request.scope.workspaceId,
      namespace_id: request.scope.namespaceId,
    },
    tool: request.tool,
    action: request.action,
    resource: request.resource,
    classification: request.classification,
    trace: { trace_id: request.trace.traceId, span_id: request.trace.spanId },
  };
}

export function createLiveGovernanceClient(
  config: LiveGrpcConfig,
  trustedSecretBase: string,
  timeoutMs = 5_000,
): ApexGovernance {
  let clientPromise: Promise<{ readonly client: ReturnType<typeof createGrpcClient>; readonly token: string }> | undefined;
  const getClient = async () => {
    clientPromise ??= loadClientMaterial(config, trustedSecretBase).then((material) => ({
      client: createGrpcClient(protoPath("governance.proto"), "GovernanceGateway", config.endpoint, material),
      token: material.token,
    }));
    return clientPromise;
  };
  return {
    async authorize(request) {
      const { client, token } = await getClient();
      const response = await unaryCall(
        client,
        "authorize",
        toGovernanceWireRequest(request),
        token,
        timeoutMs,
        "GOVERNANCE_UNAVAILABLE",
      );
      return parseDecision(response);
    },
    async getPolicy(scope) {
      const { client, token } = await getClient();
      const response = await unaryCall(
        client,
        "getPolicy",
        { scope: { workspace_id: scope.workspaceId, namespace_id: scope.namespaceId } },
        token,
        timeoutMs,
        "GOVERNANCE_UNAVAILABLE",
      );
      return parsePolicy(response);
    },
  };
}

function parseDecision(value: unknown): AuthorizationDecision {
  if (!isRecord(value)) {
    throw unavailable();
  }
  const outcome = value.outcome;
  if (outcome !== "ALLOWED" && outcome !== "DENIED" && outcome !== "REQUIRES_APPROVAL") {
    throw unavailable();
  }
  const fieldRestrictions = value.field_restrictions;
  if (!Array.isArray(fieldRestrictions) || !fieldRestrictions.every((field) => typeof field === "string")) {
    throw unavailable();
  }
  return {
    outcome: outcome === "ALLOWED" ? "allowed" : outcome === "DENIED" ? "denied" : "requires_approval",
    policyId: safeString(value.policy_id),
    reasonCode: safeString(value.reason_code),
    fieldRestrictions,
  };
}

function parsePolicy(value: unknown): PolicySnapshot {
  if (!isRecord(value) || !isRecord(value.scope)) {
    throw unavailable();
  }
  const revision = Number(value.revision);
  if (!Number.isSafeInteger(revision) || revision < 1) {
    throw unavailable();
  }
  return {
    scope: {
      workspaceId: safeString(value.scope.workspace_id),
      namespaceId: safeString(value.scope.namespace_id),
    },
    policyId: safeString(value.policy_id),
    revision,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function safeString(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 256 || value.includes("..")) {
    throw unavailable();
  }
  return value;
}

function unavailable(): GatewayError {
  return new GatewayError("GOVERNANCE_UNAVAILABLE", "request rejected safely");
}
