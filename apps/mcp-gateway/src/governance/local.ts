import { randomBytes } from "node:crypto";

import type {
  ApexEvents,
  ApexGovernance,
  AuthorizationDecision,
  AuthorizationRequest,
  EventReceipt,
  PolicySnapshot,
  ToolExecutionEvent,
} from "../contracts.js";
import { portfolioResourceReference } from "../context.js";
import { EventReceiptSchema, ToolExecutionEventSchema } from "../schemas.js";

const LOCAL_POLICY_ID = "local-read-v1";
const LOCAL_POLICY_REVISION = 1;
const LOCAL_FIELD_RESTRICTIONS = Object.freeze([
  "client.account_number",
  "client.tax_id",
  "positions.cost_basis",
] as const);
const DEFAULT_ALLOWED_PORTFOLIOS = Object.freeze(["northstar-401k"]);

function isPortfolioReadRequest(request: AuthorizationRequest): boolean {
  return (
    request.tool === "portfolio.read" &&
    request.action === "read" &&
    request.classification === "confidential" &&
    /^portfolio:sha256:[0-9a-f]{64}$/.test(request.resource)
  );
}

function createUuidV7(): string {
  const bytes = Buffer.alloc(16);
  bytes.writeUIntBE(Date.now(), 0, 6);
  randomBytes(10).copy(bytes, 6);
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");

  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export class StaticLocalApex implements ApexGovernance, ApexEvents {
  readonly #allowedResources: ReadonlySet<string>;
  readonly #eventSink?: ToolExecutionEvent[];

  constructor(options: {
    allowedPortfolios?: Iterable<string>;
    eventSink?: ToolExecutionEvent[];
  } = {}) {
    this.#allowedResources = new Set(
      [...(options.allowedPortfolios ?? DEFAULT_ALLOWED_PORTFOLIOS)].map(
        portfolioResourceReference,
      ),
    );
    this.#eventSink = options.eventSink;
  }

  async authorize(request: AuthorizationRequest): Promise<AuthorizationDecision> {
    if (
      !isPortfolioReadRequest(request) ||
      !this.#allowedResources.has(request.resource)
    ) {
      return {
        outcome: "denied",
        policyId: LOCAL_POLICY_ID,
        reasonCode: "policy.denied",
        fieldRestrictions: [],
      };
    }

    return {
      outcome: "allowed",
      policyId: LOCAL_POLICY_ID,
      reasonCode: "policy.allowed",
      fieldRestrictions: LOCAL_FIELD_RESTRICTIONS,
    };
  }

  async getPolicy(scope: AuthorizationRequest["scope"]): Promise<PolicySnapshot> {
    return {
      scope,
      policyId: LOCAL_POLICY_ID,
      revision: LOCAL_POLICY_REVISION,
    };
  }

  async emit(event: ToolExecutionEvent): Promise<EventReceipt> {
    const metadata = ToolExecutionEventSchema.parse(event);

    this.#eventSink?.push({
      caller: {
        principal: metadata.caller.principal,
        agentId: metadata.caller.agentId,
      },
      scope: {
        workspaceId: metadata.scope.workspaceId,
        namespaceId: metadata.scope.namespaceId,
      },
      tool: metadata.tool,
      action: metadata.action,
      resource: metadata.resource,
      backend: metadata.backend,
      status: metadata.status,
      latencyMs: metadata.latencyMs,
      retryCount: metadata.retryCount,
      filtering: {
        removedFields: [...metadata.filtering.removedFields],
      },
      sizes: {
        inputBytes: metadata.sizes.inputBytes,
        sourceBytes: metadata.sizes.sourceBytes,
        filteredBytes: metadata.sizes.filteredBytes,
        outputBytes: metadata.sizes.outputBytes,
      },
      policy: {
        outcome: metadata.policy.outcome,
        policyId: metadata.policy.policyId,
        reasonCode: metadata.policy.reasonCode,
        revision: metadata.policy.revision,
      },
      trace: {
        traceId: metadata.trace.traceId,
        spanId: metadata.trace.spanId,
      },
    });

    return EventReceiptSchema.parse({ eventId: createUuidV7() });
  }
}
