import { randomUUID } from "node:crypto";

import type {
  ApexEvents,
  ApexGovernance,
  AuthorizationDecision,
  AuthorizationRequest,
  PolicySnapshot,
  ToolExecutionEvent,
} from "../contracts.js";
import { ToolExecutionEventSchema } from "../schemas.js";

const LOCAL_POLICY_ID = "local-read-v1";
const LOCAL_POLICY_REVISION = 1;
const LOCAL_FIELD_RESTRICTIONS = Object.freeze([
  "client.account_number",
  "client.tax_id",
  "positions.cost_basis",
] as const);
const DEFAULT_ALLOWED_PORTFOLIOS = Object.freeze(["northstar-401k"]);

function resourcePrefix(scope: AuthorizationRequest["scope"]): string {
  return `portfolio:${scope.workspaceId}/${scope.namespaceId}/`;
}

function extractPortfolioId(request: AuthorizationRequest): string | null {
  const prefix = resourcePrefix(request.scope);

  if (
    request.tool !== "portfolio.read" ||
    request.action !== "read" ||
    request.classification !== "confidential" ||
    !request.resource.startsWith(prefix)
  ) {
    return null;
  }

  const portfolioId = request.resource.slice(prefix.length);
  return portfolioId.length > 0 ? portfolioId : null;
}

export class StaticLocalApex implements ApexGovernance, ApexEvents {
  readonly #allowedPortfolios: ReadonlySet<string>;
  readonly #eventSink?: ToolExecutionEvent[];

  constructor(options: {
    allowedPortfolios?: Iterable<string>;
    eventSink?: ToolExecutionEvent[];
  } = {}) {
    this.#allowedPortfolios = new Set(
      options.allowedPortfolios ?? DEFAULT_ALLOWED_PORTFOLIOS,
    );
    this.#eventSink = options.eventSink;
  }

  async authorize(request: AuthorizationRequest): Promise<AuthorizationDecision> {
    const portfolioId = extractPortfolioId(request);

    if (portfolioId === null || !this.#allowedPortfolios.has(portfolioId)) {
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
      tool: "portfolio.read",
      action: "read",
      classification: "confidential",
    };
  }

  async emit(event: ToolExecutionEvent): Promise<{ readonly eventId: string }> {
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

    return { eventId: `evt-${randomUUID()}` };
  }
}
