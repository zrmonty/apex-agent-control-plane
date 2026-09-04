import { randomUUID } from "node:crypto";

import type {
  ApexEvents,
  ApexGovernance,
  AuthorizationDecision,
  AuthorizationRequest,
  PolicySnapshot,
  ToolExecutionEvent,
} from "../contracts.js";

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
    this.#eventSink?.push({
      ...event,
      filtering: {
        removedFields: [...event.filtering.removedFields],
      },
      sizes: { ...event.sizes },
      policy: { ...event.policy },
      trace: { ...event.trace },
      caller: { ...event.caller },
      scope: { ...event.scope },
    });

    return { eventId: `evt-${randomUUID()}` };
  }
}
