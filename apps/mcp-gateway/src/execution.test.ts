import assert from "node:assert/strict";
import test from "node:test";

import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import {
  GatewayError,
  type ApexEvents,
  type ApexGovernance,
  type AuthorizationDecision,
  type AuthorizationRequest,
  type GatewayErrorCode,
  type PolicySnapshot,
  type SafeTelemetry,
  type ToolExecutionEvent,
} from "./contracts.js";
import { GatewayExecutor } from "./execution.js";
import { StaticLocalApex } from "./governance/local.js";
import type { RawPortfolioRecord } from "./filtering.js";
import type { PortfolioAdapter } from "./adapters/portfolio.js";

const rawPortfolioFixture: RawPortfolioRecord = {
  portfolio_id: "northstar-401k",
  as_of: "2026-08-31",
  base_currency: "USD",
  total_value: 125000,
  client: {
    display_name: "Northstar Research",
    account_number: "client-record-raw",
    tax_id: "tax-record-raw",
  },
  positions: [
    {
      symbol: "APEX",
      quantity: 100,
      market_value: 10000,
      cost_basis: 7000,
    },
  ],
};

function allowedDecision(): AuthorizationDecision {
  return {
    outcome: "allowed",
    policyId: "local-read-v1",
    reasonCode: "policy.allowed",
    fieldRestrictions: [
      "client.account_number",
      "client.tax_id",
      "positions.cost_basis",
    ],
  };
}

function deniedDecision(): AuthorizationDecision {
  return {
    outcome: "denied",
    policyId: "local-read-v1",
    reasonCode: "policy.denied",
    fieldRestrictions: [],
  };
}

function approvalDecision(): AuthorizationDecision {
  return {
    outcome: "requires_approval",
    policyId: "local-read-v1",
    reasonCode: "policy.requires-approval",
    fieldRestrictions: [],
  };
}

class RecordingGovernance implements ApexGovernance {
  readonly requests: AuthorizationRequest[] = [];
  readonly policyScopes: AuthorizationRequest["scope"][] = [];
  readonly decision: AuthorizationDecision | unknown;
  readonly policy: PolicySnapshot | unknown;
  readonly authorizeError?: Error;
  readonly policyError?: Error;

  constructor(options: {
    decision: AuthorizationDecision | unknown;
    policy?: PolicySnapshot | unknown;
    authorizeError?: Error;
    policyError?: Error;
  }) {
    this.decision = options.decision;
    this.policy =
      options.policy ??
      ({
        scope: {
          workspaceId: "northstar",
          namespaceId: "research",
        },
        policyId: "local-read-v1",
        revision: 1,
        tool: "portfolio.read",
        action: "read",
        classification: "confidential",
      } satisfies PolicySnapshot);
    this.authorizeError = options.authorizeError;
    this.policyError = options.policyError;
  }

  async authorize(request: AuthorizationRequest): Promise<AuthorizationDecision> {
    this.requests.push(request);

    if (this.authorizeError) {
      throw this.authorizeError;
    }

    return this.decision as AuthorizationDecision;
  }

  async getPolicy(scope: AuthorizationRequest["scope"]): Promise<PolicySnapshot> {
    this.policyScopes.push(scope);

    if (this.policyError) {
      throw this.policyError;
    }

    return this.policy as PolicySnapshot;
  }
}

class RecordingEvents implements ApexEvents {
  readonly events: ToolExecutionEvent[] = [];
  readonly emitError?: Error;

  constructor(emitError?: Error) {
    this.emitError = emitError;
  }

  async emit(event: ToolExecutionEvent): Promise<{ readonly eventId: string }> {
    this.events.push(event);

    if (this.emitError) {
      throw this.emitError;
    }

    return { eventId: `evt-${this.events.length}` };
  }
}

class RecordingPortfolioAdapter implements PortfolioAdapter {
  readonly reads: unknown[] = [];
  readonly result: RawPortfolioRecord;
  readonly readError?: Error;

  constructor(options: { result?: RawPortfolioRecord; readError?: Error }) {
    this.result = options.result ?? rawPortfolioFixture;
    this.readError = options.readError;
  }

  get readCount(): number {
    return this.reads.length;
  }

  async read(input: { readonly portfolioId: string; readonly asOf?: string }): Promise<RawPortfolioRecord> {
    this.reads.push(input);

    if (this.readError) {
      throw this.readError;
    }

    return this.result;
  }
}

class RecordingTelemetry implements SafeTelemetry {
  readonly codes: GatewayErrorCode[] = [];

  record(code: GatewayErrorCode): void {
    this.codes.push(code);
  }
}

type FixtureOptions = {
  decision?: AuthorizationDecision | unknown;
  policy?: PolicySnapshot | unknown;
  authorizeError?: Error;
  policyError?: Error;
  emitError?: Error;
  readError?: Error;
  filter?: GatewayExecutor["dependencies"]["filter"];
};

function fixture(options: FixtureOptions = {}) {
  const governance = new RecordingGovernance({
    decision: options.decision ?? allowedDecision(),
    policy: options.policy,
    authorizeError: options.authorizeError,
    policyError: options.policyError,
  });
  const events = new RecordingEvents(options.emitError);
  const adapter = new RecordingPortfolioAdapter({ readError: options.readError });
  const telemetry = new RecordingTelemetry();
  const executor = new GatewayExecutor({
    context: {
      principal: "spiffe://apex/agent/research",
      agentId: "research-agent",
      workspaceId: "northstar",
      namespaceId: "research",
      traceId: "trace-001",
    },
    governance,
    events,
    portfolio: adapter,
    telemetry,
    filter: options.filter,
  });

  return { executor, governance, events, adapter, telemetry };
}

function assertSafeErrorResult(
  result: CallToolResult,
  code: GatewayErrorCode,
  forbiddenValues: readonly string[] = [],
): void {
  assert.equal(result.isError, true);
  assert.equal(result.structuredContent, undefined);
  assert.equal(result.content.length, 1);
  assert.equal(result.content[0]?.type, "text");
  assert.match(result.content[0]?.text ?? "", new RegExp(`\\b${code}\\b`));

  for (const forbiddenValue of forbiddenValues) {
    assert.equal(result.content[0]?.text.includes(forbiddenValue), false);
  }
}

test("allowed reads filter, emit metadata, and return only the public view", async () => {
  const { executor, events, adapter, governance } = fixture();

  const result = await executor.executePortfolioRead({ portfolioId: "northstar-401k" });

  assert.equal(result.isError, undefined);
  assert.equal(adapter.readCount, 1);
  assert.equal(governance.requests.length, 1);
  assert.equal(events.events.length, 1);
  assert.deepEqual(result.structuredContent, {
    portfolioId: "northstar-401k",
    asOf: "2026-08-31",
    baseCurrency: "USD",
    totalValue: 125000,
    client: {
      displayName: "Northstar Research",
    },
    positions: [
      {
        symbol: "APEX",
        quantity: 100,
        marketValue: 10000,
      },
    ],
  });
  assert.equal(JSON.stringify(result.structuredContent).includes("account_number"), false);
  assert.equal(JSON.stringify(events.events[0]).includes("client-record-raw"), false);
  assert.equal(events.events[0]?.status, "succeeded");
  assert.equal(events.events[0]?.policy.revision, 1);
  assert.equal(events.events[0]?.trace.traceId, "trace-001");
  assert.notEqual(events.events[0]?.trace.spanId, "trace-001");
});

test("invalid input is rejected before authorization", async () => {
  const { executor, governance, adapter, events } = fixture();

  const result = await executor.executePortfolioRead({
    portfolioId: "northstar-401k",
    extra: "not-allowed",
  });

  assertSafeErrorResult(result, "INVALID_INPUT", [
    "not-allowed",
    "northstar-401k",
    "client-record-raw",
  ]);
  assert.equal(governance.requests.length, 0);
  assert.equal(adapter.readCount, 0);
  assert.equal(events.events.length, 0);
});

test("denials never execute the adapter", async () => {
  const { executor, adapter, events, governance, telemetry } = fixture({
    decision: deniedDecision(),
  });

  const result = await executor.executePortfolioRead({ portfolioId: "northstar-401k" });

  assertSafeErrorResult(result, "AUTHORIZATION_DENIED", [
    "northstar-401k",
    "client-record-raw",
  ]);
  assert.equal(adapter.readCount, 0);
  assert.equal(governance.policyScopes.length, 0);
  assert.equal(events.events.length, 1);
  assert.equal(events.events[0]?.status, "denied");
  assert.deepEqual(telemetry.codes, []);
});

test("requires approval returns safely without adapter execution", async () => {
  const { executor, adapter, events } = fixture({
    decision: approvalDecision(),
  });

  const result = await executor.executePortfolioRead({ portfolioId: "northstar-401k" });

  assertSafeErrorResult(result, "APPROVAL_REQUIRED", [
    "northstar-401k",
    "client-record-raw",
  ]);
  assert.equal(adapter.readCount, 0);
  assert.equal(events.events.length, 1);
  assert.equal(events.events[0]?.status, "denied");
  assert.equal(events.events[0]?.policy.outcome, "requires_approval");
});

test("authorization service failure becomes governance unavailable", async () => {
  const { executor, adapter, events } = fixture({
    authorizeError: new Error("governance backend raw detail"),
  });

  const result = await executor.executePortfolioRead({ portfolioId: "northstar-401k" });

  assertSafeErrorResult(result, "GOVERNANCE_UNAVAILABLE", [
    "governance backend raw detail",
    "northstar-401k",
  ]);
  assert.equal(adapter.readCount, 0);
  assert.equal(events.events.length, 0);
});

test("policy mismatch fails closed before adapter access", async () => {
  const { executor, adapter, events } = fixture({
    policy: {
      scope: {
        workspaceId: "northstar",
        namespaceId: "research",
      },
      policyId: "different-policy",
      revision: 1,
      tool: "portfolio.read",
      action: "read",
      classification: "confidential",
    },
  });

  const result = await executor.executePortfolioRead({ portfolioId: "northstar-401k" });

  assertSafeErrorResult(result, "GOVERNANCE_UNAVAILABLE", [
    "different-policy",
    "northstar-401k",
  ]);
  assert.equal(adapter.readCount, 0);
  assert.equal(events.events.length, 0);
});

test("malformed policy snapshots fail safely before adapter access", async () => {
  const { executor, adapter, events } = fixture({
    policy: {
      policyId: "local-read-v1",
      revision: 1,
      tool: "portfolio.read",
      action: "read",
      classification: "confidential",
    },
  });

  const result = await executor.executePortfolioRead({ portfolioId: "northstar-401k" });

  assertSafeErrorResult(result, "GOVERNANCE_UNAVAILABLE", ["northstar-401k"]);
  assert.equal(adapter.readCount, 0);
  assert.equal(events.events.length, 0);
});

test("malformed authorization decisions fail safely before adapter access", async () => {
  const { executor, adapter, events } = fixture({
    decision: {
      outcome: "allowed",
      policyId: "local-read-v1",
      reasonCode: "policy.allowed",
    },
  });

  const result = await executor.executePortfolioRead({ portfolioId: "northstar-401k" });

  assertSafeErrorResult(result, "GOVERNANCE_UNAVAILABLE", ["northstar-401k"]);
  assert.equal(adapter.readCount, 0);
  assert.equal(events.events.length, 0);
});

test("adapter failure returns a safe adapter error", async () => {
  const { executor, events } = fixture({
    readError: new Error("portfolio backend exploded"),
  });

  const result = await executor.executePortfolioRead({ portfolioId: "northstar-401k" });

  assertSafeErrorResult(result, "ADAPTER_FAILED", [
    "portfolio backend exploded",
    "northstar-401k",
    "client-record-raw",
  ]);
  assert.equal(events.events.length, 0);
});

test("filter failures return a safe filtering error", async () => {
  const { executor, adapter, events } = fixture({
    filter: () => {
      throw new Error("raw filter failure");
    },
  });

  const result = await executor.executePortfolioRead({ portfolioId: "northstar-401k" });

  assertSafeErrorResult(result, "FILTERING_FAILED", [
    "raw filter failure",
    "northstar-401k",
    "client-record-raw",
  ]);
  assert.equal(adapter.readCount, 1);
  assert.equal(events.events.length, 0);
});

test("event admission failure prevents an allowed result", async () => {
  const { executor, adapter, events } = fixture({
    emitError: new GatewayError("EVENT_ADMISSION_FAILED", "event admission failed"),
  });

  const result = await executor.executePortfolioRead({ portfolioId: "northstar-401k" });

  assertSafeErrorResult(result, "EVENT_ADMISSION_FAILED", [
    "northstar-401k",
    "client-record-raw",
  ]);
  assert.equal(adapter.readCount, 1);
  assert.equal(events.events.length, 1);
  assert.equal(events.events[0]?.status, "succeeded");
});

test("execution events exclude caller-supplied portfolio identifiers", async () => {
  const { executor, events } = fixture();

  await executor.executePortfolioRead({ portfolioId: "northstar-401k" });

  assert.equal(JSON.stringify(events.events[0]).includes("northstar-401k"), false);
});

test("denied-event admission failure preserves the denial and records safe telemetry only", async () => {
  const { executor, adapter, telemetry, events } = fixture({
    decision: deniedDecision(),
    emitError: new Error("raw denied event failure"),
  });

  const result = await executor.executePortfolioRead({ portfolioId: "northstar-401k" });

  assertSafeErrorResult(result, "AUTHORIZATION_DENIED", [
    "raw denied event failure",
    "northstar-401k",
    "client-record-raw",
  ]);
  assert.equal(adapter.readCount, 0);
  assert.equal(events.events.length, 1);
  assert.deepEqual(telemetry.codes, ["EVENT_ADMISSION_FAILED"]);
});

test("local event admission rejects non-metadata fields without persisting them", async () => {
  const sink: ToolExecutionEvent[] = [];
  const apex = new StaticLocalApex({ eventSink: sink });
  const event = {
    caller: {
      principal: "spiffe://apex/agent/research",
      agentId: "research-agent",
    },
    scope: {
      workspaceId: "northstar",
      namespaceId: "research",
    },
    tool: "portfolio.read",
    action: "read",
    backend: "local-portfolio",
    status: "succeeded",
    latencyMs: 1,
    retryCount: 0,
    sizes: {
      inputBytes: 10,
      sourceBytes: 20,
      filteredBytes: 15,
      outputBytes: 15,
    },
    filtering: { removedFields: ["client.tax_id"] },
    policy: {
      outcome: "allowed",
      policyId: "local-read-v1",
      reasonCode: "policy.allowed",
      revision: 1,
    },
    trace: { traceId: "trace-001", spanId: "span-001" },
    rawRecord: rawPortfolioFixture,
  };

  await assert.rejects(apex.emit(event as ToolExecutionEvent));
  assert.deepEqual(sink, []);
});
