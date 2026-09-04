import assert from "node:assert/strict";
import test from "node:test";

import {
  AuthorizationDecisionSchema,
  EventReceiptSchema,
  PolicySnapshotSchema,
  ToolExecutionEventSchema,
  parsePortfolioReadInput,
} from "./schemas.js";

test("rejects unknown fields, invalid portfolio ids, and impossible dates", () => {
  assert.throws(() => {
    parsePortfolioReadInput({
      portfolioId: "Northstar/401k",
      query: "select * from client_records",
    });
  });

  assert.throws(() => {
    parsePortfolioReadInput({
      portfolioId: "northstar-401k",
      asOf: "2026-02-31",
    });
  });

  assert.throws(() => {
    parsePortfolioReadInput({
      portfolioId: "northstar-401k",
      scope: "client",
    });
  });
});

test("accepts only lowercase UUIDv7 event receipts", () => {
  assert.equal(
    EventReceiptSchema.safeParse({
      eventId: "018f5c91-2d88-7c00-8000-000000000001",
    }).success,
    true,
  );
  assert.equal(EventReceiptSchema.safeParse(null).success, false);
  assert.equal(
    EventReceiptSchema.safeParse({
      eventId: "018f5c91-2d88-4c00-8000-000000000001",
    }).success,
    false,
  );
  assert.equal(
    EventReceiptSchema.safeParse({
      eventId: "018F5C91-2D88-7C00-8000-000000000001",
    }).success,
    false,
  );
  assert.equal(
    EventReceiptSchema.safeParse({
      eventId: "018f5c91-2d88-7c00-8000-000000000001",
      raw: "must-not-be-accepted",
    }).success,
    false,
  );
});

test("bounds governance identifiers and field restriction cardinality", () => {
  assert.equal(
    AuthorizationDecisionSchema.safeParse({
      outcome: "allowed",
      policyId: "p".repeat(10_000),
      reasonCode: "policy.allowed",
      fieldRestrictions: [],
    }).success,
    false,
  );
  assert.equal(
    AuthorizationDecisionSchema.safeParse({
      outcome: "allowed",
      policyId: "local-read-v1",
      reasonCode: "policy.allowed",
      fieldRestrictions: Array.from({ length: 65 }, () => "client.tax_id"),
    }).success,
    false,
  );
  assert.equal(
    AuthorizationDecisionSchema.safeParse({
      outcome: "allowed",
      policyId: "local-read-v1",
      reasonCode: "policy.allowed",
      fieldRestrictions: Array.from(
        { length: 64 },
        () => `field.${"a".repeat(59)}`,
      ),
    }).success,
    false,
  );
  assert.equal(
    PolicySnapshotSchema.safeParse({
      scope: { workspaceId: "northstar", namespaceId: "research" },
      policyId: "local-read-v1",
      revision: 1,
    }).success,
    true,
  );
  assert.equal(
    PolicySnapshotSchema.safeParse({
      scope: { workspaceId: "northstar", namespaceId: "research" },
      policyId: "local-read-v1",
      revision: 1,
      tool: "portfolio.read",
    }).success,
    false,
  );
  assert.equal(
    PolicySnapshotSchema.safeParse({
      scope: { workspaceId: "northstar", namespaceId: "research" },
      policyId: "local/read/v1",
      revision: 1,
    }).success,
    false,
  );
});

test("bounds metadata identifiers, removed fields, and aggregate event size", () => {
  const baseEvent = {
    caller: {
      principal: "spiffe://apex/agent/research",
      agentId: "research-agent",
    },
    scope: { workspaceId: "northstar", namespaceId: "research" },
    tool: "portfolio.read",
    action: "read",
    resource: "portfolio:sha256:0000000000000000000000000000000000000000000000000000000000000000",
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
      fieldRestrictions: ["client.tax_id"],
    },
    trace: { traceId: "trace-001", spanId: "span-001" },
  };

  assert.equal(ToolExecutionEventSchema.safeParse(baseEvent).success, true);
  assert.equal(
    ToolExecutionEventSchema.safeParse({
      ...baseEvent,
      policy: { ...baseEvent.policy, revision: 1 },
    }).success,
    false,
  );

  assert.equal(
    ToolExecutionEventSchema.safeParse({
      ...baseEvent,
      backend: "b".repeat(10_000),
    }).success,
    false,
  );
  assert.equal(
    ToolExecutionEventSchema.safeParse({
      ...baseEvent,
      filtering: {
        removedFields: Array.from({ length: 65 }, () => "client.tax_id"),
      },
    }).success,
    false,
  );
  assert.equal(
    ToolExecutionEventSchema.safeParse({
      ...baseEvent,
      filtering: {
        removedFields: Array.from({ length: 64 }, () => "f".repeat(256)),
      },
    }).success,
    false,
  );
  assert.equal(
    ToolExecutionEventSchema.safeParse({
      ...baseEvent,
      filtering: {
        removedFields: Array.from(
          { length: 64 },
          () => `field.${"a".repeat(53)}`,
        ),
      },
    }).success,
    false,
  );
});
