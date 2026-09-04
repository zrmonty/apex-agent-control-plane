import assert from "node:assert/strict";
import test from "node:test";

import type { ToolExecutionEvent } from "./contracts.js";
import { StaticLocalApex } from "./governance/local.js";
import type { RawPortfolioRecord } from "./filtering.js";

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
    resource: "portfolio:opaque",
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
    rawRecord: rawPortfolioFixture,
  };

  await assert.rejects(apex.emit(event as ToolExecutionEvent));
  assert.deepEqual(sink, []);

  const metadataEvent = { ...event };
  delete (metadataEvent as { rawRecord?: unknown }).rawRecord;
  const receipt = await apex.emit(metadataEvent as ToolExecutionEvent);
  assert.match(
    receipt.eventId,
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
  );
  assert.equal(sink.length, 1);
});
