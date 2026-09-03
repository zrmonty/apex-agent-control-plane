import assert from "node:assert/strict";
import test from "node:test";

import { GatewayError, type AuthorizationDecision } from "./contracts.js";
import { filterPortfolioRecord, type RawPortfolioRecord } from "./filtering.js";

const allowedDecision: AuthorizationDecision = {
  outcome: "allowed",
  policyId: "local-read-v1",
  reasonCode: "policy.allowed",
  fieldRestrictions: [],
};

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

test("filters restricted client and position fields before model access", () => {
  const result = filterPortfolioRecord(rawPortfolioFixture, {
    outcome: "allowed",
    policyId: "local-read-v1",
    reasonCode: "policy.allowed",
    fieldRestrictions: [
      "client.account_number",
      "client.tax_id",
      "positions.cost_basis",
    ],
  });
  const serialized = JSON.stringify(result.view);

  assert.equal(serialized.includes("account_number"), false);
  assert.equal(serialized.includes("tax_id"), false);
  assert.equal(serialized.includes("cost_basis"), false);
  assert.deepEqual(result.removedFields, [
    "client.account_number",
    "client.tax_id",
    "positions.cost_basis",
  ]);
});

test("constructs the public portfolio view from the allowlist only", () => {
  const result = filterPortfolioRecord(rawPortfolioFixture, allowedDecision);

  assert.deepEqual(result.view, {
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
  assert.equal(Object.isFrozen(result.view), true);
  assert.equal(Object.isFrozen(result.view.client), true);
  assert.equal(Object.isFrozen(result.view.positions), true);
  assert.equal(Object.isFrozen(result.view.positions[0]), true);
});

test("fails closed when a required raw field is missing", () => {
  const raw = {
    ...rawPortfolioFixture,
    client: {
      ...rawPortfolioFixture.client,
      display_name: "",
    },
  } satisfies RawPortfolioRecord;

  assert.throws(
    () => filterPortfolioRecord(raw, allowedDecision),
    (error: unknown) => {
      assert.ok(error instanceof GatewayError);
      assert.equal(error.code, "FILTERING_FAILED");
      return true;
    },
  );
});

test("fails closed when a required numeric field is non-finite", () => {
  const raw = {
    ...rawPortfolioFixture,
    total_value: Number.NaN,
  } satisfies RawPortfolioRecord;

  assert.throws(
    () => filterPortfolioRecord(raw, allowedDecision),
    (error: unknown) => {
      assert.ok(error instanceof GatewayError);
      assert.equal(error.code, "FILTERING_FAILED");
      return true;
    },
  );
});
