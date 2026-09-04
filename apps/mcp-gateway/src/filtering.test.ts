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

test("reads validated portfolio scalars once before freezing the public view", () => {
  let reads = 0;
  const raw = { ...rawPortfolioFixture } as RawPortfolioRecord;
  Object.defineProperty(raw, "portfolio_id", {
    configurable: true,
    enumerable: false,
    get() {
      reads += 1;
      return rawPortfolioFixture.portfolio_id;
    },
  });

  filterPortfolioRecord(raw, allowedDecision);

  assert.equal(reads, 1);
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

test("fails closed when a hidden required client field is missing", () => {
  const raw = {
    ...rawPortfolioFixture,
    client: {
      ...rawPortfolioFixture.client,
      tax_id: "",
    },
  } satisfies RawPortfolioRecord;

  assert.throws(
    () => filterPortfolioRecord(raw, allowedDecision),
    (error: unknown) => {
      assert.ok(error instanceof GatewayError);
      assert.equal(error.code, "FILTERING_FAILED");
      assert.equal(error.message.includes("client.tax_id"), true);
      return true;
    },
  );
});

test("fails closed when a hidden required numeric position field is non-finite", () => {
  const raw = {
    ...rawPortfolioFixture,
    positions: [
      {
        ...rawPortfolioFixture.positions[0],
        cost_basis: Number.POSITIVE_INFINITY,
      },
    ],
  } satisfies RawPortfolioRecord;

  assert.throws(
    () => filterPortfolioRecord(raw, allowedDecision),
    (error: unknown) => {
      assert.ok(error instanceof GatewayError);
      assert.equal(error.code, "FILTERING_FAILED");
      assert.equal(error.message.includes("positions.cost_basis"), true);
      return true;
    },
  );
});

test("converts malformed client structure into a safe filtering error", () => {
  const raw = {
    ...rawPortfolioFixture,
    client: null,
  } as unknown as RawPortfolioRecord;

  assert.throws(
    () => filterPortfolioRecord(raw, allowedDecision),
    (error: unknown) => {
      assert.ok(error instanceof GatewayError);
      assert.equal(error.code, "FILTERING_FAILED");
      assert.equal(error instanceof TypeError, false);
      return true;
    },
  );
});

test("converts malformed positions structure into a safe filtering error", () => {
  const raw = {
    ...rawPortfolioFixture,
    positions: [null],
  } as unknown as RawPortfolioRecord;

  assert.throws(
    () => filterPortfolioRecord(raw, allowedDecision),
    (error: unknown) => {
      assert.ok(error instanceof GatewayError);
      assert.equal(error.code, "FILTERING_FAILED");
      assert.equal(error instanceof TypeError, false);
      return true;
    },
  );
});
