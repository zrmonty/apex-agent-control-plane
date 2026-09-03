import assert from "node:assert/strict";
import test from "node:test";

import { GatewayError } from "../context.js";
import { LocalPortfolioAdapter } from "./portfolio.js";

test("returns the same immutable portfolio record for the same read", async () => {
  const adapter = new LocalPortfolioAdapter();
  const first = await adapter.read({ portfolioId: "northstar-401k" });
  const second = await adapter.read({ portfolioId: "northstar-401k" });

  assert.deepEqual(first, second);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.client), true);
  assert.equal(Object.isFrozen(first.positions), true);
  assert.equal(Object.isFrozen(first.positions[0]), true);
  assert.equal("write" in adapter, false);
  assert.equal("trade" in adapter, false);
});

test("fails unknown portfolio reads without echoing requested values", async () => {
  const adapter = new LocalPortfolioAdapter();

  await assert.rejects(
    () => adapter.read({ portfolioId: "secret-portfolio" }),
    (error: unknown) => {
      assert.ok(error instanceof GatewayError);
      assert.equal(error.code, "ADAPTER_FAILED");
      assert.equal(error.message.includes("secret-portfolio"), false);
      return true;
    },
  );
});

test("rejects mismatched snapshot requests with a safe adapter error", async () => {
  const adapter = new LocalPortfolioAdapter();

  await assert.rejects(
    () => adapter.read({ portfolioId: "northstar-401k", asOf: "2026-09-01" }),
    (error: unknown) => {
      assert.ok(error instanceof GatewayError);
      assert.equal(error.code, "ADAPTER_FAILED");
      assert.equal(error.message.includes("2026-09-01"), false);
      return true;
    },
  );
});
