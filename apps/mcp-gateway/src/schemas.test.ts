import assert from "node:assert/strict";
import test from "node:test";

import { parsePortfolioReadInput } from "./schemas.js";

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
