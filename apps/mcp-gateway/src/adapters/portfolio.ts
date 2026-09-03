import type { PortfolioReadInput } from "../schemas.js";
import { GatewayError } from "../contracts.js";
import type { RawPortfolioRecord } from "../filtering.js";

export interface PortfolioAdapter {
  read(input: PortfolioReadInput): Promise<RawPortfolioRecord>;
}

const SEEDED_PORTFOLIOS: Readonly<Record<string, RawPortfolioRecord>> = Object.freeze({
  "northstar-401k": deepFreeze({
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
  }),
});

function cloneRawPortfolioRecord(record: RawPortfolioRecord): RawPortfolioRecord {
  return {
    portfolio_id: record.portfolio_id,
    as_of: record.as_of,
    base_currency: record.base_currency,
    total_value: record.total_value,
    client: {
      display_name: record.client.display_name,
      account_number: record.client.account_number,
      tax_id: record.client.tax_id,
    },
    positions: record.positions.map((position) => ({
      symbol: position.symbol,
      quantity: position.quantity,
      market_value: position.market_value,
      cost_basis: position.cost_basis,
    })),
  };
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);

    for (const nested of Object.values(value as Record<string, unknown>)) {
      deepFreeze(nested);
    }
  }

  return value;
}

export class LocalPortfolioAdapter implements PortfolioAdapter {
  async read(input: PortfolioReadInput): Promise<RawPortfolioRecord> {
    const record = SEEDED_PORTFOLIOS[input.portfolioId];

    if (record === undefined) {
      throw new GatewayError("ADAPTER_FAILED", "portfolio record unavailable");
    }

    return deepFreeze(cloneRawPortfolioRecord(record));
  }
}
