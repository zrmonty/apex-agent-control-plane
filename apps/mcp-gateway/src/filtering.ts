import type { AuthorizationDecision } from "./contracts.js";
import { GatewayError } from "./contracts.js";

export type RawPortfolioRecord = {
  readonly portfolio_id: string;
  readonly as_of: string;
  readonly base_currency: string;
  readonly total_value: number;
  readonly client: {
    readonly display_name: string;
    readonly account_number: string;
    readonly tax_id: string;
  };
  readonly positions: ReadonlyArray<{
    readonly symbol: string;
    readonly quantity: number;
    readonly market_value: number;
    readonly cost_basis: number;
  }>;
};

export type PortfolioPublicView = {
  readonly portfolioId: string;
  readonly asOf: string;
  readonly baseCurrency: string;
  readonly totalValue: number;
  readonly client: { readonly displayName: string };
  readonly positions: ReadonlyArray<{
    readonly symbol: string;
    readonly quantity: number;
    readonly marketValue: number;
  }>;
};

export type FilterResult = {
  readonly view: PortfolioPublicView;
  readonly removedFields: readonly string[];
  readonly sourceBytes: number;
  readonly filteredBytes: number;
};

function requireObject(
  value: unknown,
  field: string,
): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new GatewayError("FILTERING_FAILED", `missing required field ${field}`);
  }

  return value as Readonly<Record<string, unknown>>;
}

function requireArray(value: unknown, field: string): readonly unknown[] {
  if (!Array.isArray(value)) {
    throw new GatewayError("FILTERING_FAILED", `missing required field ${field}`);
  }

  return value;
}

function requireNonEmptyString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new GatewayError("FILTERING_FAILED", `missing required field ${field}`);
  }

  return value;
}

function requireFiniteNumber(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new GatewayError("FILTERING_FAILED", `invalid required field ${field}`);
  }

  return value;
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

export function filterPortfolioRecord(
  raw: RawPortfolioRecord,
  decision: AuthorizationDecision,
): FilterResult {
  const restrictions = new Set(decision.fieldRestrictions);
  const removedFields: string[] = [];
  const rawObject = requireObject(raw, "portfolio");
  const client = requireObject(rawObject.client, "client");
  const positions = requireArray(rawObject.positions, "positions");

  const portfolioId = requireNonEmptyString(rawObject.portfolio_id, "portfolio_id");
  const asOf = requireNonEmptyString(rawObject.as_of, "as_of");
  const baseCurrency = requireNonEmptyString(rawObject.base_currency, "base_currency");
  const totalValue = requireFiniteNumber(rawObject.total_value, "total_value");
  const displayName = requireNonEmptyString(client.display_name, "client.display_name");
  requireNonEmptyString(client.account_number, "client.account_number");
  requireNonEmptyString(client.tax_id, "client.tax_id");

  const publicPositions = positions.map((position, index) => {
    const validatedPosition = requireObject(position, `positions[${index}]`);
    const symbol = requireNonEmptyString(
      validatedPosition.symbol,
      `positions[${index}].symbol`,
    );
    const quantity = requireFiniteNumber(
      validatedPosition.quantity,
      `positions[${index}].quantity`,
    );
    const marketValue = requireFiniteNumber(
      validatedPosition.market_value,
      `positions[${index}].market_value`,
    );
    requireFiniteNumber(validatedPosition.cost_basis, "positions.cost_basis");

    return {
      symbol,
      quantity,
      marketValue,
    };
  });

  const view: PortfolioPublicView = {
    portfolioId,
    asOf,
    baseCurrency,
    totalValue,
    client: {
      displayName,
    },
    positions: publicPositions,
  };

  for (const field of decision.fieldRestrictions) {
    if (!restrictions.has(field)) {
      continue;
    }

    switch (field) {
      case "client.account_number":
      case "client.tax_id":
      case "positions.cost_basis":
        removedFields.push(field);
        break;
      default:
        throw new GatewayError("FILTERING_FAILED", "unsupported field restriction");
    }
  }

  const sourceBytes = Buffer.byteLength(JSON.stringify(raw), "utf8");
  const frozenView = deepFreeze(view);
  const filteredBytes = Buffer.byteLength(JSON.stringify(frozenView), "utf8");

  return {
    view: frozenView,
    removedFields,
    sourceBytes,
    filteredBytes,
  };
}
