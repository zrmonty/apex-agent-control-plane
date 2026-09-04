import { z } from "zod";

const portfolioId = z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/);
const asOf = z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional();
const MAX_RUST_IDENTIFIER_LENGTH = 256;
const MAX_METADATA_FIELDS = 64;
const MAX_FIELD_PATH_BYTES = 4_096;
const MAX_EVENT_BYTES = 4_096;
const RUST_IDENTIFIER_PATTERN = /^[A-Za-z0-9._:-]+$/;
const LOWERCASE_UUID_V7_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const textEncoder = new TextEncoder();

function isRustIdentifier(value: string): boolean {
  return (
    value.length <= MAX_RUST_IDENTIFIER_LENGTH &&
    !value.includes("..") &&
    RUST_IDENTIFIER_PATTERN.test(value)
  );
}

function isRustCallerPrincipal(value: string): boolean {
  if (value.length > MAX_RUST_IDENTIFIER_LENGTH || !/^[\x00-\x7f]+$/.test(value)) {
    return false;
  }

  if (isRustIdentifier(value)) {
    return true;
  }

  const path = value.startsWith("spiffe://") ? value.slice("spiffe://".length) : "";
  return path.length > 0 && path.split("/").every(isRustIdentifier);
}

function aggregateBytesWithinLimit(values: readonly string[]): boolean {
  let bytes = 0;

  for (const value of values) {
    bytes += textEncoder.encode(value).length;
    if (bytes > MAX_FIELD_PATH_BYTES) {
      return false;
    }
  }

  return true;
}

function jsonSizeWithinLimit(value: unknown, limit: number): boolean {
  try {
    const serialized = JSON.stringify(value);
    return serialized !== undefined && textEncoder.encode(serialized).length <= limit;
  } catch {
    return false;
  }
}

const RustIdentifierSchema = z
  .string()
  .min(1)
  .max(MAX_RUST_IDENTIFIER_LENGTH)
  .regex(RUST_IDENTIFIER_PATTERN)
  .refine((value) => !value.includes(".."));

export const CallerPrincipalSchema = z.string().refine(isRustCallerPrincipal);

const fieldPathsSchema = z
  .array(RustIdentifierSchema)
  .max(MAX_METADATA_FIELDS)
  .refine(aggregateBytesWithinLimit);

const rustU64Schema = z.number().int().nonnegative().safe();
const rustU32Schema = z.number().int().nonnegative().max(0xffff_ffff);

function isValidUtcCalendarDate(value: string): boolean {
  const [yearText, monthText, dayText] = value.split("-");
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const date = new Date(Date.UTC(year, month - 1, day));

  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
}

export const PortfolioReadInputSchema = z
  .object({ portfolioId, asOf })
  .strict()
  .superRefine((value, context) => {
    if (value.asOf !== undefined && !isValidUtcCalendarDate(value.asOf)) {
      context.addIssue({
        code: "custom",
        message: "Invalid calendar date",
        path: ["asOf"],
      });
    }
  });

export type PortfolioReadInput = z.infer<typeof PortfolioReadInputSchema>;

export function parsePortfolioReadInput(value: unknown): PortfolioReadInput {
  return PortfolioReadInputSchema.parse(value);
}

const scopeSchema = z
  .object({
    workspaceId: RustIdentifierSchema,
    namespaceId: RustIdentifierSchema,
  })
  .strict();

export const AuthorizationDecisionSchema = z
  .object({
    outcome: z.enum(["allowed", "denied", "requires_approval"]),
    policyId: RustIdentifierSchema,
    reasonCode: RustIdentifierSchema,
    fieldRestrictions: fieldPathsSchema,
  })
  .strict()
  .refine(
    (decision) =>
      decision.outcome === "allowed" || decision.fieldRestrictions.length === 0,
  );

export const PolicySnapshotSchema = z
  .object({
    scope: scopeSchema,
    policyId: RustIdentifierSchema,
    revision: rustU64Schema,
  })
  .strict();

export const EventReceiptSchema = z
  .object({
    eventId: z.string().regex(LOWERCASE_UUID_V7_PATTERN),
  })
  .strict();

export const ToolExecutionEventSchema = z
  .object({
    caller: z
      .object({
        principal: CallerPrincipalSchema,
        agentId: RustIdentifierSchema,
      })
      .strict(),
    scope: scopeSchema,
    tool: z.literal("portfolio.read"),
    action: z.literal("read"),
    resource: RustIdentifierSchema,
    backend: RustIdentifierSchema,
    status: z.enum(["succeeded", "denied", "failed"]),
    latencyMs: rustU64Schema,
    retryCount: rustU32Schema,
    sizes: z
      .object({
        inputBytes: rustU64Schema,
        sourceBytes: rustU64Schema,
        filteredBytes: rustU64Schema,
        outputBytes: rustU64Schema,
      })
      .strict(),
    filtering: z
      .object({ removedFields: fieldPathsSchema })
      .strict(),
    policy: AuthorizationDecisionSchema,
    trace: z
      .object({
        traceId: RustIdentifierSchema,
        spanId: RustIdentifierSchema,
      })
      .strict(),
  })
  .strict()
  .refine((event) => jsonSizeWithinLimit(event, MAX_EVENT_BYTES));
