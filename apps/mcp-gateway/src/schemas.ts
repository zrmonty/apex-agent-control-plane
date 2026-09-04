import { z } from "zod";

const portfolioId = z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/);
const asOf = z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional();

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
    workspaceId: z.string().min(1),
    namespaceId: z.string().min(1),
  })
  .strict();

export const AuthorizationDecisionSchema = z
  .object({
    outcome: z.enum(["allowed", "denied", "requires_approval"]),
    policyId: z.string().min(1),
    reasonCode: z.string().min(1),
    fieldRestrictions: z.array(z.string()),
  })
  .strict();

export const PolicySnapshotSchema = z
  .object({
    scope: scopeSchema,
    policyId: z.string().min(1),
    revision: z.number().int().nonnegative(),
    tool: z.literal("portfolio.read"),
    action: z.literal("read"),
    classification: z.literal("confidential"),
  })
  .strict();

export const ToolExecutionEventSchema = z
  .object({
    caller: z
      .object({
        principal: z.string().min(1),
        agentId: z.string().min(1),
      })
      .strict(),
    scope: scopeSchema,
    tool: z.literal("portfolio.read"),
    action: z.literal("read"),
    backend: z.string().min(1),
    status: z.enum(["succeeded", "denied", "failed"]),
    latencyMs: z.number().finite().nonnegative(),
    retryCount: z.number().int().nonnegative(),
    sizes: z
      .object({
        inputBytes: z.number().int().nonnegative(),
        sourceBytes: z.number().int().nonnegative(),
        filteredBytes: z.number().int().nonnegative(),
        outputBytes: z.number().int().nonnegative(),
      })
      .strict(),
    filtering: z
      .object({ removedFields: z.array(z.string()) })
      .strict(),
    policy: z
      .object({
        outcome: z.enum(["allowed", "denied", "requires_approval"]),
        policyId: z.string().min(1),
        reasonCode: z.string().min(1),
        revision: z.number().int().nonnegative(),
      })
      .strict(),
    trace: z
      .object({
        traceId: z.string().min(1),
        spanId: z.string().min(1),
      })
      .strict(),
  })
  .strict();
