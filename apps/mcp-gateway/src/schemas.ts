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
