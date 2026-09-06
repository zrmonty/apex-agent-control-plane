import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { filterPortfolioRecord, type RawPortfolioRecord } from "../../filtering.js";
import type { BusinessDecision } from "../authority/business-types.js";
import { assertDataTree, freezeTree } from "../runtime-config/boundary.js";
import { record } from "../call-preparation/boundary.js";
import { refused, type SafeToolResult } from "./types.js";

/** No clock or trusted callback until the entire passive envelope is copied.
 * 256 KiB / 8193 nodes / 64 depth, tighter than the wire owner's 1 MiB bound. */
export function captureEnvelope(value: unknown): Record<string, unknown> {
  assertDataTree(value, false);
  record(value, ["content", "structuredContent", "isError", "_meta"]);
  return JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
}
export function structuredPortfolio(envelope: Record<string, unknown>, portfolioId: string): RawPortfolioRecord {
  CallToolResultSchema.parse(envelope);
  if (envelope.isError !== undefined && envelope.isError !== false) throw refused();
  const value = envelope.structuredContent;
  if (!value || typeof value !== "object" || Array.isArray(value) ||
    (value as Record<string, unknown>).portfolio_id !== portfolioId) throw refused();
  return value as RawPortfolioRecord;
}
export function safeOutput(raw: RawPortfolioRecord, decision: BusinessDecision) {
  const filtered = filterPortfolioRecord(raw, decision);
  const result: SafeToolResult = freezeTree({ isError: false, structuredContent: filtered.view,
    content: [{ type: "text" as const, text: JSON.stringify(filtered.view) }] });
  return { result, sourceBytes: filtered.sourceBytes, filteredBytes: filtered.filteredBytes,
    outputBytes: Buffer.byteLength(JSON.stringify(result)), removedFields: [...filtered.removedFields] };
}
