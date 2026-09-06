// Pure synthetic evidence, not authenticated deployment or durability authority.
import type { CallEvidence } from "./types.js";
import { metadata, request } from "../authority/business-testing.js";
export function example(duration = 7n): CallEvidence {
  const submitted = request(); submitted.trace!.traceId = "1".repeat(32); submitted.trace!.spanId = "2".repeat(16);
  const started = { monotonicNs: 1000n, unixUs: 9_007_199_254_740_993n, resolutionNs: 1000n, uncertaintyUs: 2n, source: "test-clock" };
  return { phase: "admission", eventId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e10", linkedEventId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e11",
    request: submitted, decision: { outcome: "denied", policyId: metadata.policyId, policyRevision: 9_007_199_254_740_993n,
      reasonCode: "policy.denied", fieldRestrictions: [] }, status: "denied", started,
    observed: { ...started, monotonicNs: started.monotonicNs + duration * 1000n, unixUs: started.unixUs + duration },
    stages: [{ name: "authorization", spanId: "3".repeat(16), parentSpanId: submitted.trace!.spanId,
      started, durationNs: duration * 1000n, status: "ok" }], inputBytes: 21, sourceBytes: 0, filteredBytes: 0, outputBytes: 0, removedFields: [] };
}
