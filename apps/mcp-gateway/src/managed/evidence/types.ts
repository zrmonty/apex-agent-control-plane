import type { ManagedCallAuthorizationRequest } from "@apex/contracts";
import type { ClockSnapshot } from "../../telemetry/clock.js";
import type { BusinessDecision } from "../authority/business-types.js";
import type { CallOwnerOptions } from "../call-owner.js";
export type EvidenceProfile = Pick<CallOwnerOptions, "binding" | "policyId" | "evidenceAgentId" | "dataClassification">;
export type MeasuredStage = Readonly<{ name: string; spanId: string; parentSpanId: string;
  started: ClockSnapshot; durationNs?: bigint; status: "ok" | "error" | "missing" }>;
export type CallEvidence = Readonly<{
  phase: "admission" | "completion"; eventId: string; linkedEventId: string;
  request: ManagedCallAuthorizationRequest; decision: BusinessDecision; status: "succeeded" | "denied" | "failed";
  started: ClockSnapshot; observed: ClockSnapshot; stages: readonly MeasuredStage[];
  inputBytes: number; sourceBytes: number; filteredBytes: number; outputBytes: number; removedFields: readonly string[];
}>;
export type PreparedEvidence = Readonly<{ eventId: string; eventHash: string }>;
