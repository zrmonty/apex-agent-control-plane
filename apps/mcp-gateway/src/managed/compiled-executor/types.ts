import type { ClockSnapshot } from "../../telemetry/clock.js";
import type { PortfolioPublicView } from "../../filtering.js";
import type { CallPreparationOptions } from "../call-preparation-types.js";
import type { OwnedCallCoordinator } from "../call-owner.js";
import type { CallObservation, CallStageObservation } from "../call-observation.js";
import type { ManagedEvidenceClient, EvidenceReceipt } from "../evidence/client.js";
import type { CallEvidence } from "../evidence/types.js";

export type ExecutorOptions = Readonly<{ preparation: CallPreparationOptions;
  calls: Pick<OwnedCallCoordinator, "start">; evidence: Pick<ManagedEvidenceClient, "start"> }>;
export type SafeToolResult = Readonly<{ isError: false; structuredContent: PortfolioPublicView;
  content: readonly Readonly<{ type: "text"; text: string }>[] }>;
export type ExecutorState = "pending" | "succeeded" | "denied" | "requires_approval" | "failed" | "cancelled";
export type ExecutorObservation = Readonly<{ state: ExecutorState; callId?: string; traceId?: string; spanId?: string;
  admissionEventId?: string; completionEventId?: string; evidenceState: "not_started" | "pending" | "admitted" | "failed";
  rawClosed: boolean; evidenceClosed: boolean; closed: boolean; closedAtMonotonicNs?: bigint }>;
/** Metadata only, for a later actual response finish/abort owner. Not evidence
 * that a response was written, a remote reservation released, or cleanup ended. */
export type CompletionContext = Readonly<{ admission: CallEvidence; admissionEventHash: string;
  receipt?: EvidenceReceipt; evidence?: CallStageObservation; raw?: CallObservation;
  closedAtMonotonicNs?: bigint }>;
export type CompiledExecution = Readonly<{ result: Promise<SafeToolResult>; closed: Promise<void>; cancel(): void;
  observation(): ExecutorObservation; completion(): CompletionContext | undefined }>;
export type StageInterval = Readonly<{ name: "output.validation" | "output.filtering";
  started: ClockSnapshot; ended: ClockSnapshot; status: "ok" | "error" }>;
export const refused = () => new Error("compiled managed execution refused safely");
