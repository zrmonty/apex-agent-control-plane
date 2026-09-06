import type { ManagedCallAuthorizationRequest } from "@apex/contracts";
import type { BusinessDecision } from "./authority/business-types.js";
import { businessIdentifier } from "./authority/business-codec.js";
import { assertDataTree, freezeTree } from "./runtime-config/boundary.js";
import { types } from "node:util";

export type CallStageName = "authorization" | "upstream" | "cleanup";
export type CallStageState = "pending" | "ok" | "error" | "cancelled";
export type CallStageObservation = Readonly<{
  state: CallStageState;
  startedAtMonotonicNs?: bigint;
  resultAtMonotonicNs?: bigint;
  closedAtMonotonicNs?: bigint;
}>;
/** Local owner boundaries only; neither durable evidence nor remote timing. */
export type CallObservation = Readonly<{
  callId: string; traceId: string; spanId: string; startedAtMonotonicNs: bigint;
  decision?: BusinessDecision;
  authorization?: CallStageObservation; upstream?: CallStageObservation; cleanup?: CallStageObservation;
  /** Final supplied beforeWrite gate passed; not remote receipt or execution time. */
  dispatchedAtMonotonicNs?: bigint;
  closedAtMonotonicNs?: bigint;
}>;
type MutableStage = { -readonly [K in keyof CallStageObservation]: CallStageObservation[K] };

/** Internal bounded data recorder. No clock, dependency, observer callback, or I/O capability. */
export class CallObservationRecord {
  private readonly stages: Partial<Record<CallStageName, MutableStage>> = {};
  private readonly results = new Set<CallStageName>();
  private readonly closures = new Set<CallStageName>();
  private decision?: BusinessDecision;
  private dispatchedAtMonotonicNs?: bigint;
  private closedAtMonotonicNs?: bigint;
  constructor(private readonly request: ManagedCallAuthorizationRequest, private readonly started: bigint) {}
  begin(name: CallStageName, time?: bigint): void {
    if (!this.stages[name]) this.stages[name] = { state: "pending", ...this.time("startedAtMonotonicNs", time) };
  }
  startTime(name: CallStageName, time?: bigint): void { Object.assign(this.stages[name]!, this.time("startedAtMonotonicNs", time)); }
  result(name: CallStageName, state: "ok" | "error", time?: bigint): void {
    const stage = this.stages[name]; if (!stage || this.results.has(name)) return;
    this.results.add(name);
    if (stage.state !== "cancelled") stage.state = state;
    Object.assign(stage, this.time("resultAtMonotonicNs", time));
  }
  physicalClose(name: CallStageName, time?: bigint): void {
    const stage = this.stages[name]; if (!stage || this.closures.has(name)) return;
    this.closures.add(name); Object.assign(stage, this.time("closedAtMonotonicNs", time));
  }
  cancel(name?: CallStageName): void {
    for (const key of name ? [name] : ["authorization", "upstream", "cleanup"] as const)
      if (this.stages[key]?.state === "pending") this.stages[key]!.state = "cancelled";
  }
  known(value: BusinessDecision): void { this.decision = value; }
  dispatch(time: bigint): void { this.dispatchedAtMonotonicNs ??= time; }
  finish(time?: bigint): void { if (time !== undefined && time >= this.started) this.closedAtMonotonicNs = time; }
  snapshot(): CallObservation {
    return freezeTree(structuredClone({ callId: this.request.callId,
      traceId: this.request.trace!.traceId, spanId: this.request.trace!.spanId, startedAtMonotonicNs: this.started,
      ...(this.decision ? { decision: this.decision } : {}), ...this.stages,
      ...this.time("dispatchedAtMonotonicNs", this.dispatchedAtMonotonicNs),
      ...this.time("closedAtMonotonicNs", this.closedAtMonotonicNs) }));
  }
  private time(key: string, value?: bigint): Record<string, bigint> {
    return value !== undefined && value >= this.started ? { [key]: value } : {};
  }
}

/** Copy only the bounded typed metadata, before clocks or other dependencies can re-enter. */
export function copyBusinessDecision(value: BusinessDecision): BusinessDecision {
  const metadata = { policyId: field(value, "policyId"), policyRevision: field(value, "policyRevision"),
    reasonCode: field(value, "reasonCode"), fieldRestrictions: field(value, "fieldRestrictions") };
  assertDataTree(metadata, true);
  if (!Array.isArray(metadata.fieldRestrictions) || metadata.fieldRestrictions.length > 128 ||
    typeof metadata.policyRevision !== "bigint" || metadata.policyRevision <= 0n) throw new Error("managed call refused safely");
  const fieldRestrictions = metadata.fieldRestrictions.map(businessIdentifier);
  if (fieldRestrictions.reduce((bytes, field) => bytes + Buffer.byteLength(field), 0) > 8192) throw new Error("managed call refused safely");
  const common = { policyId: businessIdentifier(metadata.policyId), policyRevision: metadata.policyRevision,
    reasonCode: businessIdentifier(metadata.reasonCode), fieldRestrictions }, outcome = field(value, "outcome");
  if (outcome === "denied" || outcome === "requires_approval") return freezeTree({ ...common, outcome });
  if (outcome !== "allowed") throw new Error("managed call refused safely");
  const allowed = value as Extract<BusinessDecision, { outcome: "allowed" }>;
  const wire = { ...common, outcome, admissionId: field(allowed, "admissionId"), epoch: field(allowed, "epoch"),
    expiresAtUnixUs: field(allowed, "expiresAtUnixUs"), validForUs: field(allowed, "validForUs"),
    submittedRequest: field(allowed, "submittedRequest") };
  assertDataTree(wire, true);
  // This is a locally computed deadline, not a generated uint64 wire field.
  const startDeadlineMonotonicNs = field(allowed, "startDeadlineMonotonicNs");
  if (typeof startDeadlineMonotonicNs !== "bigint" || startDeadlineMonotonicNs < 0n) throw new Error("managed call refused safely");
  return freezeTree({ ...structuredClone(wire), startDeadlineMonotonicNs });
}

function field<T extends object, K extends keyof T>(value: T, key: K): T[K] {
  if (!value || typeof value !== "object" || types.isProxy(value)) throw new Error("managed call refused safely");
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !("value" in descriptor)) throw new Error("managed call refused safely");
  return descriptor.value as T[K];
}
