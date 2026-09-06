import type { InboundIdentity } from "../auth.js";
import type { ClockSnapshot } from "../../telemetry/clock.js";
import type { CompiledCallPreparer, PreparedManagedCall } from "../call-preparation.js";
import type { ManagedEvidenceBuilder } from "../evidence/builder.js";
import type { OwnedCall } from "../call-owner.js";
import type { BusinessDecision, BusinessExchange } from "../authority/business-types.js";
import type { EvidenceReceipt } from "../evidence/client.js";
import type { CallEvidence } from "../evidence/types.js";
import { copyBusinessDecision, type CallObservation, type CallStageObservation } from "../call-observation.js";
import { consistent } from "../call-preparation/timing.js";
import { record } from "../call-preparation/boundary.js";
import { assertDataTree, freezeTree } from "../runtime-config/boundary.js";
import { createUuidV7 } from "../../live/uuid.js";
import { captureEnvelope, structuredPortfolio, safeOutput } from "./output.js";
import { measuredStages } from "./evidence.js";
import { refused, type ExecutorOptions, type CompiledExecution, type CompletionContext,
  type ExecutorObservation, type SafeToolResult, type StageInterval, type ExecutorState } from "./types.js";

export class ExecutionJob {
  readonly handle: CompiledExecution;
  private prepared?: PreparedManagedCall;
  private raw?: OwnedCall;
  private wire?: BusinessExchange<EvidenceReceipt>;
  private rawObservation?: CallObservation;
  private context?: CompletionContext;
  private evidenceStage?: CallStageObservation;
  private evidenceState: ExecutorObservation["evidenceState"] = "not_started";
  private state: ExecutorState = "pending";
  private rawClosed = true;
  private evidenceClosed = true;
  private workDone = false;
  private closed = false;
  private closedAt?: bigint;
  private cancelled = false;
  private settled = false;
  private rawCancelled = false;
  private wireCancelled = false;
  private timer?: ReturnType<typeof setTimeout>;
  private last?: ClockSnapshot;
  private resolve!: (value: SafeToolResult) => void;
  private reject!: (error: Error) => void;
  private drain!: () => void;

  constructor(private readonly options: ExecutorOptions, private readonly preparer: CompiledCallPreparer,
    private readonly builder: ManagedEvidenceBuilder, private readonly now: () => ClockSnapshot,
    private readonly stopped: () => boolean, private readonly release: () => void) {
    const result = new Promise<SafeToolResult>((yes, no) => { this.resolve = yes; this.reject = no; });
    void result.catch(() => {}); // Synchronous close/reentry before caller receives the job.
    this.handle = Object.freeze({ result, closed: new Promise<void>(done => { this.drain = done; }),
      cancel: () => this.cancel(), observation: () => this.observation(), completion: () => this.completion() });
  }
  start(identity: InboundIdentity, alias: string, input: unknown, original: ClockSnapshot, deadline: bigint): void {
    try {
      this.prepared = this.preparer.prepare(identity, alias, input, original, deadline);
      this.check(); this.arm();
      // Return handle before external I/O. Slot remains held through this dispatch.
      queueMicrotask(() => { void this.run().catch(() => { this.fail(); this.cancelRaw(); this.cancelWire(); }).finally(() => {
        this.workDone = true; clearTimeout(this.timer); this.finish();
      }); });
    } catch { this.fail(); this.workDone = true; this.finish(); }
  }
  cancel(): void {
    this.cancelled = true;
    if (!this.settled) { this.state = "cancelled"; this.fail(); }
    this.cancelRaw(); this.cancelWire(); clearTimeout(this.timer);
  }
  private fail(): void {
    if (!this.settled) { this.settled = true; if (this.state === "pending") this.state = "failed"; this.reject(refused()); }
  }
  private sample(): ClockSnapshot {
    const at = this.now();
    consistent(this.prepared!.originalSnapshot, at); if (this.last) consistent(this.last, at); this.last = at; return at;
  }
  private observe(): bigint | undefined { try { return this.sample().monotonicNs; } catch { return undefined; } }
  private check(): ClockSnapshot {
    const at = this.sample();
    if (this.cancelled || this.stopped() || at.monotonicNs >= this.prepared!.deadlineMonotonicNs) throw refused(); return at;
  }
  private arm(): void {
    const remaining = this.prepared!.deadlineMonotonicNs - this.check().monotonicNs;
    this.timer = setTimeout(() => {
      try { this.check(); this.arm(); } catch { this.cancel(); }
    }, Number((remaining + 999999n) / 1000000n));
  }
  private copyObservation(): void {
    if (!this.raw) return;
    try {
      const value = this.raw.observation(); assertDataTree(value, true);
      if (value.callId !== this.prepared!.trace.callId || value.traceId !== this.prepared!.trace.traceId ||
        value.spanId !== this.prepared!.trace.spanId || value.startedAtMonotonicNs !== this.prepared!.startedAtMonotonicNs) throw refused();
      this.rawObservation = freezeTree(structuredClone(value));
    } catch { this.fail(); }
  }
  private async run(): Promise<void> {
    const prepared = this.prepared!;
    this.check();
    this.raw = this.options.calls.start(prepared);
    this.rawClosed = false;
    let decision: BusinessDecision | undefined, envelope: Record<string, unknown> | undefined;
    let rawFailed = false;
    // Snapshot raw data before any executor clock/observation callback.
    const captured = this.raw.result.then(value => {
      record(value, ["decision", "output"]); decision = copyBusinessDecision(value.decision);
      if (decision.outcome === "allowed") envelope = captureEnvelope(value.output);
    });
    void captured.catch(() => {});
    void this.raw.closed.then(() => {
      this.copyObservation(); this.rawClosed = true; this.finish();
    }, () => this.cancel());
    if (this.cancelled || this.stopped()) this.cancelRaw();
    try { await captured; } catch { rawFailed = true; }
    this.copyObservation();
    decision ??= this.rawObservation?.decision;
    // A cancellation can reject result before authorization settles. Preserve
    // a subsequently known decision, without treating unknown as denied.
    if (!decision) {
      this.fail(); await this.raw.closed; this.copyObservation(); decision = this.rawObservation?.decision;
    }
    if (!decision) { this.fail(); return; }
    decision = copyBusinessDecision(decision);
    const local: StageInterval[] = [];
    let output: ReturnType<typeof safeOutput> | undefined, sourceBytes = 0;
    if (!rawFailed && decision.outcome === "allowed" && !this.cancelled && !this.stopped()) {
      let start: ClockSnapshot | undefined;
      try {
        start = this.check(); const portfolio = structuredPortfolio(envelope!, prepared.input.portfolioId);
        sourceBytes = Buffer.byteLength(JSON.stringify(portfolio));
        const validated = this.check(); local.push({ name: "output.validation", started: start, ended: validated, status: "ok" });
        start = validated; output = safeOutput(portfolio, decision);
        const filtered = this.check(); local.push({ name: "output.filtering", started: start, ended: filtered, status: "ok" });
      } catch {
        output = undefined;
        if (start) { const end = this.sample(); local.push({ name: local.length ? "output.filtering" : "output.validation",
          started: start, ended: end, status: "error" }); }
      }
    }
    const status = decision.outcome !== "allowed" ? "denied" : output && !this.cancelled && !this.stopped() ? "succeeded" : "failed";
    if (!this.settled && status !== "succeeded") this.state = decision.outcome === "allowed" ? "failed" : decision.outcome;
    const observed = this.sample(), eventId = createUuidV7(), linkedEventId = createUuidV7();
    if (eventId === linkedEventId) throw refused();
    const admission: CallEvidence = freezeTree({ phase: "admission", eventId, linkedEventId, request: prepared.request, decision, status,
      started: prepared.originalSnapshot, observed,
      stages: measuredStages(prepared.originalSnapshot, observed, prepared.trace.spanId, this.rawObservation, local),
      inputBytes: Buffer.byteLength(JSON.stringify(prepared.input)), sourceBytes,
      filteredBytes: output?.filteredBytes ?? 0, outputBytes: status === "succeeded" ? output!.outputBytes : 0,
      removedFields: output?.removedFields ?? [] });
    const evidence = this.builder.prepare(admission);
    this.context = Object.freeze({ admission, admissionEventHash: evidence.eventHash });
    try {
      const attempt = this.check();
      this.evidenceStage = Object.freeze({ state: "pending", startedAtMonotonicNs: attempt.monotonicNs });
      this.evidenceState = "pending";
      this.wire = this.options.evidence.start(evidence, attempt.monotonicNs, prepared.deadlineMonotonicNs);
      this.evidenceClosed = false;
      const receiptResult = this.wire.result.then(value => {
        assertDataTree(value, false); record(value, ["eventId", "eventHash", "duplicate"]);
        if (value.eventId !== evidence.eventId || value.eventHash !== evidence.eventHash || typeof value.duplicate !== "boolean") throw refused();
        return Object.freeze({ ...value });
      });
      void receiptResult.catch(() => {});
      void this.wire.closed.then(() => {
        this.evidenceClosed = true;
        this.evidenceStage = Object.freeze({ ...this.evidenceStage!, ...this.time("closedAtMonotonicNs", this.observe()) }); this.finish();
      }, () => this.cancel());
      if (this.cancelled || this.stopped()) this.cancelWire();
      const receipt = await receiptResult, accepted = this.check();
      this.evidenceStage = Object.freeze({ ...this.evidenceStage!, state: "ok", resultAtMonotonicNs: accepted.monotonicNs });
      this.evidenceState = "admitted"; this.context = Object.freeze({ ...this.context, receipt });
      if (status === "succeeded" && output && !this.settled) {
        this.check(); this.settled = true; this.state = "succeeded"; this.resolve(output.result);
      } else this.fail();
    } catch {
      this.evidenceState = "failed";
      if (this.evidenceStage) this.evidenceStage = Object.freeze({ ...this.evidenceStage, state: "error",
        ...this.time("resultAtMonotonicNs", this.observe()) });
      this.fail();
    } finally { this.cancelWire(); this.cancelRaw(); }
  }
  private cancelRaw(): void {
    if (this.raw && !this.rawCancelled) { this.rawCancelled = true; try { this.raw.cancel(); } catch { /* Still owned. */ } }
  }
  private cancelWire(): void {
    if (this.wire && !this.wireCancelled) { this.wireCancelled = true; try { this.wire.cancel(); } catch { /* Still owned. */ } }
  }
  private finish(): void {
    if (this.closed || !this.workDone || !this.rawClosed || !this.evidenceClosed) return;
    this.closedAt = this.prepared ? this.observe() : undefined;
    this.closed = true;
    this.raw = undefined; this.wire = undefined; // Drop settled promises retaining unfiltered source/transport data.
    this.release(); this.drain();
  }
  private observation(): ExecutorObservation {
    return Object.freeze({ state: this.state, ...(this.prepared ? { callId: this.prepared.trace.callId,
      traceId: this.prepared.trace.traceId, spanId: this.prepared.trace.spanId } : {}),
      ...(this.context ? { admissionEventId: this.context.admission.eventId, completionEventId: this.context.admission.linkedEventId } : {}),
      evidenceState: this.evidenceState, rawClosed: this.rawClosed, evidenceClosed: this.evidenceClosed, closed: this.closed,
      ...this.time("closedAtMonotonicNs", this.closedAt) });
  }
  private completion(): CompletionContext | undefined {
    if (!this.context) return undefined;
    return Object.freeze({ ...this.context, ...(this.rawObservation ? { raw: this.rawObservation } : {}),
      ...(this.evidenceStage ? { evidence: this.evidenceStage } : {}), ...this.time("closedAtMonotonicNs", this.closedAt) });
  }
  private time(key: string, value?: bigint): Record<string, bigint> { return value === undefined ? {} : { [key]: value }; }
}
