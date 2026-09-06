import type { InboundIdentity } from "./auth.js";
import type { ClockSnapshot } from "../telemetry/clock.js";
import { CompiledCallPreparer } from "./call-preparation.js";
import { compile } from "./call-preparation/compile.js";
import { snapshot, consistent } from "./call-preparation/timing.js";
import { ManagedEvidenceBuilder } from "./evidence/builder.js";
import { ExecutionJob } from "./compiled-executor/job.js";
import { refused, type ExecutorOptions, type CompiledExecution } from "./compiled-executor/types.js";
export type { ExecutorOptions, CompiledExecution, CompletionContext, ExecutorObservation, SafeToolResult } from "./compiled-executor/types.js";

/** Trusted composition only. Does not own or close shared raw/channel roots. */
export class CompiledManagedExecutor {
  private readonly preparer: CompiledCallPreparer;
  private readonly builder: ManagedEvidenceBuilder;
  private readonly options: ExecutorOptions;
  private readonly now: () => ClockSnapshot;
  private readonly jobs = new Set<ExecutionJob>();
  private last?: ClockSnapshot;
  private stopped = false;
  private closing?: Promise<void>;
  constructor(options: ExecutorOptions) {
    try {
      const compiled = compile(options.preparation);
      if (options.preparation.config.spec!.authBindings.length || typeof options.calls?.start !== "function" ||
        typeof options.evidence?.start !== "function") throw refused();
      this.options = Object.freeze({ preparation: options.preparation,
        calls: { start: options.calls.start.bind(options.calls) }, evidence: { start: options.evidence.start.bind(options.evidence) } });
      this.now = compiled.now;
      this.preparer = new CompiledCallPreparer(options.preparation);
      this.builder = new ManagedEvidenceBuilder({ binding: compiled.binding, policyId: compiled.policyId,
        evidenceAgentId: compiled.evidenceAgentId, dataClassification: compiled.dataClassification });
    } catch { throw refused(); }
  }
  start(identity: InboundIdentity, alias: string, input: unknown, original: ClockSnapshot, deadline: bigint): CompiledExecution {
    if (this.stopped || this.jobs.size >= 128) throw refused();
    const job = new ExecutionJob(this.options, this.preparer, this.builder, () => this.sample(), () => this.stopped,
      () => this.jobs.delete(job));
    this.jobs.add(job); // Reserve before preparation's first trusted clock/reentry.
    job.start(identity, alias, input, original, deadline);
    return job.handle;
  }
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.stopped = true;
    this.closing = Promise.all([...this.jobs].map(job => job.handle.closed)).then(() => undefined);
    for (const job of this.jobs) job.cancel();
    return this.closing;
  }
  private sample(): ClockSnapshot {
    try {
      const at = snapshot(this.now()); if (this.last) consistent(this.last, at); this.last = at; return at;
    } catch { void this.close(); throw refused(); }
  }
}
