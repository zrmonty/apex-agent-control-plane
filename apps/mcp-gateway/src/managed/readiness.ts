import { create } from "@bufbuild/protobuf";
import { ReadinessReportSchema, ReadinessCheckSchema, ReadinessCheckStatus as Status, ReadinessReason as Reason,
  RuntimeConfigurationSchema, encodeJson, type RuntimeConfiguration, type ReadinessCheck, type ProxyStageTiming,
  type ReadinessReport, type RuntimeTarget } from "@apex/contracts";
import { GatewayError } from "../contracts.js";
import type { ClockSnapshot } from "../telemetry/clock.js";
import { parseRuntimeLaunchContext } from "./launch-context.js";
import { parseRuntimeConfiguration } from "./runtime-config.js";
import { assertDataTree, assertMessage, freezeTree } from "./runtime-config/boundary.js";
import { evidence, failed } from "./readiness/evidence.js";
import { clockSample, timing } from "./readiness/timing.js";
import { ReadinessReportCodec } from "./readiness/report-codec.js";
import { CHECK_IDS, type CheckId, type ProbeHandle, type ReadinessBinding, type ReadinessOptions,
  type ReadonlyReadinessReport, type ReadinessScheduler } from "./readiness/types.js";
export type { ReadinessBinding, ReadinessOptions, ProbeOwner, ProbeHandle, ProbeResult } from "./readiness/types.js";

type Operation = { handle?: ProbeHandle; cancelled: boolean; start: ClockSnapshot };
type Sweep = {
  deadline: bigint; next: number; pending: Map<CheckId, Operation>; checks: ReadinessCheck[];
  invalid?: Reason; stopTimer?: () => void; stopCleanup?: () => void; cleanupDeadline?: bigint;
  result: Promise<ReadonlyReadinessReport>; resolve(value: ReadonlyReadinessReport): void;
  cleanup: Promise<void>; cleaned(): void;
  stages: Map<CheckId, ProxyStageTiming>; expiries: Map<CheckId, bigint>; observed?: ClockSnapshot;
};
const scheduler: ReadinessScheduler = { after: (ms, callback) => {
  const timer = setTimeout(callback, ms); return () => clearTimeout(timer);
} };

/** Non-admitting component, never composed into startup in this slice. All
 * synchronous owner/clock/scheduler callbacks are trusted and must not block.
 * Completion means underlying I/O termination, NOT a timer-raced result.
 * The live owner must authenticate the complete immutable binding; hashes and
 * synthetic component probes establish no production dependency authority. */
export class ReadinessMonitor {
  private readonly binding: ReadinessBinding;
  private readonly codec: ReadinessReportCodec;
  private readonly options: ReadinessOptions;
  private readonly timers: ReadinessScheduler;
  private readonly deadlineMs: number;
  private readonly cleanupMs: number;
  private report: ReadonlyReadinessReport;
  private active?: Sweep;
  private lastStart?: bigint;
  private lastClock?: bigint;
  private validUntil?: bigint;
  private clockFailed = false;
  private lost = false;
  private closed = false;
  private fatal = false;

  constructor(options: ReadinessOptions) {
    try {
      if (!options.clock || typeof options.clock.now !== "function" || typeof options.isCurrent !== "function" ||
        typeof options.onFatal !== "function" || !Array.isArray(options.owners) || options.owners.length !== 9 ||
        new Set(options.owners.map(owner => owner.id)).size !== 9 ||
        options.owners.some(owner => !CHECK_IDS.includes(owner.id) || typeof owner.start !== "function")) throw new Error();
      this.options = { ...options, owners: CHECK_IDS.map(id => {
        const owner = options.owners.find(owner => owner.id === id)!;
        return Object.freeze({ id, start: owner.start.bind(owner) });
      }) };
      this.timers = options.scheduler ?? scheduler;
      if (typeof this.timers.after !== "function") throw new Error();
      this.deadlineMs = options.limits?.deadlineMs ?? 2000;
      this.cleanupMs = options.limits?.cleanupMs ?? 5000;
      for (const [value, ceiling] of [[this.deadlineMs, 2000], [this.cleanupMs, 5000]]) {
        if (!Number.isSafeInteger(value) || value < 1 || value > ceiling) throw new Error();
      }
      assertDataTree(options.configuration, true);
      assertMessage(RuntimeConfigurationSchema, options.configuration);
      const config = parseRuntimeConfiguration(encodeJson(RuntimeConfigurationSchema, options.configuration as RuntimeConfiguration));
      const launch = parseRuntimeLaunchContext(options.launchContext, config);
      this.binding = freezeTree({ config, launch });
      this.codec = new ReadinessReportCodec(this.binding);
      this.report = this.build(CHECK_IDS.map(id => create(ReadinessCheckSchema, { id, status: Status.PENDING, reason: Reason.UNAVAILABLE })));
    } catch { throw new GatewayError("INVALID_INPUT", "readiness configuration rejected safely"); }
  }

  checkStartup(): Promise<ReadonlyReadinessReport> {
    if (this.closed || this.fatal || this.clockFailed || !this.current()) return Promise.resolve(this.snapshot());
    if (this.active) return this.active.result;
    const now = this.sample();
    if (!now) return Promise.resolve(this.snapshot());
    // The initial clock callback may have started a nested sweep. Its pending
    // ownership takes precedence even if the outer sample observes elapsed cadence.
    const reentered = this.active as Sweep | undefined; // TS cannot track callback mutations.
    if (reentered) return reentered.result;
    if (this.lastStart !== undefined && now.monotonicNs - this.lastStart < 5000000000n) return Promise.resolve(this.snapshot());
    this.lastStart = now.monotonicNs;
    let resolve!: Sweep["resolve"], cleaned!: Sweep["cleaned"];
    const sweep: Sweep = { deadline: now.monotonicNs + BigInt(this.deadlineMs) * 1000000n, next: 0,
      pending: new Map(), checks: CHECK_IDS.map(id => create(ReadinessCheckSchema, { id, status: Status.PENDING, reason: Reason.UNAVAILABLE })),
      result: new Promise(done => { resolve = done; }), resolve: value => resolve(value),
      cleanup: new Promise(done => { cleaned = done; }), cleaned: () => cleaned(), stages: new Map(), expiries: new Map() };
    this.active = sweep;
    this.validUntil = undefined;
    this.report = this.build(sweep.checks, this.report.observedAtUnixUs);
    sweep.stopTimer = this.arm(sweep, this.deadlineMs, () => this.deadline(sweep));
    this.pump(sweep);
    return sweep.result;
  }

  /** Cached metadata only: no probe starts, cancellation, timestamp restamping
   * or cadence reset. Identity loss is latched; the active sweep observes it at
   * its next completion/deadline, or close cancels immediately. */
  snapshot(): ReadonlyReadinessReport {
    const current = this.closed || this.fatal ? false : this.current();
    const now = this.closed || this.fatal ? undefined : this.sample();
    const reason = this.closed ? Reason.SHUTTING_DOWN : this.fatal ? Reason.UNAVAILABLE : this.clockFailed ? Reason.INVALID :
      !current ? Reason.MISMATCH : this.report.ready && now && this.validUntil !== undefined && now.monotonicNs >= this.validUntil
        ? Reason.STALE : undefined;
    return reason === undefined ? this.report : this.invalidReport(reason);
  }

  /** Settles after actual termination OR the fatal hook requests process failure.
   * A fatal settlement is not a claim that unresponsive I/O closed gracefully. */
  close(): Promise<void> {
    this.closed = true; // Invalidate before any user cancellation callback.
    this.report = this.invalidReport(Reason.SHUTTING_DOWN);
    const sweep = this.active;
    if (!sweep) return Promise.resolve();
    this.abort(sweep, Reason.SHUTTING_DOWN);
    return sweep.cleanup;
  }

  private current(): boolean {
    if (this.lost) return false;
    try { if (this.options.isCurrent(this.binding) === true) return true; } catch { /* Static mismatch only. */ }
    this.lost = true;
    return false;
  }

  private sample(): ClockSnapshot | undefined {
    if (this.clockFailed) return undefined;
    try {
      const sample = clockSample(this.options.clock, this.lastClock);
      this.lastClock = sample.monotonicNs;
      return sample;
    } catch { this.clockFailed = true; return undefined; }
  }

  private pump(sweep: Sweep): void {
    if (sweep.invalid !== undefined || this.active !== sweep) return;
    while (sweep.pending.size < 4 && sweep.next < this.options.owners.length) {
      const start = this.guard(sweep);
      if (!start) return;
      const owner = this.options.owners[sweep.next++];
      // Reserve before entering a user start callback: it may reenter close().
      const operation: Operation = { cancelled: false, start };
      sweep.pending.set(owner.id, operation);
      let handle: ProbeHandle;
      try {
        handle = owner.start(this.binding);
      } catch {
        sweep.pending.delete(owner.id);
        if (sweep.invalid !== undefined) { if (!sweep.pending.size) this.release(sweep); return; }
        sweep.checks[owner.id - 1] = failed(owner.id, Reason.UNAVAILABLE);
        const end = this.guard(sweep);
        if (!end) return;
        sweep.observed = end;
        sweep.stages.set(owner.id, timing(owner.id, start, end, this.binding.launch.processInstanceId));
        continue;
      }
      try {
        operation.handle = handle;
        if (!handle || !(handle.completion instanceof Promise) || typeof handle.cancel !== "function") throw new Error();
        // Capture ownership once; a caller cannot replace cancellation later.
        operation.handle = { completion: handle.completion, cancel: handle.cancel.bind(handle) };
        void operation.handle.completion.then(value => this.complete(sweep, owner.id, value), () => this.complete(sweep, owner.id))
          .catch(() => this.abort(sweep, Reason.INVALID));
      } catch {
        // No trustworthy termination promise means no safe permit replacement.
        this.abort(sweep, Reason.INVALID);
        this.terminal(sweep);
        return;
      }
      if (sweep.invalid !== undefined) { this.cancel(operation); return; }
    }
    if (sweep.next === 9 && sweep.pending.size === 0) {
      const now = this.guard(sweep); // Immediately before publication, not the last awaited sample.
      if (!now) return;
      for (const [id, expiry] of sweep.expiries) if (expiry <= now.monotonicNs) sweep.checks[id - 1] = failed(id, Reason.STALE);
      const observed = sweep.observed!; // Every owner completed or synchronously failed with a real sample.
      this.validUntil = [...sweep.expiries.values()].reduce((earliest, expiry) => expiry < earliest ? expiry : earliest,
        observed.monotonicNs + 10000000000n);
      this.report = this.build(sweep.checks, observed.unixUs, CHECK_IDS.flatMap(id => sweep.stages.get(id) ?? []));
      sweep.resolve(this.report);
      this.release(sweep);
    }
  }

  private complete(sweep: Sweep, id: CheckId, value?: unknown): void {
    // A promise callback is the first evidence that the actual operation ended.
    // Until here, cancellation never releases its concurrency permit.
    const operation = sweep.pending.get(id)!;
    const sampled = this.sample();
    if (sweep.invalid !== undefined && sampled && sweep.cleanupDeadline !== undefined && sampled.monotonicNs >= sweep.cleanupDeadline) {
      this.cleanupDeadline(sweep); // A late completion cannot conceal an already-exceeded grace bound.
    }
    sweep.pending.delete(id);
    if (sweep.invalid !== undefined) {
      if (sweep.pending.size === 0) this.release(sweep);
      return;
    }
    const now = this.guard(sweep);
    if (!now) return;
    const result = value === undefined ? { check: failed(id, Reason.UNAVAILABLE), expiry: undefined } : evidence(value, id, now.monotonicNs);
    sweep.checks[id - 1] = result.check;
    if (result.expiry !== undefined) {
      const maximumAge = now.monotonicNs + 10000000000n;
      sweep.expiries.set(id, result.expiry < maximumAge ? result.expiry : maximumAge);
    }
    sweep.observed = now;
    sweep.stages.set(id, timing(id, operation.start, now, this.binding.launch.processInstanceId));
    this.pump(sweep);
  }

  private guardState(sweep: Sweep): boolean {
    if (sweep.invalid !== undefined) return false;
    const reason = this.closed ? Reason.SHUTTING_DOWN : this.fatal ? Reason.UNAVAILABLE : this.clockFailed ? Reason.INVALID :
      this.lost ? Reason.MISMATCH : this.active !== sweep ? Reason.CANCELLED : undefined;
    if (reason !== undefined) { this.abort(sweep, reason); return false; }
    return true;
  }

  private guard(sweep: Sweep): ClockSnapshot | undefined {
    if (!this.guardState(sweep)) return undefined;
    this.current();
    // Trusted callbacks can reenter close/other reads: their return values do
    // not restore sweep ownership. Recheck before sampling or authorizing work.
    if (!this.guardState(sweep)) return undefined;
    const now = this.sample();
    if (!this.guardState(sweep) || !now) return undefined;
    if (now.monotonicNs >= sweep.deadline) { this.abort(sweep, Reason.TIMEOUT); return undefined; }
    return now;
  }

  private deadline(sweep: Sweep): void {
    if (sweep.invalid !== undefined || this.active !== sweep) return;
    const now = this.guard(sweep);
    if (now) {
      const left = sweep.deadline - now.monotonicNs;
      sweep.stopTimer = this.arm(sweep, Number((left + 999999n) / 1000000n), () => this.deadline(sweep));
    }
  }

  private abort(sweep: Sweep, reason: Reason): void {
    if (sweep.invalid !== undefined) return;
    sweep.invalid = reason;
    sweep.stopTimer?.();
    this.report = this.invalidReport(reason);
    sweep.resolve(this.report); // Logical outcome is separate from actual cleanup.
    if (sweep.pending.size === 0) { this.release(sweep); return; }
    const sample = this.sample();
    sweep.cleanupDeadline = sample && sample.monotonicNs + BigInt(this.cleanupMs) * 1000000n;
    sweep.stopCleanup = this.arm(sweep, this.cleanupMs, () => this.cleanupDeadline(sweep));
    for (const operation of sweep.pending.values()) this.cancel(operation);
  }

  private cancel(operation: Operation): void {
    if (operation.cancelled || operation.handle === undefined) return;
    operation.cancelled = true;
    try { operation.handle.cancel(); } catch { /* Owner errors never enter reports/logs. */ }
  }

  private cleanupDeadline(sweep: Sweep): void {
    if (!sweep.pending.size || this.fatal) return;
    const now = this.sample();
    const left = now && sweep.cleanupDeadline !== undefined ? sweep.cleanupDeadline - now.monotonicNs : 0n;
    if (left > 0n) {
      sweep.stopCleanup = this.arm(sweep, Number((left + 999999n) / 1000000n), () => this.cleanupDeadline(sweep));
      return;
    }
    this.terminal(sweep);
  }

  private terminal(sweep: Sweep): void {
    if (this.fatal) return;
    this.fatal = true;
    for (const operation of sweep.pending.values()) this.cancel(operation);
    this.report = this.invalidReport(Reason.UNAVAILABLE);
    sweep.resolve(this.report);
    sweep.stopTimer?.(); sweep.stopCleanup?.(); sweep.cleaned();
    try { this.options.onFatal(); } catch { /* The terminal latch and bounded settlement remain. */ }
  }

  private arm(sweep: Sweep, ms: number, callback: () => void): () => void {
    const broken = () => { sweep.invalid ??= Reason.INVALID; this.terminal(sweep); };
    try {
      const cancel = this.timers.after(ms, () => { try { callback(); } catch { broken(); } });
      if (typeof cancel !== "function") throw new Error();
      return () => { try { cancel(); } catch { /* No raw scheduler diagnostics. */ } };
    } catch { broken(); return () => {}; }
  }

  private release(sweep: Sweep): void {
    sweep.stopTimer?.(); sweep.stopCleanup?.(); sweep.cleaned();
    if (this.active === sweep) this.active = undefined;
  }

  private invalidReport(reason: Reason): ReadonlyReadinessReport {
    const report = create(ReadinessReportSchema, { ...this.report as ReadinessReport, live: !this.closed && !this.fatal && !this.clockFailed, ready: false,
      checks: CHECK_IDS.map(id => failed(id, reason)) });
    return this.codec.decode(this.codec.encode(report));
  }

  private build(checks: ReadinessCheck[], observedAtUnixUs = 0n, stages: ProxyStageTiming[] = []): ReadonlyReadinessReport {
    const launch = this.binding.launch;
    const report = create(ReadinessReportSchema, { live: !this.closed && !this.fatal && !this.clockFailed,
      ready: checks.length === 9 && checks.every(check => check.status === Status.PASS && check.reason === Reason.OK),
      target: launch.target as RuntimeTarget, configHash: launch.configHash, runtimeManifestHash: launch.runtimeManifestHash,
      launchContextHash: launch.launchContextHash, processInstanceId: launch.processInstanceId, observedAtUnixUs, checks, stages });
    // One once-bound semantic/size boundary, including every invalidated view.
    // Round-trip copies/freeze independently without reparsing config per read.
    return this.codec.decode(this.codec.encode(report));
  }
}
