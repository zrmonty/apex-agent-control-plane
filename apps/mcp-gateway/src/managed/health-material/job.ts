import { isDeepStrictEqual, types } from "node:util";
import { parseRuntimeConfiguration } from "../runtime-config.js";
import { parseRuntimeLaunchContext } from "../launch-context.js";
import { clockSample } from "../readiness/timing.js";
import type { ReadinessBinding } from "../readiness/types.js";
import type { Clock } from "../../telemetry/clock.js";
import { copyBinding, decodeToken, rejected } from "./binding.js";
import { directory, regular, unchanged } from "./metadata.js";
import type { HealthFile, HealthFileSystem, HealthMaterialLoad, HealthMaterialLoadOptions,
  LoadedHealthMaterial, TimerBoundary } from "./types.js";

const ROOT = "/run/apex/runtime";
const WORK_NS = 2000000000n, CLEANUP_NS = 5000000000n;
type Descriptor = { file: HealthFile; closing?: Promise<void>; closed: boolean; uncertain: boolean };
// Exactly one fixed-mount job per process, including cancelled/fatal jobs with
// unresolved I/O. The strong reference is released only after actual cleanup.
type LoadGate = { held?: object };
const processGate: LoadGate = {};

/** Private fixture isolation only; not exported from the public loader. */
export function isolatedGate(): LoadGate { return {}; }

/** Private OS-boundary injection only; never reexported by the public entry. */
export function startLoad(options: HealthMaterialLoadOptions, files: HealthFileSystem, timers: TimerBoundary,
  gate: LoadGate = processGate): HealthMaterialLoad {
  if (gate.held) return refusedLoad();
  const reservation = {};
  gate.held = reservation; // Reserve before construction or any reentrant callback.
  try {
    const job = new LoadJob(options, files, timers, () => {
      if (gate.held === job) delete gate.held;
    });
    gate.held = job;
    return job.handle;
  } catch {
    // Construction has not started I/O. Do not free an unrelated reservation.
    if (gate.held === reservation) delete gate.held;
    return refusedLoad();
  }
}
function refusedLoad(): HealthMaterialLoad {
  return Object.freeze({ completion: Promise.reject(rejected()), cancel() {} });
}

class LoadJob {
  readonly handle: HealthMaterialLoad;
  private readonly entryNs: bigint;
  private binding?: ReadinessBinding;
  private current?: (binding: ReadinessBinding) => boolean;
  private clock?: Clock;
  private onFatal?: () => void;
  private clockStart?: bigint;
  private lastClock?: bigint;
  private stopWork?: () => void;
  private stopCleanup?: () => void;
  private cleanupAt?: bigint;
  private failed = false;
  private fatal = false;
  private running = true;
  private settled = false;
  private pending = 0;
  private descriptor?: Descriptor;
  private token?: Buffer;
  private resolve!: (value: LoadedHealthMaterial) => void;
  private reject!: (reason: unknown) => void;

  constructor(options: HealthMaterialLoadOptions, private readonly files: HealthFileSystem,
    private readonly timers: TimerBoundary, private readonly release: () => void) {
    this.handle = Object.freeze({ completion: new Promise<LoadedHealthMaterial>((resolve, reject) => {
      this.resolve = resolve; this.reject = reject;
    }), cancel: () => this.cancel() });
    // Capture the OS timer anchor before bounded copying. Supplied owner/clock
    // callbacks are entered only after expected metadata is independently copied.
    this.entryNs = timers.monotonicNs();
    try {
      const owner = dataProperty(options, "owner");
      this.binding = copyBinding(dataProperty(owner, "expected") as ReadinessBinding);
      const current = dataProperty(owner, "isCurrent"), clock = dataProperty(options, "clock");
      const now = dataProperty(clock, "now"), fatal = dataProperty(options, "onFatal");
      if (typeof current !== "function" || typeof now !== "function" || typeof fatal !== "function") throw rejected();
      this.current = current.bind(owner); this.clock = { now: now.bind(clock) }; this.onFatal = () => { fatal.call(options); };
    } catch { this.failed = true; }
    // Return cancel ownership before starting even the first supplied callback.
    queueMicrotask(() => { void this.run(); });
  }

  private sample(): bigint {
    const sampled = clockSample(this.clock!, this.lastClock);
    this.lastClock = sampled.monotonicNs;
    // Deduct already-consumed preflight time; neither supplied callbacks nor
    // defensive generated serialization receive a fresh two-second allowance.
    this.clockStart ??= sampled.monotonicNs - (this.timers.monotonicNs() - this.entryNs);
    return sampled.monotonicNs;
  }

  private guard(): void {
    if (this.failed) throw rejected();
    const now = this.sample();
    if (this.failed) throw rejected(); // Clock callbacks may cancel/reenter too.
    // Currentness is the last supplied callback: a valid Clock sample may have
    // invalidated the owner without cancelling. No recursive callback rechecks.
    if (this.current!(this.binding!) !== true) this.fail();
    if (this.failed) throw rejected(); // Currentness callback may cancel/reenter.
    // The independent native fence also covers time spent in that last callback.
    if (now - this.clockStart! >= WORK_NS || this.timers.monotonicNs() - this.entryNs >= WORK_NS) {
      this.fail(); throw rejected();
    }
  }

  private async run(): Promise<void> {
    try {
      if (this.failed) throw rejected();
      const f = this.files.flags;
      if (this.files.platform !== "linux" || f.readOnly !== 0 || !Number.isSafeInteger(f.noFollow) || f.noFollow <= 0 ||
        !Number.isSafeInteger(f.nonblock) || f.nonblock <= 0) throw rejected();
      this.stopWork = this.arm(2000, () => this.workDeadline());
      this.guard();
      // Conservative inspection only, not race-proof ancestor confinement.
      for (const path of ["/", "/run", "/run/apex", ROOT]) {
        this.guard(); const info = await this.own(() => this.files.lstat(path)); this.guard(); directory(info);
      }
      const configBytes = await this.read("runtime-revision.json", 262144);
      let config;
      try { config = parseRuntimeConfiguration(text(configBytes)); this.guard(); }
      finally { configBytes.fill(0); }
      if (!isDeepStrictEqual(config, this.binding!.config)) throw rejected();
      const launchBytes = await this.read("launch-context.json", 16384);
      let launch;
      try { launch = parseRuntimeLaunchContext(text(launchBytes), config); this.guard(); }
      finally { launchBytes.fill(0); }
      if (!isDeepStrictEqual(launch, this.binding!.launch)) throw rejected();
      const tokenBytes = await this.read("health-token", 43);
      try { this.token = decodeToken(tokenBytes); this.guard(); }
      finally { tokenBytes.fill(0); }
      this.guard();
    } catch { this.fail(); }
    finally {
      this.running = false;
      this.checkCleanupDeadline();
      this.finish();
    }
  }

  private async own<T>(operation: () => Promise<T>): Promise<T> {
    // Reserve before the syscall can synchronously fail or a private test seam
    // can reenter cancellation. Never race its termination against a timer.
    this.pending++;
    try { return await operation(); }
    finally { this.pending--; this.checkCleanupDeadline(); }
  }

  private async read(slot: string, cap: number): Promise<Buffer> {
    this.guard();
    const path = `${ROOT}/${slot}`;
    const before = await this.own(() => this.files.lstat(path)); this.guard(); regular(before, cap);
    const f = this.files.flags;
    this.guard();
    const file = await this.own(() => this.files.open(path, f.readOnly | f.noFollow | f.nonblock));
    // Even a late open transfers a real handle. Register it BEFORE the guard so
    // cancellation can only close it, never discard it or start another read.
    const descriptor: Descriptor = { file, closed: false, uncertain: false };
    this.descriptor = descriptor;
    let buffer: Buffer | undefined, accepted = false;
    try {
      this.guard();
      const opened = await this.own(() => file.stat()); this.guard();
      regular(opened, cap); unchanged(before, opened);
      buffer = Buffer.alloc(cap + 1);
      let length = 0;
      while (length < buffer.length) {
        this.guard();
        const count = await this.own(() => file.read(buffer!, length, buffer!.length - length));
        this.guard();
        if (!Number.isSafeInteger(count) || count < 0 || count > buffer.length - length) throw rejected();
        if (count === 0) break;
        length += count;
      }
      if (length < 1 || length > cap || BigInt(length) !== opened.size) throw rejected();
      const after = await this.own(() => file.stat()); this.guard();
      regular(after, cap); unchanged(opened, after);
      await this.close(descriptor); this.guard();
      accepted = true;
      return buffer.subarray(0, length);
    } catch {
      // Failure starts its cleanup grace now, not after an unresponsive close.
      this.fail();
      throw rejected();
    } finally {
      // Await real close even after failure. Never clear a pending OS-read buffer.
      await this.close(descriptor);
      if (!accepted) buffer?.fill(0);
    }
  }

  private close(descriptor: Descriptor): Promise<void> {
    if (!descriptor.closing) {
      // Install the close owner before invoking close (which may reenter).
      let begin!: () => void;
      descriptor.closing = new Promise<void>(resolve => { begin = resolve; }).then(async () => {
        try { await this.own(() => descriptor.file.close()); descriptor.closed = true; }
        catch { descriptor.uncertain = true; this.fail(); }
      });
      begin();
    }
    return descriptor.closing;
  }

  private cancel(): void {
    if (this.settled) { this.token?.fill(0); return; }
    this.fail();
  }

  private fail(): void {
    if (this.failed) return;
    this.failed = true; // Latch BEFORE any clock/timer/close callback.
    this.stopWork?.(); this.stopWork = undefined;
    this.cleanupAt = this.timers.monotonicNs() + CLEANUP_NS;
    this.checkCleanupDeadline();
    if (this.descriptor) void this.close(this.descriptor);
  }

  private workDeadline(): void {
    if (this.failed || this.settled) return;
    try {
      this.guard();
      this.stopWork = this.arm(1, () => this.workDeadline()); // Early timer: never extend the absolute bound.
    } catch { this.fail(); }
  }

  private checkCleanupDeadline(): void {
    if (!this.failed || this.fatal || this.cleanupAt === undefined) return;
    if (this.running || this.pending || this.descriptor && !this.descriptor.closed) {
      const remaining = this.cleanupAt - this.timers.monotonicNs();
      if (remaining > 0n) {
        // One owned wake, rounded up only to timer milliseconds. An early wake
        // consumes its slot, then rearms against the SAME absolute deadline.
        if (!this.stopCleanup) this.stopCleanup = this.arm(Number((remaining + 999999n) / 1000000n), () => {
          this.stopCleanup = undefined;
          this.checkCleanupDeadline();
        });
        return;
      }
      this.fatal = true;
      this.stopWork?.(); this.stopCleanup?.();
      try { this.onFatal?.(); } catch { /* Static terminal failure, no error diagnostics. */ }
    }
  }

  private arm(ms: number, callback: () => void): () => void {
    const stop = this.timers.after(ms, callback);
    return () => { try { stop(); } catch { /* Cannot restore ownership after cancellation. */ } };
  }

  private finish(): void {
    if (this.settled || this.running || this.pending || this.descriptor && !this.descriptor.closed) return;
    this.stopWork?.(); this.stopCleanup?.();
    if (!this.failed) { try { this.guard(); } catch { this.fail(); } }
    this.stopWork?.(); this.stopCleanup?.();
    this.settled = true; this.release();
    if (this.failed || !this.token) { this.token?.fill(0); this.reject(rejected()); }
    else this.resolve(Object.freeze({ binding: this.binding!, tokenBytes: this.token, dispose: () => this.token?.fill(0) }));
  }
}

function text(bytes: Buffer): string {
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
}
function dataProperty(value: unknown, key: string): unknown {
  if (!value || typeof value !== "object" || types.isProxy(value)) throw rejected();
  const property = Object.getOwnPropertyDescriptor(value, key);
  if (!property || !("value" in property)) throw rejected();
  return property.value;
}
