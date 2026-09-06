import { readStage, type ReadOwner } from "./reader.js";
import { options } from "./validation.js";
import { guardOptions, type GuardStageLoadOptions } from "./guard-options.js";
import { rejected, type FileSystem, type LoadedManagedStage, type ManagedStageLoad,
  type ManagedStageLoadOptions, type Timers } from "./types.js";
export type Gate = { held?: object };
const processGate: Gate = {};
const WORK = 5000000000n, CLEANUP = 5000000000n;
type Resource = { value: { close(): Promise<void> }; closed: boolean };

/** Internal OS fixture seam; the guard entry always selects its fixed inventory. */
export function startGuardLoad(input: GuardStageLoadOptions, fs: FileSystem, timers: Timers,
  gate: Gate = processGate): ManagedStageLoad {
  return reserveLoad(() => guardOptions(input), fs, timers, gate);
}

/** Internal OS fixture seam; production entry never accepts a filesystem/gate. */
export function startLoad(input: ManagedStageLoadOptions, fs: FileSystem, timers: Timers,
  gate: Gate = processGate): ManagedStageLoad {
  return reserveLoad(() => options(input), fs, timers, gate);
}
function reserveLoad(selectConfig: () => ReturnType<typeof options>, fs: FileSystem,
  timers: Timers, gate: Gate): ManagedStageLoad {
  if (gate.held) return refused();
  const reservation = {}; gate.held = reservation;
  try {
    const job = new Job(selectConfig, fs, timers, () => { if (gate.held === job) delete gate.held; });
    gate.held = job; // Strong ownership survives even an uncertain, rejected close.
    return job.handle;
  } catch { delete gate.held; return refused(); }
}
function refused(): ManagedStageLoad {
  return Object.freeze({ result: Promise.reject(rejected()), closed: Promise.resolve(), cancel() {} });
}

class Job implements ReadOwner {
  readonly handle: ManagedStageLoad;
  private readonly entry: bigint;
  private config?: ReturnType<typeof options>;
  private failed = false;
  private finished = false;
  private fatal = false;
  private running = true;
  private pending = 0;
  private clockStart?: bigint;
  private clockLast?: bigint;
  private cleanupAt?: bigint;
  private stopWork?: () => void;
  private stopCleanup?: () => void;
  private resources: Resource[] = [];
  private buffers = new Set<Buffer>();
  private material?: LoadedManagedStage;
  private resolve!: (value: LoadedManagedStage) => void;
  private reject!: (reason: unknown) => void;
  private resolveClosed!: () => void;

  constructor(selectConfig: () => ReturnType<typeof options>, readonly fs: FileSystem, private readonly timers: Timers,
    private readonly release: () => void) {
    this.entry = timers.now();
    this.handle = Object.freeze({ result: new Promise<LoadedManagedStage>((yes, no) => {
      this.resolve = yes; this.reject = no;
    }), closed: new Promise<void>(yes => { this.resolveClosed = yes; }), cancel: () => {
      if (this.finished) this.material?.dispose(); else this.fail();
    } });
    try { this.config = selectConfig(); } catch { /* Static refusal in run, before I/O. */ }
    queueMicrotask(() => { void this.run(); });
  }
  guard(): void {
    if (this.failed) throw rejected();
    if (this.config?.clock) {
      const sample = this.config.clock();
      if (typeof sample !== "bigint" || sample < 0n || this.clockLast !== undefined && sample < this.clockLast) throw rejected();
      this.clockLast = sample;
      this.clockStart ??= sample - (this.timers.now() - this.entry);
      if (sample - this.clockStart >= WORK) throw rejected();
    }
    if (this.failed || this.timers.now() - this.entry >= WORK) throw rejected();
  }
  async io<T>(operation: () => Promise<T>, adopt?: (value: T) => void): Promise<T> {
    this.guard(); this.pending++;
    try {
      const value = await operation();
      adopt?.(value); // Adopt a late open/Dir BEFORE the post-await fence.
      this.guard(); return value;
    } finally { this.pending--; this.cleanupDeadline(); }
  }
  resource(value: { close(): Promise<void> }): void { this.resources.push({ value, closed: false }); }
  allocate(size: number): Buffer {
    this.guard(); const bytes = Buffer.alloc(size); this.buffers.add(bytes); return bytes;
  }
  wipe(view: Buffer): void {
    for (const bytes of this.buffers) if (bytes.buffer === view.buffer) {
      bytes.fill(0); this.buffers.delete(bytes); return;
    }
  }
  private async run(): Promise<void> {
    let files: Readonly<Record<string, Buffer>> | undefined;
    try {
      if (!this.config) throw rejected();
      const remaining = this.entry + WORK - this.timers.now();
      this.stopWork = this.timers.after(Number((remaining > 0n ? remaining + 999999n : 0n) / 1000000n),
        () => this.workDeadline());
      this.guard(); files = await readStage(this, this.config.names, this.config.hash); this.guard();
    } catch { this.fail(); }
    finally {
      // No close/wipe races an outstanding read/open: the awaited run owns I/O.
      // Close once. A failed close remains uncertain; it is never retried.
      for (const resource of [...this.resources].reverse()) {
        if (!this.failed) { try { this.guard(); } catch { this.fail(); } }
        this.pending++;
        try { await resource.value.close(); resource.closed = true; }
        catch { this.fail(); }
        finally { this.pending--; this.cleanupDeadline(); }
        if (!this.failed) { try { this.guard(); } catch { this.fail(); } }
      }
      this.running = false;
      if (!this.failed) { try { this.guard(); } catch { this.fail(); } }
      if (this.failed) this.dispose();
      if (this.pending || this.resources.some(resource => !resource.closed)) {
        this.cleanupDeadline(); return; // Never invent closed or free the slot.
      }
      this.finished = true;
      this.stopWork?.(); this.stopCleanup?.(); this.release(); this.resolveClosed();
      if (!this.failed && files) {
        this.material = Object.freeze({ files, manifestSha256: this.config!.hash, dispose: () => this.dispose() });
        this.resolve(this.material);
      }
    }
  }
  private dispose(): void { for (const bytes of this.buffers) bytes.fill(0); this.buffers.clear(); }
  private fail(): void {
    if (this.failed || this.finished) return;
    this.failed = true; this.reject(rejected());
    this.stopWork?.(); this.stopWork = undefined;
    const observed = this.timers.now();
    this.cleanupAt = (observed < this.entry + WORK ? observed : this.entry + WORK) + CLEANUP;
    this.cleanupDeadline();
  }
  private workDeadline(): void {
    if (this.failed || this.finished) return;
    try { this.guard(); this.stopWork = this.timers.after(1, () => this.workDeadline()); }
    catch { this.fail(); }
  }
  private cleanupDeadline(): void {
    if (!this.failed || this.finished || this.fatal || this.cleanupAt === undefined) return;
    if (!this.running && !this.pending && this.resources.every(resource => resource.closed)) return;
    const remaining = this.cleanupAt - this.timers.now();
    if (remaining <= 0n) {
      this.fatal = true; this.stopCleanup?.(); this.stopCleanup = undefined;
      try { this.config?.fatal(); } catch { /* Static surface; supervisor must terminate. */ }
    } else if (!this.stopCleanup) {
      this.stopCleanup = this.timers.after(Number((remaining + 999999n) / 1000000n), () => {
        this.stopCleanup = undefined; this.cleanupDeadline();
      });
    }
  }
}
