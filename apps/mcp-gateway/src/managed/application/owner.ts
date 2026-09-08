import type { Clock } from "../../telemetry/clock.js";
import { createManagedRuntimeMaterials, disposeRuntimeMaterials, runtimeTokenMaterial,
  type RuntimeMaterials } from "../bootstrap/runtime-materials.js";
import { disposeStageOwner, type StageBootstrap, type StageOwner, type startSealedStageBootstrap } from "../bootstrap/stage-owner.js";
import type { RuntimeCore, RuntimeCoreHandle, startManagedRuntimeCore } from "../runtime-core.js";
import type { startHealthServer } from "../health-server.js";
import type { startManagedIngress } from "../ingress.js";
import type { Timers } from "../stage-reader/types.js";
import type { PendingCompletion } from "../call-owner.js";
import { ReadinessReportCodec } from "../readiness/report-codec.js";
import { clockSample } from "../readiness/timing.js";

export type ApplicationOptions = Readonly<{ env: NodeJS.ProcessEnv; onFatal(): void }>;
export type ManagedApplication = Readonly<{
  /** Listening plus completed PREPARE readiness, not selected SERVE or a route. */
  result: Promise<Readonly<{ host: string; port: number }>>;
  /** Actual resource closure; fatal timeout never fabricates this proof. */
  closed: Promise<void>;
  completionHandoff: Promise<readonly PendingCompletion[]>;
  /** True only when this invocation initiated stop; never physical closure proof. */
  cancel(): boolean;
}>;
type Dependencies = Readonly<{ clock: Clock; timers: Timers; bootstrap: typeof startSealedStageBootstrap;
  core: typeof startManagedRuntimeCore; health: typeof startHealthServer; ingress: typeof startManagedIngress }>;
type Resource = { close(): Promise<unknown>; closing: boolean; closed: boolean };
const retained = new Set<ManagedApplication>();
const refused = () => new Error("managed application refused safely");

/** Private owner boundary: production entry fixes all factories and clocks. */
export function startApplication(options: ApplicationOptions, deps: Dependencies): ManagedApplication {
  return new Application(options, deps).start();
}
class Application {
  readonly handle: ManagedApplication;
  private resolve!: (address: { host: string; port: number }) => void;
  private reject!: (error: Error) => void;
  private drain!: () => void;
  private handoff!: (pending: readonly PendingCompletion[]) => void;
  private readonly resources: Resource[] = [];
  private bootstrap?: StageBootstrap;
  private stage?: StageOwner;
  private materials?: RuntimeMaterials;
  private coreOwner?: RuntimeCoreHandle;
  private core?: RuntimeCore;
  private stopped = false;
  private finished = false;
  private finishing = false;
  private pending = false;
  private published = false;
  private fatal = false;
  private unobservedHealth = false;
  private last = 0n;
  private deadline = 0n;
  private cleanupDeadline?: bigint;
  private stopStartup?: () => void;
  private stopRefresh?: () => void;
  private stopCleanup?: () => void;
  private settleReadiness?: () => void;
  constructor(private readonly options: ApplicationOptions, private readonly deps: Dependencies) {
    const result = new Promise<Readonly<{ host: string; port: number }>>((yes, no) => { this.resolve = yes; this.reject = no; });
    void result.catch(() => {});
    this.handle = Object.freeze({ result, closed: new Promise<void>(done => { this.drain = done; }),
      completionHandoff: new Promise<readonly PendingCompletion[]>(done => { this.handoff = done; }), cancel: () => this.stop() });
    retained.add(this.handle);
  }
  start() {
    try {
      if (typeof this.options.onFatal !== "function") throw refused();
      this.deadline = this.sample() + 20_000_000_000n;
      this.stopStartup = this.deps.timers.after(20000, () => this.stop());
      this.pending = true;
      queueMicrotask(() => { void this.run(); });
    } catch { this.stop(); }
    return this.handle;
  }
  private sample() {
    const now = this.deps.timers.now();
    if (typeof now !== "bigint" || now < this.last) throw refused();
    this.last = now; return now;
  }
  private check() {
    const now = this.sample();
    if (this.stopped || !this.published && now >= this.deadline) throw refused();
  }
  private adopt(close: Resource["close"]) {
    const resource: Resource = { close, closing: false, closed: false }; this.resources.push(resource);
    if (this.stopped) this.close(resource);
  }
  private async run() {
    try {
      this.check();
      this.bootstrap = this.deps.bootstrap({ env: this.options.env, onFatal: () => this.fail() });
      this.stage = await this.bootstrap.result; this.check();
      if (!this.stage.network) throw refused();
      const wall = clockSample(this.deps.clock).unixUs;
      this.check();
      this.materials = createManagedRuntimeMaterials(this.stage, wall); this.check();
      const options = { stage: this.stage, materials: this.materials, clock: this.deps.clock, onFatal: () => this.fail() };
      const owner = this.deps.core(options); this.coreOwner = owner;
      this.adopt(() => { owner.cancel(); return owner.closed; });
      void owner.revoked.then(() => this.stop(), () => this.fail());
      this.core = await owner.result; this.check();
      const encodedToken = runtimeTokenMaterial(this.materials, "health");
      let token: Buffer | undefined;
      let healthAdopted = false;
      try {
        // Stage validation owns canonical base64url; the transport takes raw
        // token bytes and independently copies them before starting its listener.
        token = Buffer.from(encodedToken.toString("ascii"), "base64url");
        const health = await this.deps.health({ tokenBytes: token, clock: this.deps.clock, state: this.core.readiness,
          codec: new ReadinessReportCodec({ config: this.stage.documents.config, launch: this.stage.documents.launch }),
          onFatal: () => {
            // The async health factory can report failed startup teardown
            // without returning a handle. Its rejection is not closure proof.
            if (!healthAdopted) this.unobservedHealth = true;
            this.fail();
          } });
        this.adopt(() => health.close());
        healthAdopted = true; this.unobservedHealth = false;
        // Loss stops admission before cleanup; only close() settles ownership.
        void health.lost.then(() => this.stop(), () => this.fail());
      } finally { encodedToken.fill(0); token?.fill(0); }
      this.check();
      const ingress = this.deps.ingress({ ...options, executor: this.core.executor, verifier: this.core.verifier,
        isAdmitting: () => !this.stopped && this.core!.isAdmitting() });
      this.adopt(() => { ingress.cancel(); return ingress.closed; });
      void ingress.closed.then(() => this.stop(), () => this.fail());
      const address = await ingress.result; this.check();
      // Both actual listeners exist before a successful monitor can enable a
      // SERVE grant's applied acknowledgment. PREPARE still admits no requests.
      const ready = new Promise<void>(done => { this.settleReadiness = done; });
      await this.sweep(); await ready; this.check();
      this.published = true; this.stopStartup?.(); this.resolve(Object.freeze({ ...address }));
    } catch { this.stop(); }
    finally { this.pending = false; this.finish(); }
  }
  private async sweep() {
    this.check();
    const started = this.sample();
    const pending = this.core!.readiness.checkStartup();
    // Schedule only AFTER the monitor has synchronously captured its own start.
    // Scheduling before dispatch could wake a few nanoseconds too early, reuse
    // the old cache, and skip every other required refresh.
    this.stopRefresh?.();
    this.stopRefresh = this.deps.timers.after(5000, () => {
      this.stopRefresh = undefined;
      void this.sweep().catch(() => this.stop());
    });
    const report = await pending;
    this.check();
    if (report.ready && this.sample() < started + 2_000_000_000n) {
      this.settleReadiness?.();
    } else if (this.core!.readiness.hasBeenReady || !report.live) throw refused();
    // A cold unavailable sweep keeps startup pending on the original deadline.
    // The existing scheduled dispatch asks the SAME monitor again; it retains
    // its active permit until physical cleanup, even after a logical timeout.
  }
  private close(resource: Resource) {
    if (resource.closing) return;
    resource.closing = true;
    try { void resource.close().then(() => { resource.closed = true; this.finish(); }, () => this.fail()); }
    catch { this.fail(); }
  }
  private stop() {
    if (this.finished) return false;
    // Capture disposition before any cleanup callback can reenter cancellation.
    const initiated = !this.stopped;
    if (!this.stopped) {
      this.stopped = true; this.reject(refused()); this.stopStartup?.(); this.stopRefresh?.();
      this.settleReadiness?.();
      try { this.cleanupDeadline = this.sample() + 5_000_000_000n; }
      catch { this.cleanupDeadline = this.last; }
      this.stopCleanup = this.deps.timers.after(5000, () => this.fail());
    }
    // Once stage ownership transfers, retain credentials through exact call
    // completion/transport closure. Never cancel that bootstrap prematurely.
    if (!this.stage) this.bootstrap?.cancel();
    for (const resource of this.resources) this.close(resource);
    this.finish();
    return initiated;
  }
  private fail() {
    if (this.fatal || this.finished) return;
    this.fatal = true; this.stop();
    try { this.options.onFatal(); } catch { /* Owning executable must terminate. */ }
  }
  private finish() {
    if (!this.stopped || this.finished || this.finishing || this.pending || this.unobservedHealth ||
      this.resources.some(resource => !resource.closed)) return;
    this.finishing = true;
    void (async () => {
      try {
        const pending = await this.coreOwner?.completionHandoff ?? Object.freeze([]);
        if (this.materials) disposeRuntimeMaterials(this.materials);
        if (this.stage) disposeStageOwner(this.stage);
        this.bootstrap?.cancel(); await this.bootstrap?.closed;
        try { if (this.cleanupDeadline !== undefined && this.sample() >= this.cleanupDeadline) this.fail(); }
        catch { this.fail(); }
        this.finished = true; this.stopCleanup?.(); this.stopRefresh?.(); this.stopStartup?.();
        retained.delete(this.handle); this.handoff(pending); this.drain();
      } catch { this.fail(); }
    })();
  }
}
