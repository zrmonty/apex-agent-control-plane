import type { Dependencies, Gate, GuardProcess, GuardProcessOptions, Material, Relay } from "./types.js";
import type { ManagedStageLoad } from "../stage-reader.js";
import { parseGuardConfiguration, type GuardConfiguration } from "../configuration.js";
import { guardEnvironment } from "./environment.js";
import { exact, MAX_TIME } from "../configuration/boundary.js";
const refused = () => new Error("guard process refused safely");
const min = (a: bigint, b: bigint) => a < b ? a : b;
type Resource = { relay: Relay; closing: boolean; closed: boolean };

/** Internal fixture boundary; the public entry supplies only actual OS owners. */
export function startGuard(options: GuardProcessOptions, deps: Dependencies, gate: Gate): GuardProcess {
  if (gate.held) return rejected();
  const reservation = {}; gate.held = reservation;
  try {
    const job = new Job(options, deps, () => { if (gate.held === job) delete gate.held; });
    gate.held = job; return job.handle;
  } catch { delete gate.held; return rejected(); }
}
function rejected(): GuardProcess {
  const result = Promise.reject<Readonly<{ addresses: GuardConfiguration["addresses"] }>>(refused()); void result.catch(() => {});
  return Object.freeze({ result, revoked: Promise.resolve(), closed: Promise.resolve(), cancel() {} });
}

class Job {
  readonly handle: GuardProcess;
  private resolve!: (value: Readonly<{ addresses: GuardConfiguration["addresses"] }>) => void;
  private reject!: (error: Error) => void;
  private revoke!: () => void;
  private drain!: () => void;
  private readonly started: bigint;
  private readonly initialWall: bigint;
  private last: bigint;
  private lastWall: bigint;
  private readonly workDeadline: bigint;
  private expiry?: bigint;
  private selection?: ReturnType<typeof guardEnvironment>;
  private fatal: () => void = () => {};
  private fatalInvoked = false;
  private stage?: ManagedStageLoad;
  private stageClosed = true;
  private stageCancelled = false;
  private material?: Material;
  private disposalAttempted = false;
  private config?: GuardConfiguration;
  private resources: Resource[] = [];
  private pending = true;
  private stopped = false;
  private published = false;
  private settled = false;
  private finished = false;
  private cleanupAt?: bigint;
  private cleanupLast?: bigint;
  private stopTimer?: () => void;
  private stopCleanup?: () => void;

  constructor(options: GuardProcessOptions, private readonly deps: Dependencies, private readonly release: () => void) {
    this.started = deps.timers.now(); this.last = this.started;
    if (typeof this.started !== "bigint" || this.started < 0n) throw refused();
    this.workDeadline = this.started + 10_000_000_000n;
    this.initialWall = this.wall(); this.lastWall = this.initialWall;
    const result = new Promise<Readonly<{ addresses: GuardConfiguration["addresses"] }>>((yes, no) => { this.resolve = yes; this.reject = no; });
    void result.catch(() => {});
    this.handle = Object.freeze({ result, revoked: new Promise<void>(yes => { this.revoke = yes; }),
      closed: new Promise<void>(yes => { this.drain = yes; }), cancel: () => this.stop() });
    try {
      const input = exact(options, ["env", "onFatal"]);
      if (typeof input.onFatal !== "function") throw refused();
      const fatal = input.onFatal; this.fatal = () => { fatal(); };
      this.selection = guardEnvironment(input.env as NodeJS.ProcessEnv);
    } catch { /* Statically reject before I/O in the owned queued run. */ }
    queueMicrotask(() => { void this.run(); });
  }
  private wall(): bigint {
    const ms = this.deps.unixMs();
    if (!Number.isSafeInteger(ms) || ms <= 0 || BigInt(ms) * 1000n > MAX_TIME - 1000n) throw refused();
    return BigInt(ms) * 1000n;
  }
  private check(): void {
    if (this.stopped) throw refused();
    const sample = this.deps.timers.now(), wall = this.wall();
    if (typeof sample !== "bigint" || sample < this.last || wall < this.lastWall) throw refused();
    this.last = sample; this.lastWall = wall;
    if ((!this.published && sample >= this.workDeadline) ||
      (this.expiry !== undefined && sample >= this.expiry) ||
      (this.config && wall + 1000n >= this.config.notAfterUnixUs) || this.stopped) throw refused();
  }
  private relayClock = (): bigint => {
    try { this.check(); return this.last; } catch { this.stop(); throw refused(); }
  };
  private arm(running = this.published): void {
    this.check(); this.stopTimer?.();
    const deadline = running ? this.expiry! : min(this.workDeadline, this.expiry ?? this.workDeadline);
    const remaining = deadline - this.last;
    if (remaining <= 0n) throw refused();
    this.stopTimer = this.deps.timers.after(Number(min(1000n, (remaining + 999999n) / 1000000n)), () => {
      this.stopTimer = undefined;
      try { this.check(); this.arm(); } catch { this.stop(); }
    });
  }
  private adopt(relay: Relay): Resource {
    const resource = { relay, closing: false, closed: false }; this.resources.push(resource);
    void relay.revoked.then(() => this.stop(), () => this.stop());
    if (this.stopped) this.close(resource);
    return resource;
  }
  private async run(): Promise<void> {
    try {
      if (!this.selection) throw refused(); this.arm(); this.check();
      this.stage = this.deps.load({ expectedManifestSha256: this.selection.manifest, onFatal: () => this.notifyFatal() });
      this.stageClosed = false;
      void this.stage.closed.then(() => { this.stageClosed = true; this.finish(); }, () => this.stop());
      if (this.stopped) this.cancelStage();
      this.material = await this.stage.result; this.check();
      if (this.material.manifestSha256 !== this.selection.manifest) throw refused();
      this.config = parseGuardConfiguration(this.material.files["guard-config.json"], this.selection.expected, this.initialWall);
      this.expiry = this.started + (this.config.notAfterUnixUs - this.initialWall - 1000n) * 1000n;
      this.disposeMaterial(); this.check();
      const a = this.config.addresses;
      const egress = this.adopt(this.deps.egress({ bindAddress: a.guardInternal, port: a.egressPort,
        gatewayAddress: a.gateway, outboundAddress: a.guardOuter, policy: this.config.policy, monotonicNowNs: this.relayClock }));
      this.check();
      const ingress = this.adopt(this.deps.ingress({ bindAddress: a.guardOuter, port: a.ingressPort,
        edgeAddress: a.edge, gatewayAddress: a.gateway, outboundAddress: a.guardInternal, monotonicNowNs: this.relayClock }));
      this.check();
      const bound = await Promise.all([egress.relay.listen(), ingress.relay.listen()]); this.check();
      for (const [actual, address, port] of [[bound[0], a.guardInternal, a.egressPort], [bound[1], a.guardOuter, a.ingressPort]] as const)
        if (actual.address !== address || actual.port !== port || actual.family !== 4) throw refused();
      this.arm(true); this.check(); this.published = true; this.settled = true;
      this.resolve(Object.freeze({ addresses: a }));
    } catch { this.stop(); }
    finally { this.pending = false; this.disposeMaterial(); if (this.stopped) this.stop(); this.finish(); }
  }
  private disposeMaterial(): void {
    if (!this.material || this.disposalAttempted) return; this.disposalAttempted = true;
    try { this.material.dispose(); this.material = undefined; }
    catch { this.stop(); } // Unknown disposal remains owned; watchdog must terminate.
  }
  private cancelStage(): void {
    if (!this.stage || this.stageCancelled) return; this.stageCancelled = true;
    try { this.stage.cancel(); } catch { /* Its physical receipt remains mandatory. */ }
  }
  private close(resource: Resource): void {
    if (resource.closing) return; resource.closing = true;
    try { void resource.relay.close().then(() => { resource.closed = true; this.finish(); }, () => this.stop()); }
    catch { this.stop(); }
  }
  private stop(): void {
    if (this.finished) return;
    if (!this.stopped) {
      this.stopped = true; this.revoke(); this.stopTimer?.(); this.stopTimer = undefined;
      if (!this.settled) { this.settled = true; this.reject(refused()); }
      let observed = this.last;
      try { const sample = this.deps.timers.now(); if (typeof sample === "bigint" && sample >= observed) observed = sample; } catch { /* Use last observed bound. */ }
      const deadline = this.published ? this.expiry! : min(this.workDeadline, this.expiry ?? this.workDeadline);
      this.cleanupAt = min(observed, deadline) + 5_000_000_000n;
      this.cleanupLast = observed;
    }
    this.cancelStage();
    for (const resource of this.resources) this.close(resource);
    this.cleanup(); this.finish();
  }
  private cleanup(): void {
    if (this.finished || this.fatalInvoked || this.stopCleanup || this.cleanupAt === undefined) return;
    let remaining = 0n;
    try {
      const sample = this.deps.timers.now();
      if (typeof sample !== "bigint" || sample < this.cleanupLast!) throw refused();
      this.cleanupLast = sample; remaining = this.cleanupAt - sample;
    } catch { /* Untrustworthy cleanup clock is fatal, never a renewed grace. */ }
    if (remaining <= 0n) { this.notifyFatal(); return; }
    this.stopCleanup = this.deps.timers.after(Number((remaining + 999999n) / 1000000n), () => {
      this.stopCleanup = undefined; this.cleanup();
    });
  }
  private notifyFatal(): void {
    if (this.fatalInvoked || this.finished) return; this.fatalInvoked = true;
    try { this.fatal(); } catch { /* Retain actual owner until physical receipt or process exit. */ }
  }
  private finish(): void {
    if (this.finished || !this.stopped || this.pending || !this.stageClosed || this.material ||
      this.resources.some(resource => !resource.closed)) return;
    this.finished = true; this.stopTimer?.(); this.stopCleanup?.(); this.release(); this.drain();
  }
}
