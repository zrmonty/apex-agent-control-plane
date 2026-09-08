import type { RuntimeCoreOptions } from "../runtime-core.js";
import { assertRuntimeMaterialsStage, runtimeJwksMaterial } from "../bootstrap/runtime-materials.js";
import { createManagedInboundVerifier } from "../bootstrap/inbound-verifier.js";
import { compile } from "../call-preparation/compile.js";
import { AuthenticatedGrantTransport } from "../authority/grant-transport.js";
import { RuntimeGrants } from "./grants.js";
import { createCoreReadiness } from "./concrete-readiness.js";
import type { ReadinessMonitor } from "../readiness.js";
import { UpstreamReadiness } from "./readiness.js";
import { AuthenticatedBusinessTransport } from "../authority/business-transport.js";
import { OwnedCallCoordinator, type PendingCompletion } from "../call-owner.js";
import { ManagedEvidenceClient } from "../evidence/client.js";
import { EvidenceReadinessClient } from "../evidence/readiness-client.js";
import { NetworkReadinessClient } from "../authority/network-readiness.js";
import { CompiledManagedExecutor } from "../compiled-executor.js";
import { createUpstream } from "./upstream.js";
import { refused, type Dependencies, type RuntimeCore, type RuntimeCoreHandle } from "./types.js";

type Resource = { close(): Promise<unknown>; closing: boolean; closed: boolean };

/** Internal OS-boundary seam. Public entry fixes native clocks/transports. */
export function startCore(options: RuntimeCoreOptions, deps: Dependencies): RuntimeCoreHandle {
  return new CoreJob(options, deps).start();
}
class CoreJob {
  private resolve!: (core: RuntimeCore) => void;
  private reject!: (error: Error) => void;
  private revoke!: () => void;
  private drain!: () => void;
  private handoff!: (pending: readonly PendingCompletion[]) => void;
  private unresolved: readonly PendingCompletion[] = Object.freeze([]);
  private readonly resources: Resource[] = [];
  private controlResource?: Resource;
  private hasCallCoordinator = false;
  private credentialsInvalid = false;
  private stopped = false;
  private finished = false;
  private pending = false;
  private fatal = false;
  private last = 0n;
  private wall = 0n;
  private expiry = 0n;
  private startupDeadline = 0n;
  private cleanupDeadline?: bigint;
  private stopWatch?: () => void;
  private stopRenewal?: () => void;
  private stopCleanup?: () => void;
  private grants?: RuntimeGrants;
  private published = false;
  readonly handle: RuntimeCoreHandle;
  constructor(private readonly options: RuntimeCoreOptions, private readonly deps: Dependencies) {
    const result = new Promise<RuntimeCore>((yes, no) => { this.resolve = yes; this.reject = no; });
    void result.catch(() => {});
    this.handle = Object.freeze({ result, revoked: new Promise<void>(done => { this.revoke = done; }),
      closed: new Promise<void>(done => { this.drain = done; }),
      completionHandoff: new Promise<readonly PendingCompletion[]>(done => { this.handoff = done; }), cancel: () => this.stop() });
  }
  start() {
    try {
      assertRuntimeMaterialsStage(this.options.materials, this.options.stage);
      if (typeof this.options.onFatal !== "function" || !this.options.stage.network) throw refused();
      this.last = this.sample(); this.wall = this.sampleWall();
      this.expiry = this.last + (this.options.materials.notAfterUnixUs - this.wall - 1000n) * 1000n;
      this.startupDeadline = this.last + 10_000_000_000n;
      this.check(); this.pending = true;
      queueMicrotask(() => { void this.run(); });
    } catch { this.stop(); }
    return this.handle;
  }
  private sample() {
    const now = this.deps.timers.now();
    if (typeof now !== "bigint" || now < this.last) throw refused();
    this.last = now; return now;
  }
  private sampleWall() {
    const ms = this.deps.unixMs();
    if (!Number.isSafeInteger(ms) || ms <= 0) throw refused();
    const wall = BigInt(ms) * 1000n;
    if (wall < this.wall) throw refused();
    this.wall = wall; return wall;
  }
  // Local business revocation is distinct from credential/transport validity.
  // Completion may outlive the grant, but never a revoked or expired credential.
  private authorizedNow = (): bigint => {
    try {
      if (this.credentialsInvalid || this.finished) throw refused();
      const now = this.sample(), wall = this.sampleWall();
      if (now >= this.expiry || wall + 1000n >= this.options.materials.notAfterUnixUs) throw refused();
      assertRuntimeMaterialsStage(this.options.materials, this.options.stage);
      return now;
    } catch { this.credentialsInvalid = true; this.stop(); throw refused(); }
  };
  private check = (): bigint => {
    try {
      if (this.stopped) throw refused();
      const now = this.authorizedNow();
      if (!this.published && now >= this.startupDeadline) throw refused();
      return now;
    } catch { this.stop(); throw refused(); }
  };
  private adopt(close: () => Promise<unknown>) {
    const r = { close, closing: false, closed: false }; this.resources.push(r);
    if (this.stopped) this.close(r);
    return r;
  }
  private async run() {
    try {
      this.watch();
      const { stage, materials, clock } = this.options;
      const preparation = Object.freeze({ config: stage.documents.config, binding: stage.documents.binding,
        evidenceAgentId: stage.documents.authority.profile.managed.evidence_agent_id,
        dataClassification: stage.documents.config.spec!.governanceBinding!.dataClassification, clock });
      const compiled = compile(preparation);
      const jwks = runtimeJwksMaterial(materials);
      let verifier;
      try { verifier = createManagedInboundVerifier(jwks, preparation.config); }
      finally { jwks.fill(0); }
      this.adopt(() => verifier.close()); this.check();
      const revokeCredentials = () => { this.credentialsInvalid = true; this.stop(); };
      const control = this.deps.control({ stage, materials, onFatal: () => { revokeCredentials(); this.notifyFatal(); } });
      this.controlResource = this.adopt(() => { control.cancel(); return control.closed; });
      void control.revoked.then(revokeCredentials, revokeCredentials);
      const channels = await control.result; this.check();
      let monitor: ReadinessMonitor | undefined;
      const grants = new RuntimeGrants({ binding: compiled.binding, monotonicNowNs: this.check,
        scheduler: this.deps.timers, transport: new AuthenticatedGrantTransport(channels.authority) }, () => this.stop(),
      () => monitor?.snapshot().ready === true);
      this.grants = grants; this.adopt(() => grants.close());
      if (!await grants.renew() || grants.snapshot().mode === "closed") throw refused();
      this.check();
      const upstream = createUpstream(stage, materials, this.check); this.adopt(() => upstream.close());
      const business = new AuthenticatedBusinessTransport({ channel: { start: (method, bytes) => {
        if (method === "/apex.v1.ManagedRuntimeAuthority/CompleteManagedCall") this.authorizedNow();
        else this.currentGrant();
        return channels.authority.start(method, bytes);
      } }, binding: compiled.binding,
        policyId: compiled.policyId, evidenceAgentId: compiled.evidenceAgentId,
        dataClassification: compiled.dataClassification, monotonicNowNs: this.authorizedNow });
      const calls = new OwnedCallCoordinator({ binding: compiled.binding, policyId: compiled.policyId,
        evidenceAgentId: compiled.evidenceAgentId, dataClassification: compiled.dataClassification, grants, business,
        routes: new Map([[upstream.alias, { session: upstream.session, toolName: upstream.toolName }]]), monotonicNowNs: this.authorizedNow });
      this.hasCallCoordinator = true;
      this.adopt(async () => { this.unresolved = await calls.close(); });
      const evidence = new ManagedEvidenceClient(channels.evidence, this.check); this.adopt(() => evidence.close());
      const evidenceReadiness = new EvidenceReadinessClient({ workspaceId: compiled.binding.workspaceId,
        namespaceId: compiled.binding.namespaceId, agentId: compiled.evidenceAgentId }, channels.evidence,
      () => { this.currentGrant(); return this.last; });
      this.adopt(() => evidenceReadiness.close());
      const networkReadiness = new NetworkReadinessClient(compiled.binding, stage.network!.bindingSha256,
        channels.authority, () => { this.currentGrant(); return this.last; });
      this.adopt(() => networkReadiness.close());
      const executor = new CompiledManagedExecutor({ preparation, calls, evidence }); this.adopt(() => executor.close());
      const readiness = new UpstreamReadiness(upstream, () => createUpstream(stage, materials, this.check),
        () => this.currentGrant(), () => this.stop(), () => this.notifyFatal(), this.deps.timers);
      this.adopt(() => readiness.close());
      const isAdmitting = () => { try { this.currentGrant(); return readiness.ready && grants.snapshot().admitting; } catch { return false; } };
      const prepareUpstream = readiness.prepare;
      monitor = createCoreReadiness(this.options, { verifier, business, grants, credentialExpiry: this.expiry,
        current: () => { this.currentGrant(); return this.last; }, timers: this.deps.timers,
        startNetworkReadiness: networkReadiness.start.bind(networkReadiness),
        startEvidenceReadiness: evidenceReadiness.start.bind(evidenceReadiness),
        upstream: (startedAtMonotonicNs, deadlineMonotonicNs) => {
          const result = prepareUpstream({ startedAtMonotonicNs, deadlineMonotonicNs });
          // On refusal prepare() may report before its serving socket closes.
          // Join that exact owner, never the entire root (which owns the monitor).
          let settled = false;
          const closed = result.then(() => { settled = true; }, async () => { await upstream.close(); settled = true; });
          return { result, closed, cancel: () => { if (!settled) this.stop(); } };
        } });
      this.adopt(() => monitor!.close());
      this.check(); this.published = true; this.renew();
      this.resolve(Object.freeze({ executor, verifier, grants, business, readiness: monitor, prepareUpstream, isAdmitting,
        startEvidenceReadiness: evidenceReadiness.start.bind(evidenceReadiness),
        startNetworkReadiness: networkReadiness.start.bind(networkReadiness),
        pendingCompletions: () => calls.pending(),
        retryCompletion: (callId: string) => { this.check(); return calls.retryCompletion(callId); } }));
    } catch { this.stop(); }
    finally { this.pending = false; this.finish(); }
  }
  private renew() {
    if (this.stopped) return;
    this.stopRenewal = this.deps.timers.after(2000, () => {
      this.stopRenewal = undefined;
      void (async () => {
        try {
          this.currentGrant();
          if (!await this.grants!.renew() || this.grants!.authoritySnapshot().mode === "closed") throw refused();
          this.check(); this.renew();
        } catch { this.stop(); }
      })();
    });
  }
  private watch() {
    this.check();
    if (this.published) this.currentGrant();
    this.stopWatch = this.deps.timers.after(1000, () => {
      this.stopWatch = undefined;
      try { this.watch(); } catch { this.stop(); }
    });
  }
  private currentGrant() {
    this.check();
    if (this.grants!.authoritySnapshot().mode === "closed") { this.stop(); throw refused(); }
  }
  private close(r: Resource) {
    if (r.closing) return; r.closing = true;
    try { void r.close().then(() => { r.closed = true; this.finish(); }, () => this.notifyFatal()); }
    catch { this.notifyFatal(); }
  }
  private stop() {
    if (this.finished) return;
    if (!this.stopped) {
      this.stopped = true; this.revoke(); this.reject(refused());
      this.stopWatch?.(); this.stopRenewal?.();
      let at = this.last; try { at = this.sample(); } catch { /* Keep accepted floor. */ }
      this.cleanupDeadline = at + 5_000_000_000n;
    }
    // Before composition there can be no reservation completion to protect.
    // Cancel the pending connection now so run() can leave its startup await.
    for (const r of this.resources) {
      if (r !== this.controlResource || !this.hasCallCoordinator || this.credentialsInvalid) this.close(r);
    }
    this.finish(); this.cleanup();
  }
  private cleanup() {
    if (this.finished || this.fatal || this.stopCleanup || this.cleanupDeadline === undefined) return;
    let remaining = 0n; try { remaining = this.cleanupDeadline - this.sample(); } catch { /* Clock failure cannot extend grace. */ }
    if (remaining <= 0n) { this.notifyFatal(); return; }
    this.stopCleanup = this.deps.timers.after(Number((remaining + 999999n) / 1000000n), () => {
      this.stopCleanup = undefined; this.cleanup();
    });
  }
  private notifyFatal() {
    if (this.fatal || this.finished) return; this.fatal = true;
    try { this.options.onFatal(); } catch { /* A thrown callback is not cleanup. */ }
  }
  private finish() {
    if (!this.stopped || this.finished || this.pending || this.resources.some(r => r !== this.controlResource && !r.closed)) return;
    // CompleteManagedCall retains the authenticated channel until all call and
    // retry owners physically close. Credential revocation closes it immediately.
    if (this.controlResource && !this.controlResource.closed) { this.close(this.controlResource); return; }
    this.finished = true; this.stopCleanup?.(); this.stopWatch?.(); this.stopRenewal?.();
    this.handoff(this.unresolved); this.drain();
  }
}
