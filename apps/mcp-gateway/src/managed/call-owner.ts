import type { ManagedCallAuthorizationRequest } from "@apex/contracts";
import type { DeploymentGrantOwner } from "./authority/grant-owner.js";
import type { AuthenticatedBusinessTransport } from "./authority/business-transport.js";
import type { BusinessDecision } from "./authority/business-types.js";
import type { DeploymentBinding } from "./authority/types.js";
import type { OwnedMcpSession } from "./upstream-wire/session.js";
import type { OwnedManagedCall } from "./authority/grant-owner.js";
import type { BusinessExchange } from "./authority/business-types.js";
import type { WireExchange } from "./upstream-wire/client.js";
import { authorizationRequest, businessBinding, businessIdentifier, businessClassification } from "./authority/business-codec.js";
import { assertDataTree, freezeTree } from "./runtime-config/boundary.js";
import { canonicalizeJson, sha256CanonicalJson, type JsonValue } from "../live/canonical.js";
import { isDeepStrictEqual } from "node:util";
import { CallObservationRecord, copyBusinessDecision, type CallObservation } from "./call-observation.js";
export type CallOwnerOptions = Readonly<{
  binding: DeploymentBinding; policyId: string; evidenceAgentId: string; dataClassification: string;
  grants: Pick<DeploymentGrantOwner, "snapshot" | "tryBeginCall">;
  business: Pick<AuthenticatedBusinessTransport, "startAuthorization" | "startCompletion">;
  routes: ReadonlyMap<string, Readonly<{ session: Pick<OwnedMcpSession, "call">; toolName: string }>>;
  monotonicNowNs(): bigint;
}>;
export type CallStart = Readonly<{ request: ManagedCallAuthorizationRequest; input: Record<string, unknown>;
  startedAtMonotonicNs: bigint; deadlineMonotonicNs: bigint }>;
export type CallResult = Readonly<{ decision: BusinessDecision; output?: unknown }>;
export type PendingCompletion = Readonly<{ callId: string; admissionId?: string; state: "unknown_reservation" | "completion_pending" | "completing" }>;
export type OwnedCall = Readonly<{ result: Promise<CallResult>; closed: Promise<void>; cancel(): void;
  observation(): CallObservation }>;
type Job = { callId: string; closed: Promise<void>; cancel(): void };
const refused = () => new Error("managed call refused safely");

/** Internal raw execution owner, NOT an outward success/evidence API. */
export class OwnedCallCoordinator {
  private readonly options: CallOwnerOptions;
  private readonly jobs = new Map<string, Job>();
  private readonly unresolved = new Map<string, PendingCompletion>();
  private readonly completions = new Map<string, { cancel(): void }>();
  private stopped = false;
  private lastTime?: bigint;
  private closing?: Promise<readonly PendingCompletion[]>;
  constructor(options: CallOwnerOptions) {
    try {
      const routes = new Map(options.routes);
      if (routes.size !== 1 || !routes.has("portfolio.read") || typeof options.monotonicNowNs !== "function" ||
        typeof options.grants?.snapshot !== "function" || typeof options.grants.tryBeginCall !== "function" ||
        typeof options.business?.startAuthorization !== "function" || typeof options.business.startCompletion !== "function") throw refused();
      const route = routes.get("portfolio.read")!;
      if (typeof route.session?.call !== "function" || typeof route.toolName !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(route.toolName)) throw refused();
      routes.set("portfolio.read", Object.freeze({ session: route.session, toolName: route.toolName }));
      this.options = Object.freeze({ ...options, routes, binding: businessBinding(options.binding),
        policyId: businessIdentifier(options.policyId), evidenceAgentId: businessIdentifier(options.evidenceAgentId),
        dataClassification: businessClassification(options.dataClassification) });
    } catch { throw refused(); }
  }

  start(input: CallStart): OwnedCall {
    try {
      if (this.stopped || new Set([...this.jobs.keys(), ...this.unresolved.keys()]).size >= 128) throw refused();
      assertDataTree(input.request, true); assertDataTree(input.input, false);
      if (!input.input || Array.isArray(input.input) || typeof input.input !== "object") throw refused();
      const request = authorizationRequest(input.request, this.options).submittedRequest;
      const argumentsCopy = freezeTree(JSON.parse(canonicalizeJson(input.input as JsonValue))) as Record<string, unknown>;
      if (request.argumentsHash !== sha256CanonicalJson(argumentsCopy as JsonValue) ||
        !/^[0-9a-f]{32}$/.test(request.trace!.traceId) || /^0+$/.test(request.trace!.traceId) ||
        !/^[0-9a-f]{16}$/.test(request.trace!.spanId) || /^0+$/.test(request.trace!.spanId) ||
        this.jobs.has(request.callId) || this.unresolved.has(request.callId)) throw refused();
      const started = input.startedAtMonotonicNs, deadline = input.deadlineMonotonicNs;
      if (typeof started !== "bigint" || started < 0n || typeof deadline !== "bigint" || deadline <= started ||
        deadline - started > 120_000_000_000n) throw refused();
      let resolve!: (value: CallResult) => void, reject!: (error: Error) => void, drain!: () => void;
      const result = new Promise<CallResult>((yes, no) => { resolve = yes; reject = no; });
      const closed = new Promise<void>(done => { drain = done; });
      const observation = new CallObservationRecord(request, started);
      let cleanupStarted = false;
      const beginCleanup = () => {
        if (cleanupStarted) return; cleanupStarted = true;
        observation.begin("cleanup"); observation.startTime("cleanup", this.observeTime());
      };
      let cancelled = false, settled = false, businessClosed = false, ticket: OwnedManagedCall | undefined;
      let auth: BusinessExchange<BusinessDecision> | undefined, upstream: WireExchange | undefined;
      let known: Extract<BusinessDecision, { outcome: "allowed" }> | undefined, uncertain = false;
      let timer: ReturnType<typeof setTimeout> | undefined;
      const rejectResult = () => { if (!settled) { settled = true; reject(refused()); } };
      const cancel = () => {
        // Business cancellation cannot abort the reservation receipt after all
        // business I/O ended. Its transport still owns deadline/revocation and
        // exact closure; output/HTTP/root cleanup must join that same attempt.
        if (businessClosed) return;
        cancelled = true; rejectResult(); clearTimeout(timer);
        beginCleanup(); observation.cancel();
        try { auth?.cancel(); } catch { /* Physical ownership is unchanged. */ }
        try { upstream?.cancel(); } catch { /* Physical ownership is unchanged. */ }
      };
      const job: Job = { callId: request.callId, closed, cancel }; this.jobs.set(request.callId, job);
      const check = () => {
        const now = this.sample();
        if (cancelled || this.stopped || now < started || now >= deadline) throw refused(); return now;
      };
      const settle = (value: CallResult) => { check(); if (!settled) { settled = true; resolve(Object.freeze(value)); } };
      void (async () => {
        try {
          const now = check(); timer = setTimeout(cancel, Number((deadline - now + 999_999n) / 1_000_000n));
          const initial = this.options.grants.snapshot();
          if (!initial.admitting || initial.mode !== "serve" || typeof initial.epoch !== "bigint") throw refused();
          ticket = this.options.grants.tryBeginCall();
          const authority = () => {
            const now = check(), current = this.options.grants.snapshot();
            if (!ticket?.isCurrent() || !current.admitting || current.mode !== "serve" || current.epoch !== initial.epoch ||
              (known && (known.epoch !== initial.epoch || now >= known.startDeadlineMonotonicNs))) throw refused();
            // Charge synchronous grant checks against start permission too,
            // not only the separate overall execution deadline.
            const finalNow = check();
            if (known && finalNow >= known.startDeadlineMonotonicNs) throw refused();
            return finalNow;
          };
          const authStart = authority(); uncertain = true;
          observation.begin("authorization", authStart);
          auth = this.options.business.startAuthorization(request, { startedAtMonotonicNs: started, expectedEpoch: initial.epoch });
          if (cancelled || this.stopped) auth.cancel();
          let decision: BusinessDecision;
          try {
            decision = copyBusinessDecision(await auth.result);
            if (decision.outcome === "allowed") {
              if (decision.epoch !== initial.epoch || !isDeepStrictEqual(decision.submittedRequest, request) ||
                decision.startDeadlineMonotonicNs !== started + decision.validForUs * 1000n) throw refused();
              known = decision;
            }
            uncertain = false;
            observation.known(decision); observation.result("authorization", "ok", this.observeTime());
          } catch { observation.result("authorization", "error", this.observeTime()); rejectResult(); throw refused(); }
          finally {
            if (cancelled || !known) beginCleanup();
            auth.cancel(); await auth.closed; observation.physicalClose("authorization", this.observeTime());
          }
          if (decision.outcome !== "allowed") { settle({ decision }); return; }
          const upstreamStart = authority();
          const route = this.options.routes.get(request.toolAlias)!;
          observation.begin("upstream", upstreamStart);
          upstream = route.session.call(request.callId, route.toolName, argumentsCopy,
            { startedAtMonotonicNs: started, deadlineMonotonicNs: deadline, beforeWrite: () => {
              const dispatched = authority(); observation.dispatch(dispatched);
            } });
          if (cancelled || this.stopped) upstream.cancel();
          let resultObserved = false, resultTime: bigint | undefined;
          try {
            const output = await upstream.result;
            resultObserved = true; resultTime = this.observeTime();
            settle({ decision, output }); observation.result("upstream", "ok", resultTime);
          }
          catch { observation.result("upstream", "error", resultObserved ? resultTime : this.observeTime()); rejectResult(); }
          finally { beginCleanup(); upstream.cancel(); await upstream.closed; observation.physicalClose("upstream", this.observeTime()); }
        } catch {
          if (!auth) observation.result("authorization", "error", this.observeTime());
          if (!upstream) observation.result("upstream", "error", this.observeTime());
          rejectResult();
        }
        finally {
          beginCleanup();
          clearTimeout(timer);
          // Dependencies may throw during cancel; never substitute result/abort
          // for their actual closure receipts or release the local ticket early.
          if (auth) { await auth.closed; observation.physicalClose("authorization", this.observeTime()); }
          if (upstream) { await upstream.closed; observation.physicalClose("upstream", this.observeTime()); }
          businessClosed = true;
          ticket?.release();
          if (known) {
            const pending: PendingCompletion = Object.freeze({ callId: request.callId, admissionId: known.admissionId, state: "completion_pending" });
            this.unresolved.set(request.callId, pending);
            await this.complete(pending, observation);
          } else if (uncertain) this.unresolved.set(request.callId, Object.freeze({ callId: request.callId, state: "unknown_reservation" }));
          if (!known) observation.result("cleanup", "ok", this.observeTime());
          const closedAt = this.observeTime(); observation.physicalClose("cleanup", closedAt); observation.finish(closedAt);
          this.jobs.delete(request.callId); drain();
        }
      })().catch(() => {
        // Rejected physical close or release is uncertain. Keep the strong job
        // and its local ticket pending for trusted process termination.
        cancel();
      });
      return Object.freeze({ result, closed, cancel, observation: () => observation.snapshot() });
    } catch { throw refused(); }
  }

  pending(): readonly PendingCompletion[] { return Object.freeze([...this.unresolved.values()]); }
  retryCompletion(callId: string): BusinessExchange<boolean> {
    const pending = this.unresolved.get(callId);
    if (!pending?.admissionId || pending.state !== "completion_pending" || this.jobs.has(callId)) throw refused();
    let resolve!: (value: boolean) => void, drain!: () => void;
    const result = new Promise<boolean>(done => { resolve = done; });
    const closed = new Promise<void>(done => { drain = done; });
    const cancel = () => { resolve(false); this.completions.get(callId)?.cancel(); };
    this.jobs.set(callId, { callId, closed, cancel });
    void this.complete(pending).then(() => {
      resolve(!this.unresolved.has(callId)); this.jobs.delete(callId); drain();
    }, () => { cancel(); /* Uncertain physical cleanup retains the job. */ });
    return Object.freeze({ result, closed, cancel });
  }
  close(): Promise<readonly PendingCompletion[]> {
    if (this.closing) return this.closing;
    this.stopped = true;
    const jobs = [...this.jobs.values()];
    this.closing = Promise.all(jobs.map(job => job.closed)).then(() => this.pending());
    for (const job of jobs) job.cancel();
    return this.closing;
  }
  private async complete(pending: PendingCompletion, observation?: CallObservationRecord): Promise<void> {
    if (!pending.admissionId) return;
    this.unresolved.set(pending.callId, Object.freeze({ ...pending, state: "completing" }));
    let exchange: ReturnType<AuthenticatedBusinessTransport["startCompletion"]> | undefined;
    let released = false, cancelled = false;
    const cancel = () => { cancelled = true; observation?.cancel("cleanup");
      try { exchange?.cancel(); } catch { /* Await original closure. */ } };
    this.completions.set(pending.callId, { cancel });
    try {
      exchange = this.options.business.startCompletion(pending.admissionId, pending.callId);
      if (cancelled) exchange.cancel();
      const receipt = await exchange.result;
      if (receipt.admissionId !== pending.admissionId || receipt.callId !== pending.callId || !receipt.released) throw refused();
      released = true;
      observation?.result("cleanup", "ok", this.observeTime());
    } catch { observation?.result("cleanup", "error", this.observeTime()); /* Preserve exact pending identity for an explicit cleanup retry. */ }
    finally {
      if (exchange) { exchange.cancel(); await exchange.closed; }
      this.completions.delete(pending.callId);
      if (released) this.unresolved.delete(pending.callId);
      else this.unresolved.set(pending.callId, pending);
    }
  }
  private observeTime(): bigint | undefined {
    try { return this.sample(); } catch { return undefined; } // Clock failure stops work, never skips physical cleanup.
  }
  private sample(): bigint {
    try {
      const now = this.options.monotonicNowNs();
      if (typeof now !== "bigint" || now < 0n || (this.lastTime !== undefined && now < this.lastTime)) throw refused();
      this.lastTime = now; return now;
    } catch { void this.close(); throw refused(); }
  }
}
