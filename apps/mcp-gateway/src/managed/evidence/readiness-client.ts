import type { OwnedEvidenceChannel } from "../evidence-channel.js";
import type { BusinessExchange } from "../authority/business-types.js";
import { randomBytes } from "node:crypto";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { EvidenceAdmissionProbeRequestSchema as Request, EvidenceAdmissionProbeResponseSchema as Response } from "@apex/contracts/event";
import { businessIdentifier } from "../authority/business-codec.js";
import { assertDataTree } from "../runtime-config/boundary.js";
import { dependencyUnavailable, redactDependencyFailure } from "../authority/dependency-failure.js";
export type EvidenceScope = Readonly<{ workspaceId: string; namespaceId: string; agentId: string }>;
export type AdmissionObservation = Readonly<{ validUntilMonotonicNs: bigint }>;
const refused = () => new Error("managed evidence readiness refused safely");
type Job = { closed: Promise<void>; cancel(): void };
/** Non-admitting observation over the root's already authenticated evidence channel.
 * The composing root must supply its actual enrolled scope; this constructor does
 * not establish deployment provenance or confer SERVE authority. */
export class EvidenceReadinessClient {
  private readonly scope: EvidenceScope;
  private readonly jobs = new Set<Job>();
  private stopped = false;
  private lastTime?: bigint;
  private closing?: Promise<void>;
  constructor(scope: EvidenceScope, private readonly channel: Pick<OwnedEvidenceChannel, "startReadiness">,
    private readonly now: () => bigint = process.hrtime.bigint) {
    try {
      assertDataTree(scope, true);
      this.scope = Object.freeze({ workspaceId: businessIdentifier(scope.workspaceId),
        namespaceId: businessIdentifier(scope.namespaceId), agentId: businessIdentifier(scope.agentId) });
      if (typeof channel?.startReadiness !== "function" || typeof now !== "function") throw refused();
    } catch { throw refused(); }
  }
  start(started: bigint, overallDeadline: bigint): BusinessExchange<AdmissionObservation> {
    if (this.stopped || this.jobs.size >= 4 || typeof started !== "bigint" || started < 0n ||
      typeof overallDeadline !== "bigint") throw refused();
    const deadline = overallDeadline < started + 2_000_000_000n ? overallDeadline : started + 2_000_000_000n;
    const nonce = randomBytes(32), bytes = toBinary(Request, create(Request, { ...this.scope, schemaVersion: 1, requestNonce: nonce }));
    let resolve!: (value: AdmissionObservation) => void, reject!: (error: Error) => void, drain!: () => void;
    const result = new Promise<AdmissionObservation>((yes, no) => { resolve = yes; reject = no; });
    void result.catch(() => {});
    const closed = new Promise<void>(done => { drain = done; });
    let wire: ReturnType<OwnedEvidenceChannel["startReadiness"]> | undefined;
    let finished = false, cancelled = false, timer: ReturnType<typeof setTimeout> | undefined;
    const cancel = (cause?: unknown) => {
      if (!finished) { finished = true; clearTimeout(timer); reject(redactDependencyFailure(cause, "managed evidence readiness refused safely")); }
      if (wire && !cancelled) { cancelled = true; try { wire.cancel(); } catch { /* Still physically owned. */ } }
    };
    const job = { cancel, closed }; this.jobs.add(job);
    const release = () => { bytes.fill(0); nonce.fill(0); this.jobs.delete(job); drain(); };
    const check = () => {
      const at = this.sample();
      if (this.stopped || finished || at < started || at >= deadline) throw refused();
      return at;
    };
    try { check(); wire = this.channel.startReadiness(bytes, started, deadline); }
    catch (error) { cancel(error); release(); throw redactDependencyFailure(error, "managed evidence readiness refused safely"); }
    // Once the channel hands off I/O, logical refusal never releases its slot.
    void wire.result.then(payload => {
      if (finished) return;
      try {
        check();
        if (!(payload instanceof Uint8Array) || payload.length > 1024) throw refused();
        const response = fromBinary(Response, payload, { readUnknownFields: false });
        if (!Buffer.from(toBinary(Response, response)).equals(payload) || response.schemaVersion !== 1 ||
          !nonce.equals(response.requestNonce) || response.workspaceId !== this.scope.workspaceId ||
          response.namespaceId !== this.scope.namespaceId || response.agentId !== this.scope.agentId ||
          response.validForUs <= 0n || response.validForUs > 10_000_000n) throw refused();
        const validUntilMonotonicNs = started + response.validForUs * 1000n;
        if (check() >= validUntilMonotonicNs) throw refused();
        if (!response.ready) throw dependencyUnavailable("managed evidence readiness refused safely");
        finished = true; clearTimeout(timer); resolve(Object.freeze({ validUntilMonotonicNs }));
      } catch (error) { cancel(error); }
      finally { if (!cancelled) { cancelled = true; try { wire!.cancel(); } catch { /* Retain until actual closure. */ } } }
    }, cancel);
    void wire.closed.then(() => { cancel(); release(); }, cancel);
    try { const at = check(); timer = setTimeout(cancel, Number((deadline - at + 999_999n) / 1_000_000n)); }
    catch { cancel(); }
    return Object.freeze({ result, closed, cancel });
  }
  /** Root owns the shared channel; this drain joins only this client's I/O. */
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.stopped = true;
    this.closing = Promise.all([...this.jobs].map(job => job.closed)).then(() => undefined);
    for (const job of this.jobs) job.cancel();
    return this.closing;
  }
  private sample(): bigint {
    try {
      const at = this.now();
      if (typeof at !== "bigint" || at < 0n || (this.lastTime !== undefined && at < this.lastTime)) throw refused();
      this.lastTime = at; return at;
    } catch { void this.close(); throw refused(); }
  }
}
