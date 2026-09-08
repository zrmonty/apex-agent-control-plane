import type { ManagedCallAuthorizationRequest, ManagedCallCompletionReceipt, ManagedPolicySnapshot } from "@apex/contracts";
import type { AuthorizationContext, BusinessDecision, BusinessExchange, BusinessTransportOptions } from "./business-types.js";
import { redactDependencyFailure } from "./dependency-failure.js";
import { authorizationContext, authorizationRequest, businessBinding, businessClassification, businessIdentifier,
  businessRefused, completionRequest, decodeAuthorization, decodeCompletion, decodePolicy, policyRequest } from "./business-codec.js";

const MAX_REQUEST_NS = 10_000_000_000n;
/** Uses the root's shared authenticated channel; never opens or closes that channel.
 * Returned metadata is not an execution capability. The physical call owner must
 * recheck selected SERVE and startDeadlineMonotonicNs immediately before work. */
export class AuthenticatedBusinessTransport {
  private readonly options: BusinessTransportOptions;
  private lastTime?: bigint;
  constructor(options: BusinessTransportOptions) {
    try {
      const { channel, monotonicNowNs } = options;
      if (typeof channel?.start !== "function" || typeof monotonicNowNs !== "function") throw businessRefused();
      this.options = Object.freeze({ channel, monotonicNowNs, binding: businessBinding(options.binding),
        policyId: businessIdentifier(options.policyId), evidenceAgentId: businessIdentifier(options.evidenceAgentId),
        dataClassification: businessClassification(options.dataClassification) });
    } catch { throw businessRefused(); }
  }
  startPolicy(nonce: string): BusinessExchange<ManagedPolicySnapshot> {
    try {
      const start = this.sample(), input = policyRequest(nonce, this.options.binding);
      return this.start("/apex.v1.ManagedRuntimeAuthority/GetManagedPolicy", input.payload, start,
        bytes => decodePolicy(bytes, this.options, input.expectedNonce));
    } catch (error) { throw redactDependencyFailure(error, "managed business refused safely"); }
  }
  startAuthorization(request: ManagedCallAuthorizationRequest, context: AuthorizationContext): BusinessExchange<BusinessDecision> {
    try {
      const timing = authorizationContext(context);
      this.check(timing.startedAtMonotonicNs, this.sample());
      const input = authorizationRequest(request, this.options);
      return this.start("/apex.v1.ManagedProxyGovernance/AuthorizeManagedCall", input.payload, timing.startedAtMonotonicNs,
        bytes => decodeAuthorization(bytes, this.options, timing, input.submittedRequest),
        decision => decision.outcome === "allowed" ? decision.startDeadlineMonotonicNs : undefined);
    } catch { throw businessRefused(); }
  }
  /** Caller must independently establish actual upstream cleanup before invoking.
   * Valid after grant closure/expiry; receipt is remote release, not stream cleanup. */
  startCompletion(admissionId: string, callId: string): BusinessExchange<ManagedCallCompletionReceipt> {
    try {
      const start = this.sample(), input = completionRequest(admissionId, callId, this.options.binding);
      return this.start("/apex.v1.ManagedRuntimeAuthority/CompleteManagedCall", input.payload, start,
        bytes => decodeCompletion(bytes, this.options.binding, input.admissionId, input.callId));
    } catch { throw businessRefused(); }
  }
  private start<T>(method: string, payload: Uint8Array, start: bigint, decode: (bytes: Uint8Array) => T,
    deadline?: (value: T) => bigint | undefined): BusinessExchange<T> {
    this.check(start, this.sample());
    const exchange = this.options.channel.start(method, payload);
    let resolve!: (value: T) => void, reject!: (error: Error) => void;
    const result = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
    let finished = false, cancelled = false, timer: ReturnType<typeof setTimeout> | undefined;
    const cancel = (cause?: unknown) => {
      if (!finished) { finished = true; clearTimeout(timer); reject(redactDependencyFailure(cause, "managed business refused safely")); }
      if (!cancelled) {
        cancelled = true;
        try { exchange.cancel(); } catch { /* Never leak a dependency diagnostic. Root retains channel ownership. */ }
      }
    };
    void exchange.result.then(bytes => {
      if (finished) return;
      try {
        this.check(start, this.sample());
        const value = decode(bytes);
        // A ready response callback can beat an overdue timer. Recheck AFTER
        // decoding against the unchanged original start, never remote wall time.
        const now = this.sample(); this.check(start, now);
        const end = deadline?.(value);
        if (end !== undefined && now >= end) throw businessRefused();
        finished = true; clearTimeout(timer); resolve(value);
      } catch { cancel(); }
    }, cancel);
    void exchange.closed.then(() => { if (!finished) cancel(); }, cancel);
    // Channel.start() itself may consume time. From here, failure returns the
    // exact owned exchange closure rather than throwing away physical ownership.
    try {
      const now = this.sample(); this.check(start, now);
      timer = setTimeout(cancel, Number((start + MAX_REQUEST_NS - now + 999_999n) / 1_000_000n));
    } catch { cancel(); }
    return Object.freeze({ result, closed: exchange.closed, cancel });
  }
  private check(start: bigint, now: bigint): void {
    if (start > now || now >= start + MAX_REQUEST_NS) throw businessRefused();
  }
  private sample(): bigint {
    try {
      const now = this.options.monotonicNowNs();
      if (typeof now !== "bigint" || now < 0n || (this.lastTime !== undefined && now < this.lastTime)) throw businessRefused();
      this.lastTime = now; return now;
    } catch { throw businessRefused(); }
  }
}
