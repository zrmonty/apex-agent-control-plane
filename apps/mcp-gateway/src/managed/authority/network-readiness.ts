import type { OwnedAuthorityChannel } from "./unary.js";
import type { DeploymentBinding } from "./types.js";
import { readBinding, wireBinding } from "./grant-transport.js";
import { nonce as digest } from "./binding.js";
import type { BusinessExchange } from "./business-types.js";
import { randomBytes } from "node:crypto";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { RuntimeNetworkInspectionRequestSchema as Request, RuntimeNetworkInspectionResponseSchema as Response } from "@apex/contracts";
import { businessBinding } from "./business-codec.js";
import { assertDataTree } from "../runtime-config/boundary.js";
import { redactDependencyFailure } from "./dependency-failure.js";
export type NetworkObservation = Readonly<{ validUntilMonotonicNs: bigint }>;
const refused = () => new Error("managed network readiness refused safely");
type Job = { closed: Promise<void>; cancel(): void };
/** Non-admitting network observation via the authenticated control-plane relay.
 * Root supplies the exact protected stage binding/hash and already owned channel.
 * This client never calls the host agent or infers confinement from connectivity. */
export class NetworkReadinessClient {
  private readonly binding: DeploymentBinding;
  private readonly jobs = new Set<Job>();
  private stopped = false;
  private lastTime?: bigint;
  private closing?: Promise<void>;
  constructor(binding: DeploymentBinding, private readonly networkHash: string,
    private readonly channel: Pick<OwnedAuthorityChannel, "start">,
    private readonly now: () => bigint = process.hrtime.bigint) {
    try {
      assertDataTree(binding, true); this.binding = businessBinding(binding);
      if (!digest(networkHash) || typeof channel?.start !== "function" || typeof now !== "function") throw refused();
    } catch { throw refused(); }
  }
  start(started: bigint, overallDeadline: bigint): BusinessExchange<NetworkObservation> {
    if (this.stopped || this.jobs.size >= 4 || typeof started !== "bigint" || started < 0n ||
      typeof overallDeadline !== "bigint") throw refused();
    const deadline = overallDeadline < started + 2_000_000_000n ? overallDeadline : started + 2_000_000_000n;
    const nonce = randomBytes(32), bytes = toBinary(Request, create(Request, { binding: wireBinding(this.binding), schemaVersion: 1, nonce }));
    let resolve!: (value: NetworkObservation) => void, reject!: (error: Error) => void, drain!: () => void;
    const result = new Promise<NetworkObservation>((yes, no) => { resolve = yes; reject = no; });
    void result.catch(() => {});
    const closed = new Promise<void>(done => { drain = done; });
    let wire: ReturnType<OwnedAuthorityChannel["start"]> | undefined;
    let finished = false, cancelled = false, timer: ReturnType<typeof setTimeout> | undefined;
    const cancel = (cause?: unknown) => {
      if (!finished) { finished = true; clearTimeout(timer); reject(redactDependencyFailure(cause, "managed network readiness refused safely")); }
      if (wire && !cancelled) { cancelled = true; try { wire.cancel(); } catch { /* Still physically owned. */ } }
    };
    const job = { cancel, closed }; this.jobs.add(job);
    const release = () => { bytes.fill(0); nonce.fill(0); this.jobs.delete(job); drain(); };
    const check = () => {
      const at = this.sample();
      if (this.stopped || finished || at < started || at >= deadline) throw refused();
      return at;
    };
    try { check(); wire = this.channel.start("/apex.v1.ManagedNetworkReadiness/Check", bytes); }
    catch (error) { cancel(error); release(); throw redactDependencyFailure(error, "managed network readiness refused safely"); }
    // Once the channel hands off I/O, logical refusal never releases its slot.
    void wire.result.then(payload => {
      if (finished) return;
      try {
        check();
        if (!(payload instanceof Uint8Array) || payload.length > 4096) throw refused();
        const response = fromBinary(Response, payload, { readUnknownFields: false });
        if (!Buffer.from(toBinary(Response, response)).equals(payload) || response.schemaVersion !== 1 ||
          !nonce.equals(response.nonce) || response.networkBindingSha256 !== this.networkHash ||
          !digest(response.gatewayProcessSha256) || !digest(response.guardProcessSha256) ||
          !response.confined || response.validForUs <= 0n || response.validForUs > 10_000_000n) throw refused();
        const actual = readBinding(response.binding);
        if ((Object.keys(this.binding) as (keyof DeploymentBinding)[]).some(key => actual[key] !== this.binding[key])) throw refused();
        const validUntilMonotonicNs = started + response.validForUs * 1000n;
        if (check() >= validUntilMonotonicNs) throw refused();
        finished = true; clearTimeout(timer); resolve(Object.freeze({ validUntilMonotonicNs }));
      } catch { cancel(); }
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
