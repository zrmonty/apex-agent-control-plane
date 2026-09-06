import type { PreparedEvidence } from "./types.js";
import type { OwnedEvidenceChannel } from "../evidence-channel.js";
import type { BusinessExchange } from "../authority/business-types.js";
import { fromBinary, toBinary } from "@bufbuild/protobuf";
import { IngestResponseSchema } from "@apex/contracts/event";
import { evidenceBytes } from "./builder.js";
export type EvidenceReceipt = Readonly<{ eventId: string; eventHash: string; duplicate: boolean }>;
const refused = () => new Error("managed event admission refused safely");
type Job = { cancel(): void; closed: Promise<void> };
export class ManagedEvidenceClient {
  private readonly jobs = new Set<Job>();
  private stopped = false;
  private lastTime?: bigint;
  private closing?: Promise<void>;
  constructor(private readonly channel: Pick<OwnedEvidenceChannel, "start">,
    private readonly now: () => bigint = process.hrtime.bigint) {
    if (typeof channel?.start !== "function" || typeof now !== "function") throw refused();
  }
  start(evidence: PreparedEvidence, started: bigint, overallDeadline: bigint): BusinessExchange<EvidenceReceipt> {
    if (this.stopped || this.jobs.size >= 32 || typeof started !== "bigint" || started < 0n ||
      typeof overallDeadline !== "bigint") throw refused();
    let bytes: Uint8Array;
    try { bytes = evidenceBytes(evidence); } catch { throw refused(); }
    const deadline = overallDeadline < started + 5_000_000_000n ? overallDeadline : started + 5_000_000_000n;
    let resolve!: (receipt: EvidenceReceipt) => void, reject!: (error: Error) => void, drain!: () => void;
    const result = new Promise<EvidenceReceipt>((yes, no) => { resolve = yes; reject = no; });
    // A trusted synchronous dependency may reenter close() before start returns.
    void result.catch(() => {});
    const closed = new Promise<void>(done => { drain = done; });
    let wire: ReturnType<OwnedEvidenceChannel["start"]> | undefined;
    let finished = false, cancelled = false, timer: ReturnType<typeof setTimeout> | undefined;
    const cancel = () => {
      if (!finished) { finished = true; clearTimeout(timer); reject(refused()); }
      if (wire && !cancelled) { cancelled = true; try { wire.cancel(); } catch { /* Physical closure still owns the slot. */ } }
    };
    const job = { cancel, closed }; this.jobs.add(job);
    const release = () => { bytes.fill(0); this.jobs.delete(job); drain(); };
    const check = () => {
      const at = this.sample();
      if (this.stopped || finished || at < started || at >= deadline) throw refused();
      return at;
    };
    try { check(); wire = this.channel.start(bytes, started, deadline); }
    catch { cancel(); release(); throw refused(); }
    // No failure after channel.start may discard its physical ownership.
    void wire.result.then(payload => {
      if (finished) return;
      try {
        check();
        if (!(payload instanceof Uint8Array) || payload.length > 8192) throw refused();
        const decoded = fromBinary(IngestResponseSchema, payload, { readUnknownFields: false });
        if (!Buffer.from(toBinary(IngestResponseSchema, decoded)).equals(payload)) throw refused();
        check(); finished = true; clearTimeout(timer);
        resolve(Object.freeze({ eventId: evidence.eventId, eventHash: evidence.eventHash, duplicate: decoded.duplicate }));
      } catch { cancel(); }
      finally { if (!cancelled) { cancelled = true; try { wire!.cancel(); } catch { /* Retain ownership. */ } } }
    }, cancel);
    void wire.closed.then(() => { cancel(); release(); }, cancel);
    try { const at = check(); timer = setTimeout(cancel, Number((deadline - at + 999_999n) / 1_000_000n)); }
    catch { cancel(); }
    return Object.freeze({ result, closed, cancel });
  }
  /** Stops only this typed owner; the root owns the shared evidence channel. */
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.stopped = true;
    this.closing = Promise.all([...this.jobs].map(job => job.closed)).then(() => undefined);
    for (const job of this.jobs) job.cancel();
    return this.closing;
  }
  private sample(): bigint {
    try {
      const value = this.now();
      if (typeof value !== "bigint" || value < 0n || (this.lastTime !== undefined && value < this.lastTime)) throw refused();
      this.lastTime = value; return value;
    } catch { void this.close(); throw refused(); }
  }
}
