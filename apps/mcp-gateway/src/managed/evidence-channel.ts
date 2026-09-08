import { constants, sensitiveHeaders, type ClientHttp2Session, type ClientHttp2Stream,
  type IncomingHttpHeaders, type IncomingHttpStatusHeader } from "node:http2";
import type { TLSSocket } from "node:tls";
import type { UnaryExchange } from "./authority/unary.js";
import { dependencyUnavailable, ordinaryGrpcStatus } from "./authority/dependency-failure.js";
type Job = { cancel(): void; closed: Promise<void> };
const refused = () => new Error("managed evidence refused safely");

/** Already verified guarded evidence H2/mTLS only. Constructor is not provenance.
 * A successful gRPC reply is interpreted by the typed EventIngest client. */
export class OwnedEvidenceChannel {
  private readonly jobs = new Set<Job>();
  private readonly physical: Promise<void>;
  private physicalClosed = false;
  private incoming = 0;
  private drain?: () => void;
  private stopped = false;
  private lastTime?: bigint;
  private closing?: Promise<void>;
  constructor(private readonly session: ClientHttp2Session, private readonly token: string,
    private readonly now: () => bigint = process.hrtime.bigint) {
    const socket = session.socket as TLSSocket, own = socket.getCertificate?.();
    if (session.connecting || session.closed || session.destroyed || !socket.encrypted || !socket.authorized ||
      socket.alpnProtocol !== "h2" || !own || !("raw" in own) || !own.raw?.length || typeof now !== "function" ||
      typeof token !== "string" || !/^[A-Za-z0-9._~+\/-]{16,4096}={0,2}$/.test(token)) throw refused();
    this.physical = Promise.all([new Promise<void>(done => session.once("close", done)),
      new Promise<void>(done => socket.once("close", () => done()))]).then(() => undefined);
    void this.physical.then(() => { this.physicalClosed = true; this.finishClose(); });
    session.on("error", () => { void this.close(); }); session.on("goaway", () => { void this.close(); });
    // Install ownership before SETTINGS: pushes can already be queued while
    // the peer still permits push. Never read/buffer their bodies or reuse root.
    session.on("stream", (stream: ClientHttp2Stream) => {
      this.incoming++; this.stopped = true;
      stream.on("error", () => { void this.close(); });
      stream.once("close", () => { this.incoming--; this.finishClose(); });
      stream.destroy(); void this.close();
    });
    try { session.settings({ enablePush: false }, error => { if (error) void this.close(); }); }
    catch { void this.close(); }
  }
  start(payload: Uint8Array, started: bigint, overallDeadline: bigint): UnaryExchange {
    return this.startFixed(payload, started, overallDeadline, false);
  }
  /** Same authenticated evidence owner, distinct fixed RPC; never submits an event. */
  startReadiness(payload: Uint8Array, started: bigint, overallDeadline: bigint): UnaryExchange {
    return this.startFixed(payload, started, overallDeadline, true);
  }
  private startFixed(payload: Uint8Array, started: bigint, overallDeadline: bigint, readiness: boolean): UnaryExchange {
    const budget = readiness ? 2_000_000_000n : 5_000_000_000n;
    if (this.stopped || this.jobs.size >= 32 || this.session.closed || this.session.destroyed ||
      !(payload instanceof Uint8Array) || payload.length > (readiness ? 1024 : 65_536) || typeof started !== "bigint" || started < 0n ||
      typeof overallDeadline !== "bigint") throw refused();
    const current = this.sample(), deadline = overallDeadline < started + budget ? overallDeadline : started + budget;
    if (this.stopped || current < started || current >= deadline) throw refused();
    const frame = Buffer.alloc(5 + payload.length); frame.writeUInt32BE(payload.length, 1); frame.set(payload, 5);
    let stream: ClientHttp2Stream;
    try {
      stream = this.session.request({ ":method": "POST", ":path": readiness ?
        "/apex.v1.EvidenceAdmissionReadiness/Check" : "/apex.v1.EventIngest/Ingest",
        "content-type": "application/grpc", te: "trailers", "grpc-accept-encoding": "identity",
        "grpc-timeout": `${(deadline - current + 999n) / 1000n}u`, authorization: `Bearer ${this.token}`,
        [sensitiveHeaders]: ["authorization"],
      });
    } catch { frame.fill(0); throw refused(); }
    let resolve!: (value: Uint8Array) => void, reject!: (error: Error) => void, drain!: () => void;
    const result = new Promise<Uint8Array>((yes, no) => { resolve = yes; reject = no; });
    const closed = new Promise<void>(done => { drain = done; });
    const chunks: Buffer[] = [];
    let finished = false, response = false, trailers = false, bytes = 0;
    let ordinaryFailure = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const settle = (value?: Uint8Array, ordinary = false) => {
      if (finished) return; finished = true; clearTimeout(timer);
      if (value !== undefined) resolve(value); else reject(ordinary ? dependencyUnavailable("managed evidence refused safely") : refused());
    };
    const cancel = () => { settle(); try { stream.close(constants.NGHTTP2_CANCEL); } catch { void this.close(); } };
    const check = () => { if (this.stopped || finished || this.sample() >= deadline) throw refused(); };
    const job = { cancel, closed }; this.jobs.add(job);
    stream.once("close", () => {
      settle(); frame.fill(0); for (const chunk of chunks) chunk.fill(0); chunks.length = 0;
      this.jobs.delete(job); drain(); this.finishClose();
    });
    stream.on("error", cancel); stream.on("aborted", cancel);
    stream.on("response", (headers: IncomingHttpHeaders & IncomingHttpStatusHeader, _flags: number, raw: string[]) => {
      if (response || !unique(raw) || headers[":status"] !== 200 ||
        !["application/grpc", "application/grpc+proto"].includes(String(headers["content-type"])) ||
        (headers["grpc-encoding"] !== undefined && headers["grpc-encoding"] !== "identity")) { cancel(); return; }
      response = true;
      if (headers["grpc-status"] !== undefined) {
        if (!readiness || !ordinaryGrpcStatus(headers["grpc-status"])) { cancel(); return; }
        ordinaryFailure = true; trailers = true;
      }
    });
    stream.on("trailers", (headers: IncomingHttpHeaders, _flags: number, raw: string[]) => {
      if (!response || trailers || !unique(raw)) { cancel(); return; }
      if (headers["grpc-status"] !== "0") {
        if (!readiness || bytes !== 0 || !ordinaryGrpcStatus(headers["grpc-status"])) { cancel(); return; }
        ordinaryFailure = true;
      }
      trailers = true;
    });
    stream.on("data", (chunk: Buffer) => {
      if (finished) return;
      bytes += chunk.length;
      if (!response || trailers || bytes > (readiness ? 1029 : 8197)) { cancel(); return; }
      chunks.push(Buffer.from(chunk));
    });
    stream.on("end", () => {
      if (finished) return;
      try {
        check();
        if (ordinaryFailure && response && trailers && bytes === 0) { settle(undefined, true); cancel(); return; }
        const body = Buffer.concat(chunks, bytes);
        try {
          if (!response || !trailers || body.length < 5 || body[0] !== 0 || body.readUInt32BE(1) !== body.length - 5) throw refused();
          check(); settle(Buffer.from(body.subarray(5)));
        } finally { body.fill(0); }
      } catch { cancel(); }
    });
    try {
      check(); const remaining = deadline - this.sample(); if (remaining <= 0n) throw refused();
      timer = setTimeout(cancel, Number((remaining + 999_999n) / 1_000_000n));
      check(); stream.end(frame);
    } catch { cancel(); }
    return Object.freeze({ result, closed, cancel });
  }
  close(): Promise<void> {
    if (this.closing) return this.closing; this.stopped = true;
    this.closing = new Promise<void>(done => { this.drain = done; });
    for (const job of this.jobs) job.cancel(); this.session.destroy(); this.finishClose(); return this.closing;
  }
  private finishClose(): void {
    // Native push events queued before destroy can arrive after close() starts.
    // Keep accounting live until both root receipts AND all stream receipts.
    if (this.physicalClosed && this.jobs.size === 0 && this.incoming === 0) this.drain?.();
  }
  private sample(): bigint {
    try {
      const now = this.now();
      if (typeof now !== "bigint" || now < 0n || (this.lastTime !== undefined && now < this.lastTime)) throw refused();
      this.lastTime = now; return now;
    } catch { void this.close(); throw refused(); }
  }
}
function unique(raw: readonly string[]): boolean {
  const names = new Set<string>();
  for (let i = 0; i < raw.length; i += 2) { const name = raw[i].toLowerCase(); if (names.has(name)) return false; names.add(name); }
  return true;
}
