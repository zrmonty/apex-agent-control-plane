import { constants, sensitiveHeaders, type ClientHttp2Session, type ClientHttp2Stream,
  type IncomingHttpHeaders, type IncomingHttpStatusHeader } from "node:http2";
import type { TLSSocket } from "node:tls";
import { dependencyUnavailable, ordinaryGrpcStatus } from "./dependency-failure.js";

export type UnaryExchange = Readonly<{
  result: Promise<Uint8Array>; closed: Promise<void>; cancel(): void;
}>;
export type WorkloadCredential = Readonly<{ token: string; instanceProof: Uint8Array }>;

const METHODS = new Set([
  "/apex.v1.ManagedRuntimeAuthority/RenewDeployment",
  "/apex.v1.ManagedRuntimeAuthority/GetManagedPolicy",
  "/apex.v1.ManagedRuntimeAuthority/CompleteManagedCall",
  "/apex.v1.ManagedProxyGovernance/AuthorizeManagedCall",
  "/apex.v1.ManagedNetworkReadiness/Check",
]);
const MAX_MESSAGE_BYTES = 65_536;
const MAX_STREAMS = 128;
const refused = () => new Error("managed authority refused safely");
type Job = { stream: ClientHttp2Stream; cancel(): void; closed: Promise<void> };

/** Narrow uncompressed protobuf unary gRPC, with public HTTP/2 physical ownership.
 * The root must supply an already verified, guarded, original-name TLS connection.
 * Stream closure proves LOCAL cleanup, never completion of a remote transaction. */
export class OwnedAuthorityChannel {
  private readonly jobs = new Set<Job>();
  private readonly token: string;
  private readonly proof: Buffer;
  private readonly physicallyClosed: Promise<void>;
  private stopped = false;
  private lastTime?: bigint;
  private closing?: Promise<void>;

  constructor(private readonly session: ClientHttp2Session, credential: WorkloadCredential,
    private readonly monotonicNowNs: () => bigint = process.hrtime.bigint) {
    const socket = session.socket as TLSSocket;
    const ownCertificate = socket.getCertificate?.();
    if (session.connecting || session.closed || session.destroyed || !socket.encrypted ||
      !socket.authorized || socket.alpnProtocol !== "h2" || !ownCertificate || !("raw" in ownCertificate) || !ownCertificate.raw?.length ||
      typeof credential.token !== "string" || !/^[A-Za-z0-9._~+\/-]{16,4096}={0,2}$/.test(credential.token) ||
      !(credential.instanceProof instanceof Uint8Array) || credential.instanceProof.length !== 32) throw refused();
    if (typeof monotonicNowNs !== "function") throw refused();
    this.token = credential.token;
    this.proof = Buffer.from(credential.instanceProof);
    this.physicallyClosed = Promise.all([
      new Promise<void>(done => session.once("close", done)),
      new Promise<void>(done => socket.once("close", () => done())),
    ]).then(() => { this.proof.fill(0); });
    // Both are terminal for this owner. The root may reconnect only after close.
    session.on("error", () => { void this.close(); });
    session.on("goaway", () => { void this.close(); });
  }

  start(method: string, payload: Uint8Array): UnaryExchange {
    if (this.stopped || this.session.closed || this.session.destroyed || this.jobs.size >= MAX_STREAMS ||
      !METHODS.has(method) || !(payload instanceof Uint8Array) || payload.length > MAX_MESSAGE_BYTES) throw refused();
    const started = this.sample();
    const frame = Buffer.alloc(5 + payload.length);
    frame.writeUInt32BE(payload.length, 1); frame.set(payload, 5);
    // request() either returns the owned stream or fails before returning a stream.
    // Every operation after that point runs under this job's catch/close boundary.
    const stream = this.session.request({
      ":method": "POST", ":path": method, "content-type": "application/grpc", te: "trailers",
      "grpc-timeout": "10000000u", "grpc-accept-encoding": "identity",
      authorization: `Bearer ${this.token}`, "apex-instance-proof-bin": this.proof.toString("base64"),
      [sensitiveHeaders]: ["authorization", "apex-instance-proof-bin"],
    });
    let resolve!: (value: Uint8Array) => void, reject!: (error: Error) => void, drain!: () => void;
    const result = new Promise<Uint8Array>((yes, no) => { resolve = yes; reject = no; });
    const closed = new Promise<void>(done => { drain = done; });
    let finished = false, response = false, trailers = false, bytes = 0;
    let ordinaryFailure = false;
    const readiness = method === "/apex.v1.ManagedNetworkReadiness/Check" || method === "/apex.v1.ManagedRuntimeAuthority/GetManagedPolicy";
    const chunks: Buffer[] = [];
    const settle = (value?: Uint8Array, ordinary = false) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (value) resolve(value); else reject(ordinary ? dependencyUnavailable("managed authority refused safely") : refused());
    };
    const cancel = () => {
      settle();
      // Logical failure never drains the owner; only the close event below does.
      try { stream.close(constants.NGHTTP2_CANCEL); } catch { void this.close(); }
    };
    const timer = setTimeout(cancel, 10_000);
    const job = { stream, cancel, closed };
    this.jobs.add(job);
    stream.once("close", () => {
      settle(); chunks.length = 0; frame.fill(0); this.jobs.delete(job); drain();
    });
    stream.on("error", cancel);
    stream.on("aborted", cancel);
    stream.on("response", (headers: IncomingHttpHeaders & IncomingHttpStatusHeader, _flags: number, raw: string[]) => {
      if (response || !unique(raw) || headers[":status"] !== 200 ||
        !["application/grpc", "application/grpc+proto"].includes(String(headers["content-type"])) ||
        (headers["grpc-encoding"] !== undefined && headers["grpc-encoding"] !== "identity")) { cancel(); return; }
      response = true;
      // Tonic may return an error as trailers-only initial HEADERS. Require
      // canonical status and an entirely empty body before marking it ordinary.
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
      if (!response || trailers || bytes > MAX_MESSAGE_BYTES + 5) { cancel(); return; }
      chunks.push(chunk);
    });
    stream.on("end", () => {
      if (finished) return;
      // An overdue timer can run after this callback. Only the original local
      // monotonic deadline decides whether success may still be reported.
      try { if (this.sample() - started >= 10_000_000_000n) { cancel(); return; } }
      catch { cancel(); void this.close(); return; }
      if (ordinaryFailure && response && trailers && bytes === 0) { settle(undefined, true); cancel(); return; }
      const body = Buffer.concat(chunks, bytes);
      if (!response || !trailers || body.length < 5 || body[0] !== 0 || body.readUInt32BE(1) !== body.length - 5) {
        cancel(); return;
      }
      settle(Buffer.from(body.subarray(5)));
    });
    try { stream.end(frame); } catch { cancel(); }
    return Object.freeze({ result, closed, cancel });
  }

  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.stopped = true;
    this.closing = Promise.all([this.physicallyClosed, ...Array.from(this.jobs, job => job.closed)]).then(() => undefined);
    for (const job of this.jobs) job.cancel();
    // Tear down only this owned channel. Await both HTTP/2 and actual TLS closure.
    this.session.destroy();
    return this.closing;
  }

  private sample(): bigint {
    try {
      const now = this.monotonicNowNs();
      if (typeof now !== "bigint" || now < 0n || (this.lastTime !== undefined && now < this.lastTime)) throw refused();
      this.lastTime = now;
      return now;
    } catch { void this.close(); throw refused(); }
  }
}

function unique(raw: readonly string[]): boolean {
  const names = new Set<string>();
  for (let index = 0; index < raw.length; index += 2) {
    const name = raw[index].toLowerCase();
    if (names.has(name)) return false;
    names.add(name);
  }
  return true;
}
