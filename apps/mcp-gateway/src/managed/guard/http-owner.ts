import type { GuardedTlsConnector } from "./tls-connector.js";
import { Agent, request as nativeRequest } from "node:https";
import type { ClientRequest, IncomingMessage, OutgoingHttpHeaders } from "node:http";
import { checkServerIdentity } from "node:tls";
import { types } from "node:util";

export type OwnedHttpResponse = Readonly<{ status: number; contentType: string;
  sessionId?: string; body: AsyncIterable<Uint8Array> }>;
export type OwnedHttpExchange = Readonly<{ result: Promise<OwnedHttpResponse>;
  closed: Promise<void>; cancel(): void }>;
export type OwnedHttpRequest = Readonly<{ method: "POST" | "GET" | "DELETE";
  body?: Uint8Array; sessionId?: string; protocolVersion?: string; lastEventId?: string;
  startedAtMonotonicNs: bigint; deadlineMonotonicNs: bigint; beforeWrite(): void }>;
const refused = () => new Error("managed HTTP refused safely");
type Job = { cancel(): void; closed: Promise<void> };

/** One native HTTP/1 request per owned guarded connection. No shared agent or
 * implicit business replay. Protected composition must bind endpoint to its
 * enrolled connector destination, and supply a synchronous authority gate. */
export class OwnedHttpClient {
  private readonly url: URL;
  private readonly destinationId: string;
  private readonly token?: string;
  private readonly jobs = new Set<Job>();
  private stopped = false;
  private closing?: Promise<void>;
  private lastTime?: bigint;

  constructor(private readonly connector: Pick<GuardedTlsConnector, "open">,
    endpoint: Readonly<{ destinationId: string; url: string; bearerToken?: string }>,
    private readonly now: () => bigint = process.hrtime.bigint) {
    try {
      if (typeof endpoint.url !== "string" || endpoint.url.length > 2048 ||
        !/^[A-Za-z0-9._-]{1,128}$/.test(endpoint.destinationId) || typeof now !== "function") throw refused();
      const url = new URL(endpoint.url);
      if (url.protocol !== "https:" || url.username || url.password || url.hash ||
        (endpoint.bearerToken !== undefined && !/^[A-Za-z0-9._~+\/-]{16,4096}={0,2}$/.test(endpoint.bearerToken))) throw refused();
      this.url = url; this.destinationId = endpoint.destinationId; this.token = endpoint.bearerToken;
    } catch { throw refused(); }
  }

  start(input: OwnedHttpRequest): OwnedHttpExchange {
    if (this.stopped || this.jobs.size >= 128) throw refused();
    const current = this.sample(), started = input.startedAtMonotonicNs, deadline = input.deadlineMonotonicNs;
    const method = input.method, beforeWrite = input.beforeWrite;
    if (typeof started !== "bigint" || started < 0n || started > current || typeof deadline !== "bigint" ||
      deadline <= current || deadline - started > 120_000_000_000n || typeof beforeWrite !== "function" ||
      !["POST", "GET", "DELETE"].includes(method) ||
      (input.body !== undefined && (!(input.body instanceof Uint8Array) || input.body.length > 262_144 || method !== "POST"))) throw refused();
    const body = input.body === undefined ? Buffer.alloc(0) : Buffer.from(input.body);
    const headers: OutgoingHttpHeaders = { accept: "application/json, text/event-stream", connection: "close" };
    if (method === "POST") { headers["content-type"] = "application/json"; headers["content-length"] = body.length; }
    for (const [name, value] of [["mcp-session-id", input.sessionId], ["mcp-protocol-version", input.protocolVersion],
      ["last-event-id", input.lastEventId]] as const) {
      if (value !== undefined) { headerValue(value); headers[name] = value; }
    }
    if (this.token !== undefined) headers.authorization = `Bearer ${this.token}`;
    let connection;
    try { connection = this.connector.open(this.destinationId, started); } catch { throw refused(); }
    let req: ClientRequest | undefined, response: IncomingMessage | undefined, agent: Agent | undefined;
    let cancelled = false, failed = false, settled = false, connectionDone = false, requestDone = true, responseDone = true;
    let resolve!: (value: OwnedHttpResponse) => void, reject!: (error: Error) => void, drain!: () => void;
    const result = new Promise<OwnedHttpResponse>((yes, no) => { resolve = yes; reject = no; });
    const closed = new Promise<void>(done => { drain = done; });
    const stop = (failure: boolean) => {
      failed ||= failure; cancelled = true; clearTimeout(timer);
      if (!settled) { settled = true; reject(refused()); }
      response?.destroy(); req?.destroy(); agent?.destroy(); connection.cancel();
    };
    const cancel = () => stop(true);
    const finish = () => {
      if (!connectionDone || !requestDone || !responseDone) return;
      stop(false); body.fill(0); this.jobs.delete(job); drain();
    };
    const check = () => {
      if (cancelled || this.stopped || this.sample() >= deadline) throw refused();
    };
    const timer = setTimeout(cancel, Number((deadline - current + 999_999n) / 1_000_000n));
    const job = { cancel, closed }; this.jobs.add(job);
    void connection.closed.then(() => {
      connectionDone = true;
      // A complete IncomingMessage can still own unread buffered bytes. Normal
      // transport closure must not destroy it (Node would emit "aborted"). Keep
      // its ownership and original timer until consumption/close or cancellation.
      if (!response?.complete || response.aborted) cancel();
      finish();
    });
    void connection.result.then(socket => {
      try {
        check();
        if (!socket.authorized || socket.alpnProtocol !== "http/1.1" ||
          checkServerIdentity(this.url.hostname.replace(/^\[|\]$/g, ""), socket.getPeerCertificate())) throw refused();
        agent = new Agent({ keepAlive: false, maxSockets: 1, maxCachedSessions: 0 });
        // The already prepared and verified socket is the only connection this
        // one-request agent can acquire. No inherited Agent connect/DNS path.
        agent.createConnection = () => socket;
        req = nativeRequest(this.url, { method, headers, agent, maxHeaderSize: 16_384 });
        requestDone = false;
        req.on("error", cancel);
        req.once("close", () => { requestDone = true; finish(); });
        req.on("upgrade", (_reply, upgraded) => { upgraded.destroy(); cancel(); });
        req.on("information", cancel);
        req.once("response", incoming => {
          response = incoming; responseDone = false;
          incoming.on("error", cancel); incoming.once("aborted", cancel);
          incoming.once("close", () => { responseDone = true; stop(!incoming.complete || incoming.aborted); finish(); });
          try {
            check();
            if (!incoming.statusCode || incoming.statusCode >= 300 || incoming.statusCode < 200 ||
              !unique(incoming.rawHeaders) || incoming.headers["content-encoding"] !== undefined) throw refused();
            const contentType = incoming.headers["content-type"] ?? "";
            const sessionId = incoming.headers["mcp-session-id"];
            if (typeof contentType !== "string" || contentType.length > 256 ||
              (sessionId !== undefined && typeof sessionId !== "string")) throw refused();
            if (sessionId !== undefined) headerValue(sessionId);
            let consumed = false;
            const iterable = { async *[Symbol.asyncIterator]() {
              if (consumed || failed || thisOwner.stopped) throw refused(); consumed = true;
              let bytes = 0;
              try {
                for await (const chunk of incoming) {
                  // Completed bodies may close physically before the consumer
                  // reads the final buffered chunk; clock, not cancel, applies.
                  if (failed || thisOwner.stopped || thisOwner.sample() >= deadline) throw refused();
                  bytes += chunk.length; if (bytes > 1_048_576) throw refused();
                  yield Buffer.from(chunk);
                }
                if (!incoming.complete || failed || thisOwner.stopped || thisOwner.sample() >= deadline) throw refused();
              } catch { failed = true; throw refused(); } finally { stop(!incoming.complete || failed); }
            } };
            const thisOwner = this;
            settled = true; resolve(Object.freeze({ status: incoming.statusCode, contentType, sessionId, body: iterable }));
          } catch { cancel(); }
        });
        req.once("socket", assigned => {
          try {
            // Node assigns even a prepared socket on a later turn. Do not call
            // end until this event: it would otherwise buffer an ungated write.
            if (assigned !== socket || socket.connecting || socket.destroyed) throw refused();
            check();
            const gateResult = beforeWrite();
            if (gateResult !== undefined) {
              // Contain mistaken async-gate rejection without treating it as
              // permission or leaking a private unhandled rejection.
              if (types.isPromise(gateResult)) void Promise.prototype.then.call(gateResult, undefined, () => {});
              throw refused();
            }
            // No await, flushHeaders or write between the gate and native end.
            check(); req!.end(body);
          } catch { cancel(); }
        });
      } catch { cancel(); }
    }, cancel);
    return Object.freeze({ result, closed, cancel });
  }

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

function headerValue(value: string): void {
  if (typeof value !== "string" || !/^[\x21-\x7e]{1,256}$/.test(value)) throw refused();
}
function unique(raw: readonly string[]): boolean {
  const names = new Set<string>();
  for (let i = 0; i < raw.length; i += 2) { const name = raw[i].toLowerCase(); if (names.has(name)) return false; names.add(name); }
  return true;
}
