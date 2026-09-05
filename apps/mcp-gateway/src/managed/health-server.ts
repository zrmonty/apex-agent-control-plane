import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { Socket } from "node:net";
import { authenticates, copyToken, healthError } from "../health/token.js";
import { HeaderCapture, uniqueHeaders } from "../health/envelope.js";
import type { Clock } from "../telemetry/clock.js";
import type { ReadinessMonitor } from "./readiness.js";
import type { ReadinessReportCodec } from "./readiness/report-codec.js";

export type HealthServer = Readonly<{ close(): Promise<void> }>;
export type HealthServerInput = Readonly<{
  codec: ReadinessReportCodec; state: Pick<ReadinessMonitor, "snapshot">;
  tokenBytes: Uint8Array; clock: Clock; onFatal(): void;
}>;

type Connection = {
  header: HeaderCapture; claimed: boolean; rejected: boolean;
  deadline?: bigint; last?: bigint; timer?: NodeJS.Timeout;
  retiring?: boolean; cleanupStart?: bigint; cleanupTimer?: NodeJS.Timeout;
};

/** Transport only. The trusted owner supplies the same authenticated/current
 * launch's codec, monitor and dedicated token. Callbacks must not block; neither
 * a timer nor this library can preempt a blocked event loop or kernel operation. */
export async function startHealthServer(input: HealthServerInput): Promise<HealthServer> {
  const token = copyToken(input.tokenBytes);
  let snapshot: HealthServerInput["state"]["snapshot"], encode: ReadinessReportCodec["encode"], now: Clock["now"], fatal: () => void;
  try {
    snapshot = input.state.snapshot.bind(input.state); encode = input.codec.encode.bind(input.codec);
    now = input.clock.now.bind(input.clock); fatal = input.onFatal.bind(input);
  } catch { token.fill(0); throw healthError(); }
  const sockets = new Map<Socket, Connection>();
  let closed = false, listenerClosed = false, settled = false, fatalCalled = false;
  let closing: Promise<void> | undefined, closedOk: () => void, closedBad: (error: Error) => void;
  let cleanupTimer: NodeJS.Timeout | undefined, cleanupStart: bigint | undefined;
  function sample(): bigint {
    const value = now().monotonicNs;
    if (typeof value !== "bigint" || value < 0n) throw healthError();
    return value;
  }
  function failedTeardown(): void { void close(); completeClose(true); }
  function retire(socket: Socket): void {
    const entry = sockets.get(socket);
    if (entry && !entry.retiring) {
      entry.retiring = true; entry.rejected = true;
      clearTimeout(entry.timer); entry.header.clear();
      entry.cleanupTimer = setTimeout(failedTeardown, 5000);
      try { entry.cleanupStart = sample(); } catch { /* Native grace remains bounded. */ }
    }
    socket.destroy();
  }
  function usable(socket: Socket, entry: Connection): boolean {
    if (closed || entry.rejected || socket.destroyed || entry.deadline === undefined) return false;
    try {
      const ns = sample();
      // Sampling itself is a trusted callback and may synchronously close us.
      if (closed || entry.rejected || socket.destroyed || ns < entry.last! || ns >= entry.deadline) throw healthError();
      entry.last = ns; return true;
    } catch { retire(socket); return false; }
  }
  function completeClose(failed = false): void {
    if (!closing || settled || (!failed && (!listenerClosed || sockets.size !== 0))) return;
    if (!failed && cleanupStart !== undefined) {
      try { failed = sample() - cleanupStart >= 5000000000n; } catch { /* Actual close events still prove termination. */ }
    }
    // Reentrant fatal/clock hooks must see the terminal latch and same promise.
    settled = true; clearTimeout(cleanupTimer); token.fill(0);
    for (const entry of sockets.values()) {
      clearTimeout(entry.timer); clearTimeout(entry.cleanupTimer); entry.header.clear();
    }
    if (failed) {
      if (!fatalCalled) { fatalCalled = true; try { fatal(); } catch { /* Static bounded rejection only. */ } }
      closedBad(healthError());
    } else closedOk();
  }
  function close(): Promise<void> {
    if (closing) return closing;
    closed = true;
    closing = new Promise<void>((resolve, reject) => { closedOk = resolve; closedBad = reject; });
    // Preserve the rejection for the caller, including automatic error cleanup.
    void closing.catch(() => {});
    cleanupTimer = setTimeout(() => completeClose(true), 5000);
    try { cleanupStart = sample(); } catch { /* Native timer still bounds cleanup. */ }
    server.close(() => { listenerClosed = true; completeClose(); });
    for (const socket of sockets.keys()) retire(socket);
    completeClose();
    return closing;
  }
  function empty(response: ServerResponse, status: number): void {
    const socket = response.socket;
    const entry = socket && sockets.get(socket);
    if (!socket || !entry || !usable(socket, entry)) { if (socket) retire(socket); return; }
    response.sendDate = false;
    response.writeHead(status, { "Content-Length": "0", "Cache-Control": "no-store", Connection: "close" }); response.end();
  }
  const server = createServer({ maxHeaderSize: 4096, insecureHTTPParser: false, requireHostHeader: true,
    headersTimeout: 2000, requestTimeout: 2000 }, (request, response) => {
    const entry = sockets.get(request.socket);
    if (!entry || entry.claimed || !usable(request.socket, entry)) { retire(request.socket); return; }
    entry.claimed = true;
    response.on("error", () => retire(request.socket));
    response.once("finish", () => { if (!usable(request.socket, entry)) retire(request.socket); });
    const headers = entry.header.fields;
    if (!entry.header.complete || entry.header.invalid || entry.header.bodyBytes !== 0 || !uniqueHeaders(request.rawHeaders) ||
      request.httpVersion !== "1.1" || headers.get("host") !== "127.0.0.1:8081" ||
      ["transfer-encoding", "trailer", "expect", "upgrade"].some(name => headers.has(name)) ||
      (headers.has("content-length") && headers.get("content-length") !== "0")) { empty(response, 400); return; }
    if (!authenticates(headers.get("authorization"), token)) { empty(response, 401); return; }
    if (request.method !== "GET") { empty(response, 405); return; }
    if (request.url !== "/livez" && request.url !== "/readyz") { empty(response, 404); return; }
    try {
      if (!usable(request.socket, entry)) return;
      const report = snapshot();
      if (!usable(request.socket, entry)) return;
      const body = encode(report);
      if (!usable(request.socket, entry)) return;
      if (typeof body !== "string" || Buffer.byteLength(body, "utf8") > 8192) throw healthError();
      const status = (request.url === "/livez" ? report.live : report.ready) ? 200 : 503;
      if (!usable(request.socket, entry)) return;
      response.sendDate = false;
      response.writeHead(status,
        { "Content-Type": "application/json", "Cache-Control": "no-store", "Content-Length": Buffer.byteLength(body), Connection: "close" });
      response.end(body);
    } catch { empty(response, 503); }
  });
  server.maxHeadersCount = 0;
  server.maxConnections = 8; server.maxRequestsPerSocket = 1;
  server.on("connection", socket => {
    if (closed || sockets.size >= 8) { socket.destroy(); return; }
    const entry: Connection = { header: new HeaderCapture(), claimed: false, rejected: false };
    sockets.set(socket, entry); // Own before entering the first clock callback.
    socket.on("error", () => {});
    const capture = (chunk: Buffer) => {
      if (!usable(socket, entry)) { retire(socket); return; }
      entry.header.accept(chunk);
      // Refuse before Node's automatic missing-Host response can add a body.
      if (entry.header.complete && !entry.header.fields.has("host")) { retire(socket); return; }
      if (entry.header.invalid) {
        entry.rejected = true;
        socket.end("HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
      }
      if (entry.claimed && entry.header.bodyBytes !== 0) retire(socket);
    };
    socket.prependListener("data", capture);
    socket.once("close", () => {
      if (entry.cleanupStart !== undefined) {
        try { if (sample() - entry.cleanupStart >= 5000000000n) failedTeardown(); } catch { /* No raw clock errors. */ }
      }
      clearTimeout(entry.timer); clearTimeout(entry.cleanupTimer); entry.header.clear(); socket.removeListener("data", capture);
      sockets.delete(socket); completeClose();
    });
    entry.timer = setTimeout(() => retire(socket), 2000);
    try { entry.last = sample(); entry.deadline = entry.last + 2000000000n; }
    catch { retire(socket); }
    if (closed) retire(socket);
  });
  const refuse = (_request: IncomingMessage, response: ServerResponse) => empty(response, 400);
  server.on("checkContinue", refuse); server.on("checkExpectation", refuse);
  server.on("connect", (_request, socket) => retire(socket as Socket));
  server.on("upgrade", (_request, socket) => retire(socket as Socket));
  server.on("clientError", (_error, socket) => retire(socket as Socket));
  server.on("dropRequest", (_request, socket) => retire(socket as Socket));
  server.on("timeout", socket => retire(socket));
  server.once("close", () => { listenerClosed = true; completeClose(); });
  await new Promise<void>((resolve, reject) => {
    let started = false;
    server.on("error", () => {
      void close().then(() => { if (!started) reject(healthError()); }, () => { if (!started) reject(healthError()); });
    });
    server.listen(8081, "127.0.0.1", () => { started = true; resolve(); });
  });
  return Object.freeze({ close });
}
