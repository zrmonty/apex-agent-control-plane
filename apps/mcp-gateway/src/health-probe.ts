import { request, type ClientRequest, type IncomingMessage } from "node:http";
import type { Socket } from "node:net";
import type { Clock } from "./telemetry/clock.js";
import type { ReadinessReportCodec } from "./managed/readiness/report-codec.js";
import { copyToken, healthError } from "./health/token.js";
import { HeaderCapture, uniqueHeaders } from "./health/envelope.js";

export type HealthProbeInput = Readonly<{ codec: ReadinessReportCodec; tokenBytes: Uint8Array; clock: Clock }>;

/** Library only, with independently authenticated/current binding and dedicated
 * token supplied by its trusted owner. No file/env/CLI, remote wall-age arithmetic,
 * retries, redirects, shared agent or admission decision. Callbacks must progress. */
export async function probeHealth(input: HealthProbeInput): Promise<0 | 1> {
  let token: Buffer | undefined, now: Clock["now"], decode: ReadinessReportCodec["decode"], last: bigint;
  try {
    now = input.clock.now.bind(input.clock); last = now().monotonicNs;
    if (typeof last !== "bigint" || last < 0n) throw healthError();
    token = copyToken(input.tokenBytes); decode = input.codec.decode.bind(input.codec);
  } catch { token?.fill(0); return 1; }
  const secret = token, deadline = last + 2000000000n;
  return new Promise<0 | 1>(resolve => {
    const bytes = Buffer.alloc(8193), header = new HeaderCapture();
    let req: ClientRequest | undefined, res: IncomingMessage | undefined, socket: Socket | undefined;
    let length = 0, declared = -1, ended = false, candidate = false, failed = false, settled = false;
    let requestClosed = false, responseClosed = false, socketClosed = false, cleaning = false;
    let cleanupTimer: NodeJS.Timeout | undefined, cleanupStart: bigint | undefined;
    const timer = setTimeout(fail, 2000);
    function sample(): bigint {
      const value = now().monotonicNs;
      if (typeof value !== "bigint" || value < last) throw healthError();
      last = value; return value;
    }
    function inTime(): boolean {
      if (settled || failed) return false;
      try { if (sample() >= deadline) throw healthError(); return true; }
      catch { fail(); return false; }
    }
    function finish(cleanupFailed = false): void {
      if (settled || !cleaning || (!cleanupFailed && ((req && !requestClosed) || (res && !responseClosed) || (socket && !socketClosed)))) return;
      if (candidate && !failed) {
        try {
          const current = sample();
          if (current >= deadline || (cleanupStart !== undefined && current - cleanupStart >= 1000000000n)) failed = true;
        } catch { failed = true; }
      }
      settled = true;
      clearTimeout(timer); clearTimeout(cleanupTimer);
      bytes.fill(0); header.clear(); secret.fill(0);
      socket?.removeListener("data", capture);
      // A failed teardown is NOT successful termination or readiness. Do not keep
      // the process alive solely for an unresponsive owned socket after refusal.
      if (cleanupFailed) socket?.unref();
      resolve(candidate && !failed && !cleanupFailed ? 0 : 1);
    }
    function cleanup(): void {
      if (!cleaning) {
        cleaning = true; // Reserve ownership before entering the clock callback.
        cleanupTimer = setTimeout(() => finish(true), 1000);
        try { cleanupStart = sample(); } catch { failed = true; }
        res?.destroy(); req?.destroy(); socket?.destroy();
      }
      finish();
    }
    function fail(): void { if (!settled) { failed = true; cleanup(); } }
    function capture(chunk: Buffer): void {
      if (!inTime()) return;
      header.accept(chunk);
      if (header.invalid) { fail(); return; }
      if (header.complete) {
        const fields = header.fields, size = fields.get("content-length");
        if (size === undefined || !/^(0|[1-9][0-9]{0,3})$/.test(size) || Number(size) > 8192 ||
          fields.get("content-type") !== "application/json" || fields.get("connection") !== "close" ||
          ["transfer-encoding", "content-encoding", "trailer"].some(name => fields.has(name))) { fail(); return; }
        declared = Number(size);
        if (header.bodyBytes > declared) fail();
      }
    }
    if (!inTime()) return;
    try {
      req = request({ host: "127.0.0.1", port: 8081, path: "/readyz", method: "GET", agent: false,
        maxHeaderSize: 4096, insecureHTTPParser: false,
        headers: { Host: "127.0.0.1:8081", Authorization: `Bearer ${secret.toString("base64url")}`, Connection: "close" } },
      received => {
        res = received; // Capture even an already-failed late response for cleanup.
        res.on("error", fail); res.once("aborted", fail);
        res.once("close", () => { responseClosed = true; if (!ended || !res!.complete) fail(); else finish(); });
        if (!inTime() || !header.complete || header.invalid || res.httpVersion !== "1.1" ||
          res.statusCode !== 200 || !uniqueHeaders(res.rawHeaders)) { fail(); res.destroy(); return; }
        res.on("data", (chunk: Buffer) => {
          if (!inTime()) return;
          const kept = Math.min(chunk.length, bytes.length - length);
          chunk.copy(bytes, length, 0, kept); length += kept;
          if (length > 8192 || chunk.length > kept || length > declared) fail();
        });
        res.once("end", () => {
          ended = true;
          if (!inTime() || !res!.complete || length !== declared || header.bodyBytes !== declared || res!.rawTrailers.length !== 0) { fail(); return; }
          try {
            // Preserve a BOM for the strict JSON boundary; do not silently strip it.
            const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, length));
            if (!inTime()) return;
            const report = decode(text);
            if (!inTime()) return;
            candidate = report.live === true && report.ready === true;
            if (!inTime()) return;
          } catch { failed = true; }
          cleanup();
        });
      });
      req.maxHeadersCount = 0;
      req.on("error", fail); req.on("information", fail);
      req.on("upgrade", (_response, upgraded) => { upgraded.destroy(); fail(); });
      req.once("close", () => { requestClosed = true; if (!ended) fail(); else finish(); });
      req.once("socket", assigned => {
        socket = assigned;
        socket.on("error", fail);
        socket.once("close", () => { socketClosed = true; if (!ended) fail(); else finish(); });
        socket.prependListener("data", capture);
        if (cleaning || !inTime()) socket.destroy();
      });
      if (inTime()) req.end();
    } catch { fail(); }
  });
}
