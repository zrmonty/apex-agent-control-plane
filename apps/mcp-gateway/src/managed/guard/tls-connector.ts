import { connect as tcpConnect, isIP } from "node:net";
import { connect as tlsConnect, checkServerIdentity, type TLSSocket } from "node:tls";
import { createHash } from "node:crypto";

export type GuardedTlsDestination = Readonly<{
  id: string; host: string; port: number; ca: Uint8Array;
  authentication: "server_tls" | "mutual_tls";
  alpn: "h2" | "http/1.1"; cert?: Uint8Array; key?: Uint8Array; peerSha256?: string;
}>;
export type GuardedTlsExchange = Readonly<{
  result: Promise<TLSSocket>; closed: Promise<void>; cancel(): void;
}>;
const refused = () => new Error("guarded TLS refused safely");
const TEN_SECONDS_NS = 10_000_000_000n;
type Job = { closed: Promise<void>; cancel(): void };
type CapturedDestination = Omit<GuardedTlsDestination, "ca" | "cert" | "key"> & {
  ca: Buffer; cert?: Buffer; key?: Buffer;
};

/** Protected composition supplies these fixed destinations. This connector has
 * no destination DNS, ambient proxy, redirect, retry or dynamic credential API. */
export class GuardedTlsConnector {
  private readonly guard: Readonly<{ address: string; port: number }>;
  private readonly destinations = new Map<string, CapturedDestination>();
  private readonly jobs = new Set<Job>();
  private stopped = false;
  private closing?: Promise<void>;
  private lastTime?: bigint;

  constructor(guard: Readonly<{ address: string; port: number }>,
    destinations: readonly GuardedTlsDestination[], private readonly now: () => bigint = process.hrtime.bigint) {
    try {
      if (!isIP(guard.address) || guard.address.includes("%") || !port(guard.port) ||
        !Array.isArray(destinations) || !destinations.length || destinations.length > 66 || typeof now !== "function") throw refused();
      this.guard = Object.freeze({ address: guard.address, port: guard.port });
      for (const item of destinations) {
        if (!/^[a-zA-Z0-9._-]{1,128}$/.test(item.id) || this.destinations.has(item.id) ||
          typeof item.host !== "string" || item.host.length > 253 || !port(item.port) ||
          !/^(?:[a-z0-9.-]+|\[[a-f0-9:]+\])$/.test(item.host) ||
          new URL(`https://${item.host}:${item.port}/`).hostname !== item.host ||
          !["h2", "http/1.1"].includes(item.alpn) || (item.cert === undefined) !== (item.key === undefined) ||
          !["server_tls", "mutual_tls"].includes(item.authentication) ||
          (item.authentication === "mutual_tls" && item.cert === undefined) ||
          (item.peerSha256 !== undefined && !/^[a-f0-9]{64}$/.test(item.peerSha256))) throw refused();
        this.destinations.set(item.id, Object.freeze({ id: item.id, host: item.host, port: item.port,
          authentication: item.authentication, alpn: item.alpn, ca: bytes(item.ca), cert: item.cert === undefined ? undefined : bytes(item.cert),
          key: item.key === undefined ? undefined : bytes(item.key), peerSha256: item.peerSha256 }));
      }
    } catch { throw refused(); }
  }

  open(destinationId: string, startedAtMonotonicNs: bigint): GuardedTlsExchange {
    const destination = this.destinations.get(destinationId);
    if (this.stopped || !destination || this.jobs.size >= 128) throw refused();
    const current = this.sample();
    if (typeof startedAtMonotonicNs !== "bigint" || startedAtMonotonicNs < 0n ||
      startedAtMonotonicNs > current || current - startedAtMonotonicNs >= TEN_SECONDS_NS) throw refused();
    const deadline = startedAtMonotonicNs + TEN_SECONDS_NS;
    const raw = tcpConnect({ host: this.guard.address, port: this.guard.port,
      family: isIP(this.guard.address), autoSelectFamily: false });
    let tls: TLSSocket | undefined, rawClosed = false, tlsClosed = true, settled = false, cancelled = false;
    let resolve!: (socket: TLSSocket) => void, reject!: (error: Error) => void, drain!: () => void;
    const result = new Promise<TLSSocket>((yes, no) => { resolve = yes; reject = no; });
    const closed = new Promise<void>(done => { drain = done; });
    const cancel = () => {
      cancelled = true; clearTimeout(timer);
      if (!settled) { settled = true; reject(refused()); }
      tls?.destroy(); raw.destroy();
    };
    const check = () => {
      if (cancelled || this.stopped || this.sample() >= deadline) throw refused();
    };
    const finish = () => {
      if (!rawClosed || !tlsClosed) return;
      cancel(); this.jobs.delete(job); drain();
    };
    const timer = setTimeout(cancel, Number((deadline - current + 999_999n) / 1_000_000n));
    const job = { closed, cancel }; this.jobs.add(job);
    raw.on("error", cancel);
    raw.once("close", () => { rawClosed = true; cancel(); finish(); });
    raw.once("connect", () => {
      try {
        check();
        const authority = `${destination.host}:${destination.port}`;
        raw.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`);
      } catch { cancel(); }
    });
    let header = Buffer.alloc(0);
    const onData = (chunk: Buffer) => {
      try {
        check();
        if (header.length + chunk.length > 1024) throw refused();
        header = Buffer.concat([header, chunk]);
        const end = header.indexOf("\r\n\r\n");
        if (end < 0) return;
        // Guard speaks this one fixed response. No auth challenge, redirects,
        // informational responses or bytes preceding the TLS handshake.
        if (!header.equals(Buffer.from("HTTP/1.1 200 Connection Established\r\n\r\n"))) throw refused();
        raw.off("data", onData); raw.pause();
        const name = destination.host.replace(/^\[|\]$/g, "");
        tls = tlsConnect({ socket: raw, ca: destination.ca, cert: destination.cert, key: destination.key,
          servername: isIP(name) ? undefined : name, rejectUnauthorized: true,
          checkServerIdentity: (_host, certificate) => checkServerIdentity(name, certificate),
          minVersion: "TLSv1.2", ALPNProtocols: [destination.alpn] });
        tlsClosed = false;
        tls.on("error", cancel);
        tls.once("close", () => { tlsClosed = true; cancel(); finish(); });
        tls.once("secureConnect", () => {
          try {
            check();
            if (!tls!.authorized || tls!.alpnProtocol !== destination.alpn ||
              (destination.peerSha256 !== undefined && createHash("sha256").update(tls!.getPeerCertificate().raw)
                .digest("hex") !== destination.peerSha256)) throw refused();
            settled = true; clearTimeout(timer); resolve(tls!);
          } catch { cancel(); }
        });
      } catch { cancel(); }
    };
    raw.on("data", onData);
    return Object.freeze({ result, closed, cancel });
  }

  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.stopped = true;
    this.closing = Promise.all([...this.jobs].map(job => job.closed)).then(() => {
      for (const entry of this.destinations.values()) { entry.key?.fill(0); entry.cert?.fill(0); entry.ca.fill(0); }
      this.destinations.clear();
    });
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

function port(value: number): boolean { return Number.isInteger(value) && value > 0 && value <= 65535; }
function bytes(value: Uint8Array): Buffer {
  if (!(value instanceof Uint8Array) || !value.length || value.length > 65_536) throw refused();
  return Buffer.from(value);
}
