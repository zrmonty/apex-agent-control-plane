import { createServer, isIP, Socket, type Server } from "node:net";
import type { GuardDestination } from "./egress-policy.js";
import type { RelayAddress, RelayBindOptions, RelayLookup } from "./relay-types.js";
import { CONNECT_ACK, HANDSHAKE_NS, numericAddress, relayPort, relayRefused } from "./relay-protocol.js";

/** Internal native owner shared by the two fixed-purpose listeners. */
export class OwnedRelayListener {
  private revoke!: () => void;
  /** Stop notification only; close() separately acknowledges physical ownership. */
  readonly revoked = new Promise<void>(done => { this.revoke = done; });
  private readonly server: Server;
  private readonly sockets = new Set<Socket>();
  private readonly jobs = new Set<RelayJob>();
  private readonly bindAddress: string;
  private readonly port: number;
  private readonly sourceAddress: string;
  private readonly now: () => bigint;
  private stopped = false;
  private lastTime?: bigint;
  private listening?: Promise<RelayAddress>;
  private closing?: Promise<void>;
  private bindFinished = Promise.resolve();
  private bound!: () => void;
  private ready!: (value: RelayAddress) => void;
  private failed!: (error: Error) => void;
  private binding = false;

  constructor(options: RelayBindOptions, sourceAddress: string, begin: (job: RelayJob) => void) {
    try {
      this.bindAddress = numericAddress(options.bindAddress); this.port = relayPort(options.port, true);
      this.sourceAddress = numericAddress(sourceAddress); this.now = options.monotonicNowNs ?? process.hrtime.bigint;
      if (typeof this.now !== "function") throw relayRefused();
      this.server = createServer({ pauseOnConnect: true, allowHalfOpen: false, highWaterMark: 16_384 }, socket => {
        // Install handling before any source, capacity or clock rejection.
        this.sockets.add(socket);
        socket.on("error", () => socket.destroy());
        socket.once("close", () => this.sockets.delete(socket));
        try {
          if (this.stopped || this.jobs.size >= 128 || numericAddress(socket.remoteAddress) !== this.sourceAddress) throw relayRefused();
          const job = new RelayJob(socket, this.sample(), () => this.sample(), () => this.stopped,
            () => this.jobs.delete(job));
          this.jobs.add(job);
          try { begin(job); } catch { job.cancel(); }
        } catch { socket.destroy(); }
      });
      // Also bound native accepted sockets while rejected sockets are closing.
      this.server.maxConnections = 128;
      this.server.on("error", () => {
        if (this.binding) { this.binding = false; this.failed(relayRefused()); this.bound(); }
        void this.close().catch(() => {});
      });
      this.server.once("listening", () => {
        this.binding = false; this.bound();
        if (this.stopped) { this.failed(relayRefused()); return; }
        const actual = this.server.address();
        if (!actual || typeof actual === "string") { this.failed(relayRefused()); void this.close().catch(() => {}); return; }
        this.ready(Object.freeze({ address: this.bindAddress, port: actual.port, family: isIP(this.bindAddress) as 4 | 6 }));
      });
    } catch { throw relayRefused(); }
  }
  listen(): Promise<RelayAddress> {
    if (this.stopped) return Promise.reject(relayRefused());
    if (this.listening) return this.listening;
    this.bindFinished = new Promise<void>(done => { this.bound = done; });
    this.listening = new Promise<RelayAddress>((yes, no) => { this.ready = yes; this.failed = no; });
    this.binding = true;
    try { this.server.listen({ host: this.bindAddress, port: this.port, ipv6Only: true, backlog: 128 }); }
    catch { this.binding = false; this.failed(relayRefused()); this.bound(); void this.close().catch(() => {}); }
    return this.listening;
  }
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.stopped = true;
    this.revoke();
    this.closing = (async () => {
      // A cancelled in-progress numeric bind must finish before closing its handle.
      await this.bindFinished;
      if (this.server.listening) await new Promise<void>((yes, no) => {
        this.server.close(error => error ? no(relayRefused()) : yes());
      });
      // No new job can enter after the latch. DNS jobs survive native socket close.
      await Promise.all([...this.jobs].map(job => job.closed));
    })();
    for (const job of this.jobs) job.cancel();
    for (const socket of this.sockets) socket.destroy();
    return this.closing;
  }
  private sample(): bigint {
    try {
      const now = this.now();
      if (typeof now !== "bigint" || now < 0n || (this.lastTime !== undefined && now < this.lastTime)) throw relayRefused();
      this.lastTime = now; return now;
    } catch { void this.close().catch(() => {}); throw relayRefused(); }
  }
}

/** Capacity is released only by both native close events and a settled DNS callback. */
export class RelayJob {
  readonly closed: Promise<void>;
  private drain!: () => void;
  private sourceClosed = false;
  private targetClosed = true;
  private target?: Socket;
  private dnsPending = false;
  private cancelled = false;
  private finished = false;
  private established = false;
  private readonly timer: ReturnType<typeof setTimeout>;

  constructor(readonly source: Socket, private readonly started: bigint, private readonly now: () => bigint,
    private readonly stopped: () => boolean, private readonly release: () => void) {
    this.closed = new Promise<void>(done => { this.drain = done; });
    this.timer = setTimeout(() => this.cancel(), 10_000);
    source.on("error", () => this.cancel()); source.once("end", () => this.cancel());
    source.once("close", () => { this.sourceClosed = true; this.cancel(); this.finish(); });
    source.setNoDelay(true);
  }
  checkHandshake(): void {
    if (this.cancelled || this.stopped() || this.source.destroyed || this.now() >= this.started + HANDSHAKE_NS) throw relayRefused();
  }
  cancel(): void {
    this.cancelled = true; clearTimeout(this.timer);
    this.source.destroy(); this.target?.destroy(); this.finish();
  }
  resolve(route: GuardDestination, lookup: RelayLookup, localAddress: string, removeHandshake: () => void): void {
    this.checkHandshake();
    const literal = route.host.replace(/^\[|\]$/g, "");
    const pin = (answers: readonly string[]) => {
      this.checkHandshake();
      const selected = route.pin(answers);
      if (selected.host !== route.host || selected.port !== route.port || isIP(selected.address) !== selected.family) throw relayRefused();
      this.checkHandshake();
      this.connect(numericAddress(selected.address), relayPort(selected.port), localAddress, removeHandshake);
    };
    if (isIP(literal)) { pin([literal]); return; }
    this.dnsPending = true;
    let delivered = false;
    const done: Parameters<RelayLookup>[1] = (error, answers) => {
      if (delivered) return; delivered = true;
      try {
        this.checkHandshake();
        if (error || !Array.isArray(answers) || !answers.length || answers.length > 32) throw relayRefused();
        const addresses: string[] = [];
        for (const answer of answers) {
          if (!answer || typeof answer.address !== "string" || answer.address.length > 64 ||
            answer.address.includes("%") || !isIP(answer.address) || isIP(answer.address) !== answer.family) throw relayRefused();
          addresses.push(answer.address);
        }
        pin(addresses);
      } catch { this.cancel(); }
      finally { this.dnsPending = false; this.finish(); }
    };
    try { lookup(route.host, done); }
    catch { if (!delivered) { delivered = true; this.dnsPending = false; } this.cancel(); }
  }
  connect(host: string, port: number, localAddress: string, removeHandshake?: () => void): void {
    this.checkHandshake();
    if (this.target) throw relayRefused();
    // Create and own the native socket before connect, including synchronous errors.
    const target = new Socket({ allowHalfOpen: false });
    this.target = target; this.targetClosed = false;
    target.on("error", () => this.cancel()); target.once("end", () => this.cancel());
    target.once("close", () => { this.targetClosed = true; this.cancel(); this.finish(); });
    target.once("connect", () => {
      try {
        this.checkHandshake();
        if (removeHandshake && this.source.readableLength !== 0) throw relayRefused();
        this.source.pause(); removeHandshake?.();
        this.checkHandshake();
        if (removeHandshake) this.source.write(CONNECT_ACK);
        this.established = true; clearTimeout(this.timer);
        this.source.setTimeout(60_000, () => this.cancel()); target.setTimeout(60_000, () => this.cancel());
        target.setNoDelay(true);
        this.source.pipe(target); target.pipe(this.source);
      } catch { this.cancel(); }
    });
    try {
      // Native Socket options do not publicly expose Duplex watermarks. Enforce
      // finite public defaults before connect instead of changing stream internals.
      if (![target.readableHighWaterMark, target.writableHighWaterMark].every(value =>
        Number.isInteger(value) && value > 0 && value <= 65_536)) throw relayRefused();
      target.connect({ host: numericAddress(host), port: relayPort(port), localAddress: numericAddress(localAddress),
      family: isIP(host), autoSelectFamily: false }); }
    catch { this.cancel(); }
  }
  private finish(): void {
    if (this.finished || !this.sourceClosed || !this.targetClosed || this.dnsPending) return;
    this.finished = true; this.source.removeAllListeners("data");
    if (this.established) { this.source.unpipe(); this.target?.unpipe(); }
    this.release(); this.drain();
  }
}
