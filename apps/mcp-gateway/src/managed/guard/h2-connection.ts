import { connect, type ClientHttp2Session } from "node:http2";
import { GuardedTlsConnector, type GuardedTlsDestination, type GuardedTlsExchange } from "./tls-connector.js";
export type GuardedH2Options = Readonly<{
  guard: Readonly<{ address: string; port: number }>;
  destination: GuardedTlsDestination;
  startedAtMonotonicNs: bigint;
  monotonicNowNs?(): bigint;
  onFatal(): void;
}>;
export type GuardedH2Connection = Readonly<{
  result: Promise<ClientHttp2Session>; closed: Promise<void>; cancel(): void;
}>;
const refused = () => new Error("guarded HTTP/2 connection refused safely");
const connections = new Set<Connection>();

/** Actual guarded TLS -> native H2 composition. Root owns typed unary streams
 * separately; this connection never proves a remote transaction has completed. */
export function startGuardedH2Connection(options: GuardedH2Options): GuardedH2Connection {
  if (connections.size >= 2) {
    const result = Promise.reject<ClientHttp2Session>(refused()); void result.catch(() => {});
    return Object.freeze({ result, closed: Promise.resolve(), cancel() {} });
  }
  const job = new Connection(() => connections.delete(job));
  connections.add(job); // Retain before any trusted clock or constructor callback.
  job.start(options);
  return job.handle;
}

class Connection {
  readonly handle: GuardedH2Connection;
  private resolve!: (session: ClientHttp2Session) => void;
  private reject!: (error: Error) => void;
  private drain!: () => void;
  private now = process.hrtime.bigint;
  private fatal: () => void = () => {};
  private last = 0n;
  private started = 0n;
  private deadline = 0n;
  private authority = "";
  private id = "";
  private connector?: GuardedTlsConnector;
  private exchange?: GuardedTlsExchange;
  private session?: ClientHttp2Session;
  private connectorClosed = true;
  private exchangeClosed = true;
  private sessionClosed = true;
  private processing = false;
  private pending = true;
  private stopped = false;
  private settled = false;
  private finished = false;
  private closing = false;
  private incoming = 0;
  private timer?: NodeJS.Timeout;
  private cleanup?: NodeJS.Timeout;
  constructor(private readonly release: () => void) {
    const result = new Promise<ClientHttp2Session>((yes, no) => { this.resolve = yes; this.reject = no; });
    void result.catch(() => {});
    this.handle = Object.freeze({ result, closed: new Promise<void>(yes => { this.drain = yes; }), cancel: () => this.stop() });
  }
  start(options: GuardedH2Options): void {
    try {
      const destination = { ...options.destination }, guard = { ...options.guard };
      this.now = options.monotonicNowNs ?? process.hrtime.bigint;
      const fatal = options.onFatal;
      if (typeof this.now !== "function" || typeof fatal !== "function" ||
        destination.alpn !== "h2" || destination.authentication !== "mutual_tls") throw refused();
      this.fatal = () => { fatal(); };
      this.started = options.startedAtMonotonicNs;
      if (typeof this.started !== "bigint" || this.started < 0n) throw refused();
      this.deadline = this.started + 10_000_000_000n;
      // Connector captures all CA/key buffers synchronously, before clocks/I/O.
      this.connector = new GuardedTlsConnector(guard, [destination], () => this.sample());
      this.connectorClosed = false;
      this.authority = `https://${destination.host}:${destination.port}`; this.id = destination.id;
      this.check(); this.arm();
      queueMicrotask(() => this.run());
    } catch { this.pending = false; this.stop(); }
  }
  private sample(): bigint {
    const value = this.now();
    if (typeof value !== "bigint" || value < this.last || value < this.started) throw refused();
    this.last = value; return value;
  }
  private check(): void {
    if (this.stopped || this.sample() >= this.deadline || this.stopped) throw refused();
  }
  private arm(): void {
    this.check();
    const remaining = this.deadline - this.sample();
    if (this.stopped || remaining <= 0n) throw refused();
    this.timer = setTimeout(() => {
      this.timer = undefined;
      try { this.check(); this.arm(); } catch { this.stop(); }
    }, Number((remaining + 999_999n) / 1_000_000n));
  }
  private run(): void {
    try {
      this.check();
      this.exchange = this.connector!.open(this.id, this.started);
      // open may return after a trusted clock reentered cancel/connector.close.
      // Its own physical receipt remains necessary even if close snapshotted no jobs.
      this.exchangeClosed = false;
      this.processing = true;
      void this.exchange.result.then(socket => {
        try {
          this.check();
          const session = connect(this.authority, { createConnection: () => socket,
            settings: { enablePush: false, headerTableSize: 0, maxHeaderListSize: 16384 },
            maxSessionMemory: 4, maxHeaderListPairs: 64, maxSendHeaderBlockLength: 16384,
            peerMaxConcurrentStreams: 128, maxSettings: 8, maxOutstandingPings: 1 });
          this.session = session; this.sessionClosed = false;
          session.on("error", () => this.stop()); session.on("goaway", () => this.stop());
          session.on("frameError", () => this.stop());
          session.once("close", () => { this.sessionClosed = true; this.stop(); this.finish(); });
          session.on("stream", stream => {
            this.incoming++;
            stream.on("error", () => this.stop());
            stream.once("close", () => { this.incoming--; this.finish(); });
            stream.destroy(); this.stop();
          });
          let connected = false, settings = false, acknowledged = false;
          const ready = () => {
            if (!connected || !settings || !acknowledged || this.settled) return;
            try {
              this.check();
              if (session.connecting || session.closed || session.destroyed) throw refused();
              this.settled = true; clearTimeout(this.timer); this.timer = undefined; this.resolve(session);
            } catch { this.stop(); }
          };
          session.once("connect", () => { connected = true; ready(); });
          session.once("remoteSettings", () => { settings = true; ready(); });
          session.once("localSettings", settings => { acknowledged = settings.enablePush === false; ready(); });
          this.check();
        } catch { this.stop(); }
        finally { this.processing = false; this.finish(); }
      }, () => { this.processing = false; this.stop(); this.finish(); });
      void this.exchange.closed.then(() => { this.exchangeClosed = true; this.stop(); this.finish(); }, () => this.stop());
      this.check();
    } catch { this.stop(); }
    finally { this.pending = false; this.finish(); }
  }
  private stop(): void {
    this.stopped = true;
    if (!this.settled) { this.settled = true; this.reject(refused()); }
    clearTimeout(this.timer); this.timer = undefined;
    if (!this.closing) {
      this.closing = true;
      this.cleanup = setTimeout(() => { try { this.fatal(); } catch { /* Retain actual owners. */ } }, 5000);
      if (this.connector) {
        void this.connector.close().then(() => { this.connectorClosed = true; this.finish(); }, () => {});
      }
    }
    this.session?.destroy(); this.exchange?.cancel(); this.finish();
  }
  private finish(): void {
    if (this.finished || !this.stopped || this.pending || this.processing || !this.connectorClosed ||
      !this.exchangeClosed || !this.sessionClosed || this.incoming) return;
    this.finished = true; clearTimeout(this.cleanup); this.release(); this.drain();
  }
}
