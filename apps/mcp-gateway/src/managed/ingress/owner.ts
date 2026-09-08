import { createHash } from "node:crypto";
import { createServer, type Server } from "node:https";
import type { Duplex } from "node:stream";
import type { TLSSocket } from "node:tls";
import type { ManagedIngress, ManagedIngressOptions } from "../ingress.js";
import type { StageOwner } from "../bootstrap/stage-owner.js";
import { assertRuntimeMaterialsStage, runtimeTlsMaterial } from "../bootstrap/runtime-materials.js";
import { Sessions } from "./sessions.js";
import { ingressLimits, type IngressLimits } from "./limits.js";
import { MAX_HEADERS } from "./request.js";

export interface IngressDependencies {
  address(stage: StageOwner): { host: string; port: number };
  readonly limits?: Partial<IngressLimits>;
}
const retained = new Set<object>();
const refused = () => new Error("managed ingress refused safely");

export function startIngress(options: ManagedIngressOptions, dependencies: IngressDependencies): ManagedIngress {
  let resolve!: (value: { host: string; port: number }) => void, reject!: (error: Error) => void;
  let resolveClosed!: () => void;
  const result = new Promise<{ host: string; port: number }>((yes, no) => { resolve = yes; reject = no; });
  void result.catch(() => {});
  const closed = new Promise<void>(yes => { resolveClosed = yes; });
  let server: Server | undefined, sessions: Sessions | undefined, stopped = false;
  let serverClosed = false, sessionsClosed = false, done = false, fatal = false;
  let limits = ingressLimits(), serving = false;
  let monitor: ReturnType<typeof setInterval> | undefined, startup: ReturnType<typeof setTimeout> | undefined;
  let cleanup: ReturnType<typeof setTimeout> | undefined;
  const sockets = new Set<Duplex>();
  const handle = Object.freeze({ result, closed, cancel }); retained.add(handle);
  function cancel() {
    if (stopped) return; stopped = true; reject(refused());
    clearInterval(monitor); clearTimeout(startup);
    cleanup = setTimeout(notifyFatal, limits.cleanupMs);
    void (sessions?.close() ?? Promise.resolve()).then(() => { sessionsClosed = true; finish(); }, notifyFatal);
    if (server) server.close(() => { serverClosed = true; finish(); }); else serverClosed = true;
    for (const socket of sockets) socket.destroy();
    finish();
  }
  function finish() {
    if (done || !stopped || !serverClosed || !sessionsClosed || sockets.size) return;
    done = true; clearTimeout(cleanup); retained.delete(handle); resolveClosed();
  }
  function notifyFatal() {
    if (done || fatal) return; fatal = true; cancel();
    try { options.onFatal(); } catch { /* Supervisor owns process termination. */ }
  }
  function isAdmitting() {
    const active = options.isAdmitting();
    if (typeof active !== "boolean") throw refused();
    if (active) serving = true;
    else if (serving) cancel();
    return active && !stopped;
  }
  try {
    assertRuntimeMaterialsStage(options.materials, options.stage);
    limits = ingressLimits(dependencies.limits);
    const address = dependencies.address(options.stage);
    sessions = new Sessions({ ...options, isAdmitting, onFatal: notifyFatal }, limits);
    sessions.check(); isAdmitting();
    if (stopped) throw refused();
    const profile = options.stage.documents.authority.profile.managed.ingress;
    const tls = runtimeTlsMaterial(options.materials, "ingress");
    try {
      server = createServer({ ...tls, requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3",
        handshakeTimeout: 5000, maxHeaderSize: 16384 }, (req, res) => {
        const socket = req.socket as TLSSocket;
        if (!socket.authorized || !socket.getPeerCertificate().raw || !profile.edge_certificate_sha256.includes(
          createHash("sha256").update(socket.getPeerCertificate().raw).digest("hex"))) { socket.destroy(); return; }
        if (stopped) { socket.destroy(); return; }
        void sessions!.handle(req, res);
      });
    } finally { for (const bytes of Object.values(tls)) bytes.fill(0); }
    server.on("connection", socket => {
      if (stopped || sockets.size >= limits.sockets) { socket.destroy(); return; }
      sockets.add(socket); socket.once("close", () => { sockets.delete(socket); finish(); });
    });
    server.headersTimeout = limits.bodyMs;
    server.maxHeadersCount = MAX_HEADERS;
    server.requestTimeout = limits.requestMs;
    server.keepAliveTimeout = 5000;
    server.maxRequestsPerSocket = 128;
    server.on("upgrade", (_req, socket) => socket.destroy());
    server.on("connect", (_req, socket) => socket.destroy());
    server.on("error", () => cancel());
    startup = setTimeout(cancel, limits.startupMs);
    monitor = setInterval(() => { try { sessions!.check(); isAdmitting(); } catch { cancel(); } }, 25);
    server.listen(address.port, address.host, () => {
      clearTimeout(startup);
      if (stopped) { server!.close(); return; }
      const actual = server!.address();
      if (!actual || typeof actual === "string") { cancel(); return; }
      resolve({ host: actual.address, port: actual.port });
    });
  } catch { cancel(); }
  return handle;
}
