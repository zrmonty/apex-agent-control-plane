import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer as createTcpServer, connect, type Socket, type AddressInfo } from "node:net";
import { createServer as createTlsServer, rootCertificates } from "node:tls";
import { test, type TestContext } from "node:test";
import { certificate, key } from "../authority/testing-tls.js";
import { createHash, X509Certificate } from "node:crypto";
import { GuardedTlsConnector, type GuardedTlsDestination } from "./tls-connector.js";

// TEST ONLY opaque guard peer: loopback forwarding is not production policy or
// network confinement. The production connector performs real TCP and mTLS.
async function fixture(t: TestContext, options: { response?: string; alpn?: string; stall?: boolean;
  destination?: Partial<GuardedTlsDestination>; now?: () => bigint; beforeAck?: () => void } = {}) {
  const sockets = new Set<Socket>(), selectors: string[] = [];
  const track = (socket: Socket) => {
    sockets.add(socket); socket.on("error", () => {});
    socket.once("close", () => sockets.delete(socket)); return socket;
  };
  let authenticated = 0;
  const upstream = createTlsServer({ ca: certificate, key, cert: certificate,
    requestCert: true, rejectUnauthorized: true, ALPNProtocols: [options.alpn ?? "h2"] }, socket => {
    authenticated++; track(socket); socket.on("data", chunk => socket.write(chunk));
  });
  upstream.on("connection", track); upstream.on("tlsClientError", () => {});
  upstream.listen(0, "127.0.0.1"); await once(upstream, "listening");
  const upstreamPort = (upstream.address() as AddressInfo).port;
  const guard = createTcpServer(socket => {
    track(socket);
    let header = Buffer.alloc(0);
    const read = (chunk: Buffer) => {
      header = Buffer.concat([header, chunk]);
      const end = header.indexOf("\r\n\r\n");
      if (end < 0) return;
      selectors.push(header.subarray(0, end + 4).toString("ascii"));
      socket.off("data", read); socket.pause();
      if (options.stall) return;
      if (options.response) { socket.end(options.response); return; }
      const remote = track(connect({ host: "127.0.0.1", port: upstreamPort }));
      socket.once("close", () => remote.destroy()); remote.once("close", () => socket.destroy());
      remote.once("connect", () => {
        options.beforeAck?.();
        socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        const tail = header.subarray(end + 4); if (tail.length) remote.write(tail);
        socket.pipe(remote); remote.pipe(socket); socket.resume();
      });
    };
    socket.on("data", read);
  });
  guard.listen(0, "127.0.0.1"); await once(guard, "listening");
  const destination: GuardedTlsDestination = {
    id: "authority", host: "grpc-contract-test", port: upstreamPort, ca: certificate,
    cert: certificate, key, alpn: "h2", authentication: "mutual_tls",
    ...options.destination,
  };
  const connector = new GuardedTlsConnector({ address: "127.0.0.1", port: (guard.address() as AddressInfo).port }, [destination], options.now);
  t.after(async () => {
    await connector.close();
    for (const socket of sockets) socket.destroy();
    await Promise.all([guard, upstream].map(server => new Promise<void>(done => server.close(() => done()))));
  });
  return { connector, destination, selectors, authenticated: () => authenticated,
    guard: { address: "127.0.0.1", port: (guard.address() as AddressInfo).port } };
}

test("guarded connector uses only guard TCP and authenticates original-name mTLS", async t => {
  const f = await fixture(t, { destination: { peerSha256: createHash("sha256")
    .update(new X509Certificate(certificate).raw).digest("hex") } });
  const exchange = f.connector.open("authority", process.hrtime.bigint());
  const socket = await exchange.result;
  assert.equal(socket.authorized, true); assert.equal(socket.alpnProtocol, "h2");
  assert.equal(socket.servername, "grpc-contract-test");
  const reply = once(socket, "data"); socket.write("opaque application bytes");
  assert.equal((await reply)[0].toString(), "opaque application bytes");
  assert.equal(f.authenticated(), 1);
  assert.deepEqual(f.selectors, [`CONNECT grpc-contract-test:${f.destination.port} HTTP/1.1\r\nHost: grpc-contract-test:${f.destination.port}\r\n\r\n`]);
  let closed = false; void exchange.closed.then(() => { closed = true; });
  await Promise.resolve(); assert.equal(closed, false);
  exchange.cancel(); await exchange.closed; assert.equal(socket.destroyed, true);
});

test("unknown destination refuses before any guard request", async t => {
  const f = await fixture(t);
  assert.throws(() => f.connector.open("unapproved", process.hrtime.bigint()), /guarded TLS refused safely/);
  assert.deepEqual(f.selectors, []);
});

for (const [name, destination] of [
  ["wrong original name", { host: "wrong-original-name" }],
  ["untrusted real CA", { ca: Buffer.from(rootCertificates[0]) }],
  ["wrong leaf pin", { peerSha256: "00".repeat(32) }],
] as const) {
  test(`guarded TLS refuses ${name} and closes native sockets`, async t => {
    const f = await fixture(t, { destination });
    const exchange = f.connector.open("authority", process.hrtime.bigint());
    await assert.rejects(exchange.result, /^Error: guarded TLS refused safely$/);
    await exchange.closed; assert.equal(f.authenticated(), 0);
  });
}

test("explicit mutual TLS destination refuses missing client material before any socket", () => {
  // Client secureConnect alone cannot prove the server accepted a client cert.
  assert.throws(() => new GuardedTlsConnector({ address: "127.0.0.1", port: 1 }, [{
    id: "authority", host: "grpc-contract-test", port: 443, ca: certificate,
    alpn: "h2", authentication: "mutual_tls",
  }]), /guarded TLS refused safely/);
});

test("guarded TLS rejects a different negotiated ALPN", async t => {
  const f = await fixture(t, { alpn: "http/1.1" });
  const exchange = f.connector.open("authority", process.hrtime.bigint());
  await assert.rejects(exchange.result, /guarded TLS refused safely/); await exchange.closed;
});

for (const response of ["HTTP/1.1 302 Found\r\nLocation: https://evil.invalid\r\n\r\n",
  "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
  "HTTP/1.1 200 Connection Established\r\nX-Header: x\r\n\r\n",
  "HTTP/1.1 200 Connection Established\r\n\r\nINJECTED", "x".repeat(1025)]) {
  test(`guard response refuses ${response.slice(0, 40).replaceAll("\r\n", " ")}`, async t => {
    const f = await fixture(t, { response });
    const exchange = f.connector.open("authority", process.hrtime.bigint());
    await assert.rejects(exchange.result, /^Error: guarded TLS refused safely$/); await exchange.closed;
    assert.equal(f.authenticated(), 0);
  });
}

test("overdue callback cannot restart original connect deadline before TLS", async t => {
  let now = 1000n;
  const f = await fixture(t, { now: () => now, beforeAck: () => { now = 10_000_001_000n; } });
  const exchange = f.connector.open("authority", 1000n);
  await assert.rejects(exchange.result, /guarded TLS refused safely/); await exchange.closed;
  assert.equal(f.authenticated(), 0);
});

for (const offset of [-1n, 0n, 1n]) {
  test(`final TLS callback enforces exact original deadline at ${offset}ns`, async t => {
    let samples = 0;
    const f = await fixture(t, { now: () => ++samples < 4 ? 1000n : 10_000_001_000n + offset });
    const exchange = f.connector.open("authority", 1000n);
    if (offset < 0n) { await exchange.result; exchange.cancel(); }
    else await assert.rejects(exchange.result, /guarded TLS refused safely/);
    await exchange.closed; assert.equal(samples, 4);
  });
}

test("expired, future and backwards original clock samples refuse before connecting", async t => {
  let now = 10_000_001_000n;
  const f = await fixture(t, { now: () => now });
  assert.throws(() => f.connector.open("authority", 1000n), /guarded TLS refused safely/);
  assert.throws(() => f.connector.open("authority", now + 1n), /guarded TLS refused safely/);
  now--;
  assert.throws(() => f.connector.open("authority", now), /guarded TLS refused safely/);
  assert.throws(() => f.connector.open("authority", now), /guarded TLS refused safely/);
  assert.deepEqual(f.selectors, []);
});

test("128 physical connections retain capacity across immediate cancellation", async t => {
  const f = await fixture(t, { stall: true });
  const exchanges = Array.from({ length: 128 }, () => f.connector.open("authority", process.hrtime.bigint()));
  const rejections = exchanges.map(exchange => assert.rejects(exchange.result, /guarded TLS refused safely/));
  assert.throws(() => f.connector.open("authority", process.hrtime.bigint()), /guarded TLS refused safely/);
  for (const exchange of exchanges) exchange.cancel();
  // Logical cancellation has happened; actual native close callbacks have not.
  assert.throws(() => f.connector.open("authority", process.hrtime.bigint()), /guarded TLS refused safely/);
  await Promise.all([...rejections, ...exchanges.map(exchange => exchange.closed)]);
  const next = f.connector.open("authority", process.hrtime.bigint());
  const refused = assert.rejects(next.result, /guarded TLS refused safely/);
  next.cancel(); await refused; await next.closed;
});

test("shutdown latches before pending handshakes and is physically idempotent", async t => {
  const f = await fixture(t, { stall: true });
  const exchange = f.connector.open("authority", process.hrtime.bigint());
  const refused = assert.rejects(exchange.result, /guarded TLS refused safely/);
  const closed = f.connector.close();
  assert.equal(f.connector.close(), closed);
  assert.throws(() => f.connector.open("authority", process.hrtime.bigint()), /guarded TLS refused safely/);
  await refused; await exchange.closed; await closed;
  assert.equal(f.authenticated(), 0);
});

test("one cancelled tunnel cannot close an unrelated authenticated tunnel", async t => {
  const f = await fixture(t);
  const first = f.connector.open("authority", process.hrtime.bigint());
  const second = f.connector.open("authority", process.hrtime.bigint());
  await first.result; const socket = await second.result;
  first.cancel(); await first.closed;
  const reply = once(socket, "data"); socket.write("other call still owns this tunnel");
  assert.equal((await reply)[0].toString(), "other call still owns this tunnel");
  assert.equal(socket.destroyed, false);
  second.cancel(); await second.closed;
});

test("held actual TLS close keeps capacity and root close unresolved", async t => {
  const f = await fixture(t);
  const first = f.connector.open("authority", process.hrtime.bigint());
  const socket = await first.result;
  const originalEmit = socket.emit;
  let nativeClose!: () => void, release!: () => void;
  const reached = new Promise<void>(done => { nativeClose = done; });
  t.mock.method(socket, "emit", function (event: string | symbol, ...args: unknown[]) {
    if (event === "close") {
      release = () => Reflect.apply(originalEmit, socket, [event, ...args]); nativeClose(); return true;
    }
    return Reflect.apply(originalEmit, socket, [event, ...args]);
  });
  const others = Array.from({ length: 127 }, () => f.connector.open("authority", process.hrtime.bigint()));
  const rejections = others.map(exchange => assert.rejects(exchange.result, /guarded TLS refused safely/));
  first.cancel(); await reached;
  assert.throws(() => f.connector.open("authority", process.hrtime.bigint()), /guarded TLS refused safely/);
  let settled = false; const closing = f.connector.close().then(() => { settled = true; });
  await Promise.all(rejections); await Promise.all(others.map(exchange => exchange.closed));
  assert.equal(settled, false);
  release(); await first.closed; await closing; assert.equal(settled, true);
});

test("fixed destination metadata and credential buffers are captured at construction", async t => {
  const ca = Buffer.from(certificate), cert = Buffer.from(certificate), privateKey = Buffer.from(key);
  const f = await fixture(t, { destination: { ca, cert, key: privateKey } });
  ca.fill(0); cert.fill(0); privateKey.fill(0);
  Object.assign(f.destination, { host: "changed.invalid", port: 1, alpn: "http/1.1" });
  const exchange = f.connector.open("authority", process.hrtime.bigint());
  const socket = await exchange.result; assert.equal(socket.servername, "grpc-contract-test");
  exchange.cancel(); await exchange.closed;
});
