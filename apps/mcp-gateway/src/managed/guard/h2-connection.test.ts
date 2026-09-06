import assert from "node:assert/strict";
import { once } from "node:events";
import { createSecureServer, type ServerHttp2Session, type ServerHttp2Stream, type IncomingHttpHeaders } from "node:http2";
import type { AddressInfo, Socket } from "node:net";
import test, { type TestContext } from "node:test";
import { certificate, key } from "../authority/testing-tls.js";
import { OwnedAuthorityChannel } from "../authority/unary.js";
import { OwnedEvidenceChannel } from "../evidence-channel.js";
import { rootCertificates } from "node:tls";
import { GuardedTlsConnector, type GuardedTlsExchange } from "./tls-connector.js";
import { GuardEgressRelay } from "./relay-server.js";
import { startGuardedH2Connection, type GuardedH2Options } from "./h2-connection.js";

async function fixture(t: TestContext, handle: (stream: ServerHttp2Stream, headers: IncomingHttpHeaders) => void,
  connected?: (session: ServerHttp2Session) => void) {
  const sessions = new Set<ServerHttp2Session>(), sockets = new Set<Socket>();
  const server = createSecureServer({ key, cert: certificate, ca: certificate, requestCert: true, rejectUnauthorized: true });
  server.on("connection", socket => { sockets.add(socket); socket.on("error", () => {}); socket.once("close", () => sockets.delete(socket)); });
  server.on("session", session => { sessions.add(session); session.on("error", () => {}); session.once("close", () => sessions.delete(session)); connected?.(session); });
  server.on("stream", (stream, headers) => { stream.on("error", () => {}); handle(stream, headers); });
  server.on("tlsClientError", () => {});
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const port = (server.address() as AddressInfo).port;
  // Test-only loopback selection; real relay/CONNECT/TLS/H2, not kernel policy.
  const relay = new GuardEgressRelay({ bindAddress: "127.0.0.1", port: 0, gatewayAddress: "127.0.0.1", outboundAddress: "127.0.0.1",
    lookup(_host, done) { done(null, [{ address: "127.0.0.1", family: 4 }]); },
    policy: { select(host, selected) { assert(["grpc-contract-test", "wrong-original-name"].includes(host)); assert.equal(selected, port);
      return { host, port, pin() { return { host, port, address: "127.0.0.1", family: 4 }; } }; } } });
  const guard = await relay.listen();
  let fatals = 0;
  const options: GuardedH2Options = { guard, destination: { id: "authority", host: "grpc-contract-test", port,
    ca: certificate, cert: certificate, key, authentication: "mutual_tls", alpn: "h2" },
    startedAtMonotonicNs: process.hrtime.bigint(), onFatal() { fatals++; } };
  const owners: ReturnType<typeof startGuardedH2Connection>[] = [];
  const start = (overrides: Partial<GuardedH2Options> = {}) => {
    const owner = startGuardedH2Connection({ ...options, ...overrides }); owners.push(owner); return owner;
  };
  t.after(async () => {
    for (const owner of owners) owner.cancel();
    for (const session of sessions) session.destroy();
    for (const socket of sockets) socket.destroy();
    await Promise.all(owners.map(owner => owner.closed)); await relay.close();
    await new Promise<void>(done => server.close(() => done()));
    assert.equal(fatals, 0);
  });
  return { start, options, sessions, relay };
}

for (const sample of [4, 5, 6, 7]) test(`cancel at clock sample ${sample} awaits the concrete exchange close`, async t => {
  const f = await fixture(t, stream => stream.resume());
  const anchor = f.start(); await anchor.result;
  const native = GuardedTlsConnector.prototype.open;
  let exchange: GuardedTlsExchange | undefined, exchangeClosed = false;
  // Observe the unmodified native exchange, without delaying/faking either promise.
  GuardedTlsConnector.prototype.open = function (...args) {
    const value = native.apply(this, args);
    if (!exchange) { exchange = value; void value.closed.then(() => { exchangeClosed = true; }); }
    return value;
  };
  let owner: ReturnType<typeof f.start> | undefined, count = 0, replacement: ReturnType<typeof f.start> | undefined;
  try {
    owner = f.start({ monotonicNowNs() {
      if (++count === sample) owner!.cancel();
      return process.hrtime.bigint();
    } });
    await assert.rejects(owner.result); await owner.closed;
    const closedAtRoot = exchange === undefined || exchangeClosed;
    let admitted = false;
    replacement = f.start({ monotonicNowNs() { admitted = true; return process.hrtime.bigint(); } });
    assert.equal(closedAtRoot, true, "owner.closed must await actual exchange.closed");
    assert.equal(admitted, true, "capacity recovers after actual closure");
    await replacement.result;
  } finally {
    GuardedTlsConnector.prototype.open = native;
    owner?.cancel(); anchor.cancel(); replacement?.cancel();
    await Promise.all([owner?.closed, anchor.closed, replacement?.closed, exchange?.closed]);
  }
});

test("real guard, original-name mTLS and H2 reach the actual typed authority channel", async t => {
  let seen = false;
  const f = await fixture(t, (stream, headers) => {
    seen = true;
    assert.equal(headers[":path"], "/apex.v1.ManagedRuntimeAuthority/RenewDeployment");
    assert.equal(headers[":authority"], `grpc-contract-test:${f.options.destination.port}`);
    assert.equal(headers.authorization, "Bearer test-only-workload-token");
    stream.resume(); stream.on("end", () => {
      stream.respond({ ":status": 200, "content-type": "application/grpc" }, { waitForTrailers: true });
      stream.on("wantTrailers", () => stream.sendTrailers({ "grpc-status": "0" })); stream.end(Buffer.from([0, 0, 0, 0, 0]));
    });
  });
  const owner = f.start(), session = await owner.result;
  assert.equal(session.connecting, false); assert.equal(session.localSettings.enablePush, false);
  const channel = new OwnedAuthorityChannel(session, { token: "test-only-workload-token", instanceProof: Buffer.alloc(32, 7) });
  const request = channel.start("/apex.v1.ManagedRuntimeAuthority/RenewDeployment", Buffer.alloc(0));
  assert.deepEqual(await request.result, Buffer.alloc(0)); await request.closed; assert(seen);
  await channel.close(); await owner.closed;
});

test("same concrete guarded H2 owner supplies the typed evidence channel", async t => {
  let seen = false;
  const f = await fixture(t, (stream, headers) => {
    seen = true; assert.equal(headers[":path"], "/apex.v1.EventIngest/Ingest");
    assert.equal(headers.authorization, "Bearer test-only-evidence-token");
    assert.equal(headers["apex-instance-proof-bin"], undefined);
    stream.resume(); stream.on("end", () => {
      stream.respond({ ":status": 200, "content-type": "application/grpc" }, { waitForTrailers: true });
      stream.on("wantTrailers", () => stream.sendTrailers({ "grpc-status": "0" })); stream.end(Buffer.alloc(5));
    });
  });
  const owner = f.start(), channel = new OwnedEvidenceChannel(await owner.result, "test-only-evidence-token");
  const now = process.hrtime.bigint(), request = channel.start(Buffer.alloc(0), now, now + 5_000_000_000n);
  assert.deepEqual(await request.result, Buffer.alloc(0)); await request.closed; assert(seen);
  await channel.close(); await owner.closed;
});

for (const [label, change] of [
  ["wrong original name", { host: "wrong-original-name" }],
  ["wrong CA", { ca: Buffer.from(rootCertificates[0]) }],
  ["wrong peer pin", { peerSha256: "0".repeat(64) }],
  ["non-H2", { alpn: "http/1.1" as const }],
  ["no mutual authentication", { authentication: "server_tls" as const }],
  ["missing client key", { key: undefined }],
] as const) {
  test(`guarded H2 refuses ${label} without publishing a session`, async t => {
    const f = await fixture(t, () => assert.fail("no application stream"));
    const owner = f.start({ destination: { ...f.options.destination, ...change } });
    await assert.rejects(owner.result, error => error instanceof Error && error.message === "guarded HTTP/2 connection refused safely" && !error.cause);
    await owner.closed;
  });
}

test("cancellation before dispatch and after real connection retains capacity until close", async t => {
  const f = await fixture(t, stream => stream.resume());
  const first = f.start(), second = f.start(); first.cancel();
  const full = f.start();
  await assert.rejects(first.result, /refused safely/); await assert.rejects(full.result, /refused safely/);
  await first.closed; await full.closed;
  const replacement = f.start(); const [s, r] = await Promise.all([second.result, replacement.result]);
  second.cancel(); const stillHeld = f.start(); await assert.rejects(stillHeld.result, /refused safely/);
  await second.closed; assert(s.destroyed);
  const again = f.start(); await again.result;
  replacement.cancel(); again.cancel(); await Promise.all([replacement.closed, again.closed]); assert(r.destroyed);
});

for (const at of [9_999_999_999n, 10_000_000_000n, 10_000_001_000n]) {
  test(`H2 connect/settings completion at ${at}ns uses the original deadline`, async t => {
    let now = 0n;
    const f = await fixture(t, stream => stream.resume(), () => { now = at; });
    const owner = f.start({ startedAtMonotonicNs: 0n, monotonicNowNs: () => now });
    if (at < 10_000_000_000n) { await owner.result; owner.cancel(); }
    else await assert.rejects(owner.result, /guarded HTTP\/2 connection refused safely/);
    await owner.closed;
  });
}

test("original future, expired and invalid clocks do not contact the upstream", async t => {
  const f = await fixture(t, () => assert.fail("no stream"));
  for (const [start, now] of [[1n, () => 0n], [0n, () => 10_000_000_000n], [0n, () => -1n],
    [0n, () => { throw new Error("PRIVATE-CLOCK-CANARY"); }]] as const) {
    const owner = f.start({ startedAtMonotonicNs: start, monotonicNowNs: now });
    await assert.rejects(owner.result, error => error instanceof Error && error.message === "guarded HTTP/2 connection refused safely" && !error.cause);
    await owner.closed; assert.equal(f.sessions.size, 0);
  }
});

test("captured destination and native key buffers cannot change during connection", async t => {
  const f = await fixture(t, stream => stream.resume());
  const destination = { ...f.options.destination, ca: Buffer.from(certificate), cert: Buffer.from(certificate), key: Buffer.from(key) };
  const guard = { ...f.options.guard }, owner = f.start({ destination, guard });
  destination.host = "changed-name"; destination.port = 1; guard.address = "127.0.0.2";
  destination.ca.fill(0); destination.cert.fill(0); destination.key.fill(0);
  const session = await owner.result; assert(!session.destroyed);
  owner.cancel(); await owner.closed;
});

test("real GOAWAY revokes the published session and closes guarded sockets", async t => {
  const f = await fixture(t, stream => stream.resume());
  const owner = f.start(), session = await owner.result;
  [...f.sessions][0].goaway(); await owner.closed;
  assert(session.destroyed); assert.throws(() => session.request({ ":path": "/" }));
  const replacement = f.start(); await replacement.result; replacement.cancel(); await replacement.closed;
});

test("clock reentry cannot exceed the two physical connection roots", async t => {
  const f = await fixture(t, stream => stream.resume());
  let nested: ReturnType<typeof f.start> | undefined, refused: ReturnType<typeof f.start> | undefined;
  const owner = f.start({ monotonicNowNs() {
    if (!nested) { nested = f.start(); refused = f.start(); }
    return process.hrtime.bigint();
  } });
  await assert.rejects(refused!.result, /refused safely/);
  await Promise.all([owner.result, nested!.result]);
  owner.cancel(); nested!.cancel(); await Promise.all([owner.closed, nested!.closed]);
});

test("peer shutdown during H2 startup refuses without retaining a phantom slot", async t => {
  const f = await fixture(t, () => assert.fail("no stream"), session => session.destroy());
  for (let n = 0; n < 3; n++) {
    const owner = f.start(); await assert.rejects(owner.result, /guarded HTTP\/2 connection refused safely/);
    await owner.closed;
  }
});

test("uncertain TLS closure acknowledgement retains capacity after cleanup watchdog", async t => {
  const f = await fixture(t, stream => stream.resume()); let fatals = 0;
  const first = f.start({ onFatal() { fatals++; } }), second = f.start();
  const [session] = await Promise.all([first.result, second.result]);
  let release!: () => void;
  const held = new Promise<void>(done => { release = done; }), nativeClose = GuardedTlsConnector.prototype.close;
  // Test-only scheduling seam delays acknowledgement AFTER actual native close;
  // never fabricates socket closure or replaces the production TLS/H2 path.
  GuardedTlsConnector.prototype.close = function () { return nativeClose.call(this).then(() => held); };
  t.mock.timers.enable({ apis: ["setTimeout"] });
  try {
    let closed = false; void first.closed.then(() => { closed = true; });
    const native = once(session, "close"); first.cancel(); await native;
    await new Promise<void>(done => setImmediate(done)); assert.equal(closed, false);
    t.mock.timers.tick(5000); assert.equal(fatals, 1); assert.equal(closed, false);
    t.mock.timers.tick(5000); assert.equal(fatals, 1);
    const blocked = f.start(); await assert.rejects(blocked.result, /refused safely/);
    release(); await first.closed; assert.equal(closed, true);
  } finally {
    release(); GuardedTlsConnector.prototype.close = nativeClose; t.mock.timers.reset();
    first.cancel(); second.cancel(); await Promise.all([first.closed, second.closed]);
  }
});

test("late returned exchange receipt retains capacity and watchdog despite empty connector close", async t => {
  const f = await fixture(t, stream => stream.resume()), anchor = f.start(); await anchor.result;
  const native = GuardedTlsConnector.prototype.open;
  let release!: () => void, physical: Promise<void> | undefined, fatals = 0;
  const held = new Promise<void>(done => { release = done; });
  // Only hold the receipt after native closure; never fabricate physical close.
  GuardedTlsConnector.prototype.open = function (...args) {
    const exchange = native.apply(this, args); physical = exchange.closed;
    return { ...exchange, closed: exchange.closed.then(() => held) };
  };
  let owner: ReturnType<typeof f.start> | undefined, count = 0, closed = false;
  t.mock.timers.enable({ apis: ["setTimeout"] });
  try {
    owner = f.start({ onFatal() { fatals++; }, monotonicNowNs() {
      if (++count === 5) owner!.cancel(); return process.hrtime.bigint();
    } });
    void owner.closed.then(() => { closed = true; });
    await assert.rejects(owner.result); await physical; await new Promise<void>(done => setImmediate(done));
    assert.equal(closed, false); assert(physical);
    t.mock.timers.tick(5000); assert.equal(fatals, 1);
    t.mock.timers.tick(5000); assert.equal(fatals, 1); assert.equal(closed, false);
    await assert.rejects(f.start().result);
    release(); await owner.closed; assert.equal(closed, true);
  } finally {
    release(); GuardedTlsConnector.prototype.open = native; t.mock.timers.reset();
    owner?.cancel(); anchor.cancel(); await Promise.all([owner?.closed, anchor.closed, physical]);
  }
  const first = f.start(), second = f.start(); await Promise.all([first.result, second.result]);
  first.cancel(); second.cancel(); await Promise.all([first.closed, second.closed]);
});
