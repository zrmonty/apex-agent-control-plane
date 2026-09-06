import assert from "node:assert/strict";
import { once } from "node:events";
import { connect, createSecureServer, type ClientHttp2Session, type ServerHttp2Session, type ServerHttp2Stream } from "node:http2";
import { connect as tlsConnect } from "node:tls";
import type { AddressInfo } from "node:net";
import test from "node:test";
import type { TestContext } from "node:test";
import { certificate, key } from "./authority/testing-tls.js";
import { OwnedEvidenceChannel } from "./evidence-channel.js";

async function fixture(t: TestContext, handle: (stream: ServerHttp2Stream, body: Buffer) => void, now?: () => bigint,
  beforeChannel?: (session: ClientHttp2Session) => void) {
  const sessions = new Set<ServerHttp2Session>();
  const server = createSecureServer({ key, cert: certificate, ca: certificate, requestCert: true, rejectUnauthorized: true });
  server.on("session", session => { sessions.add(session); session.on("error", () => {}); session.once("close", () => sessions.delete(session)); });
  server.on("stream", (stream, headers) => {
    stream.on("error", () => {});
    assert.equal(headers[":path"], "/apex.v1.EventIngest/Ingest"); assert.equal(headers[":method"], "POST");
    assert.equal(headers.authorization, "Bearer public-test-evidence-token");
    assert.equal(headers["apex-instance-proof-bin"], undefined);
    const chunks: Buffer[] = []; stream.on("data", chunk => chunks.push(Buffer.from(chunk)));
    stream.on("end", () => handle(stream, Buffer.concat(chunks)));
  });
  server.listen(0, "127.0.0.1"); await once(server, "listening"); const port = (server.address() as AddressInfo).port;
  const session = connect(`https://grpc-contract-test:${port}`, { createConnection: () => tlsConnect({
    host: "127.0.0.1", port, servername: "grpc-contract-test", ca: certificate, cert: certificate, key,
    ALPNProtocols: ["h2"], rejectUnauthorized: true,
  }) });
  await once(session, "connect"); beforeChannel?.(session);
  const channel = new OwnedEvidenceChannel(session, "public-test-evidence-token", now);
  t.after(async () => { const closing = channel.close(); session.destroy(); for (const peer of sessions) peer.destroy();
    await closing; await new Promise<void>(done => server.close(() => done())); });
  return { channel, session };
}
function reply(stream: ServerHttp2Stream, payload = Buffer.alloc(0), status = "0") {
  const frame = Buffer.alloc(5 + payload.length); frame.writeUInt32BE(payload.length, 1); frame.set(payload, 5);
  stream.respond({ ":status": 200, "content-type": "application/grpc" }, { waitForTrailers: true });
  stream.on("wantTrailers", () => { if (!stream.destroyed) stream.sendTrailers({ "grpc-status": status }); }); stream.end(frame);
}
function start(channel: OwnedEvidenceChannel) { const now = process.hrtime.bigint(); return channel.start(Buffer.from([8, 1]), now, now + 5_000_000_000n); }

test("separate actual mTLS evidence channel frames one fixed ingest RPC and owns closure", async t => {
  let received = 0;
  const f = await fixture(t, (stream, bytes) => { received++; assert.deepEqual(bytes, Buffer.from([0, 0, 0, 0, 2, 8, 1])); reply(stream); });
  const exchange = start(f.channel); assert.deepEqual(await exchange.result, Buffer.alloc(0)); await exchange.closed; assert.equal(received, 1);
  await f.channel.close(); assert.throws(() => start(f.channel), /managed evidence refused safely/);
});

for (const failure of ["status", "content-type", "compression", "no-trailers", "grpc-status", "frame-flag", "frame-length", "oversize"]) {
  test(`actual evidence reply refuses ${failure} statically`, async t => {
    const f = await fixture(t, stream => {
      if (failure === "grpc-status") { reply(stream, Buffer.alloc(0), "7"); return; }
      const trailers = failure !== "no-trailers";
      stream.respond({ ":status": failure === "status" ? 302 : 200,
        "content-type": failure === "content-type" ? "text/html" : "application/grpc",
        ...(failure === "compression" ? { "grpc-encoding": "gzip" } : {}),
      }, { waitForTrailers: trailers });
      if (trailers) stream.on("wantTrailers", () => { if (!stream.destroyed) stream.sendTrailers({ "grpc-status": "0" }); });
      const body = Buffer.alloc(failure === "oversize" ? 8198 : 5);
      if (failure === "frame-flag") body[0] = 1;
      if (failure === "frame-length") body.writeUInt32BE(1, 1);
      stream.end(body);
    });
    const exchange = start(f.channel); await assert.rejects(exchange.result, /^Error: managed evidence refused safely$/); await exchange.closed;
  });
}

test("payload and deadline bounds refuse before opening an evidence stream", async t => {
  let received = 0;
  const f = await fixture(t, stream => { received++; reply(stream); }); const now = process.hrtime.bigint();
  for (const input of [[Buffer.alloc(65537), now, now + 1n], [Buffer.alloc(0), now, now], [Buffer.alloc(0), -1n, now]] as const)
    assert.throws(() => f.channel.start(input[0], input[1], input[2]), /managed evidence refused safely/);
  assert.equal(received, 0);
});

test("response callback cannot beat the original evidence deadline", async t => {
  let now = process.hrtime.bigint(); const initial = now;
  const f = await fixture(t, stream => { now = initial + 5_000_000_000n; reply(stream); }, () => now);
  const exchange = f.channel.start(Buffer.alloc(0), initial, initial + 60_000_000_000n);
  await assert.rejects(exchange.result, /^Error: managed evidence refused safely$/); await exchange.closed;
});

test("cancelled evidence stream keeps physical capacity and root close until native stream close", async t => {
  const f = await fixture(t, _stream => {});
  const releases: Array<() => void> = [], request = f.session.request.bind(f.session);
  let reached!: () => void; const allCloseEvents = new Promise<void>(done => { reached = done; });
  t.mock.method(f.session, "request", (...args: Parameters<typeof request>) => {
    const stream = request(...args), emit = stream.emit;
    t.mock.method(stream, "emit", function (event: string | symbol, ...values: unknown[]) {
      if (event === "close") {
        releases.push(() => Reflect.apply(emit, stream, [event, ...values])); if (releases.length === 32) reached(); return true;
      }
      return Reflect.apply(emit, stream, [event, ...values]);
    });
    return stream;
  });
  const exchanges = Array.from({ length: 32 }, () => start(f.channel));
  const rejected = exchanges.map(exchange => assert.rejects(exchange.result, /managed evidence refused safely/));
  assert.throws(() => start(f.channel), /managed evidence refused safely/);
  for (const exchange of exchanges) exchange.cancel(); await Promise.all(rejected);
  await new Promise<void>(done => setImmediate(done));
  assert.throws(() => start(f.channel), /managed evidence refused safely/);
  let closed = false; const closing = f.channel.close().then(() => { closed = true; });
  // Wait for the actual close events, not a fabricated closure promise.
  await allCloseEvents;
  assert.equal(closed, false); for (const release of releases) release();
  await Promise.all(exchanges.map(exchange => exchange.closed)); await closing;
});

test("one evidence stream cancellation leaves a concurrent ingest intact", async t => {
  let requests = 0, firstSeen!: () => void; const firstReceived = new Promise<void>(done => { firstSeen = done; });
  const f = await fixture(t, stream => { if (++requests === 1) firstSeen(); else reply(stream, Buffer.from([8, 1])); });
  const first = start(f.channel), rejected = assert.rejects(first.result, /managed evidence refused safely/);
  await firstReceived; const second = start(f.channel); first.cancel(); await rejected;
  assert.deepEqual(await second.result, Buffer.from([8, 1])); await Promise.all([first.closed, second.closed]);
});

test("unsolicited native pushes fail closed even before push-disable SETTINGS reaches the peer", { timeout: 5000 }, async t => {
  const pushed: ServerHttp2Stream[] = [];
  const f = await fixture(t, stream => {
    assert.equal(stream.pushAllowed, true); // Actual pre-negotiation window, not a synthetic stream.
    for (let i = 0; i < 33; i++) stream.pushStream({ ":path": `/unexpected/${i}` }, (error, push) => {
      assert.ifError(error); pushed.push(push); push.on("error", () => {});
      push.respond({ ":status": 200 }); push.write("unowned bytes");
      if (pushed.length === 33) reply(stream);
    });
  }, undefined, session => {
    // Delay only SETTINGS at the native boundary. Keep the H2/TLS peer and all
    // push creation, data, cancellation and physical close operations real.
    t.mock.method(session, "settings", () => {});
  });
  const exchange = start(f.channel);
  await assert.rejects(exchange.result, /^Error: managed evidence refused safely$/);
  await exchange.closed;
  assert.equal(pushed.length, 33);
  assert.equal(f.session.destroyed, true);
  assert.throws(() => start(f.channel), /managed evidence refused safely/);
  await f.channel.close();
});

test("root drain owns queued native pushes until every held native close arrives", { timeout: 5000 }, async t => {
  const releases: Array<() => void> = [];
  const queued: Array<() => void> = [];
  let pushed = 0, allSeen!: () => void, allClosed!: () => void;
  const incoming = new Promise<void>(done => { allSeen = done; });
  const nativeCloses = new Promise<void>(done => { allClosed = done; });
  let physical!: Promise<unknown>;
  const f = await fixture(t, stream => {
    assert.equal(stream.pushAllowed, true);
    for (let i = 0; i < 3; i++) stream.pushStream({ ":path": `/queued/${i}` }, (error, push) => {
      assert.ifError(error); push.on("error", () => {});
      push.respond({ ":status": 200 }); push.write("never finishes");
      if (++pushed === 3) reply(stream);
    });
  }, undefined, session => {
    physical = Promise.all([new Promise<void>(done => session.once("close", done)),
      new Promise<void>(done => session.socket.once("close", () => done()))]);
    t.mock.method(session, "settings", () => {});
    const sessionEmit = session.emit;
    t.mock.method(session, "emit", function (event: string | symbol, ...values: unknown[]) {
      if (event !== "stream") return Reflect.apply(sessionEmit, session, [event, ...values]);
      const stream = values[0] as import("node:http2").ClientHttp2Stream, emit = stream.emit;
      t.mock.method(stream, "emit", function (streamEvent: string | symbol, ...args: unknown[]) {
        if (streamEvent !== "close") return Reflect.apply(emit, stream, [streamEvent, ...args]);
        releases.push(() => Reflect.apply(emit, stream, [streamEvent, ...args]));
        if (releases.length === 3) allClosed();
        return true;
      });
      // Hold only delivery of actual native events so packet fragmentation
      // cannot erase the already-queued-after-shutdown case under test.
      queued.push(() => Reflect.apply(sessionEmit, session, [event, ...values]));
      if (queued.length === 3) allSeen();
      return true;
    });
  });
  const exchange = start(f.channel), result = exchange.result.catch(() => undefined);
  try {
    await incoming;
    for (const deliver of queued.splice(0)) deliver();
    let drained = false;
    const closing = f.channel.close().then(() => { drained = true; });
    await Promise.all([nativeCloses, physical, result, exchange.closed]);
    await new Promise<void>(done => setImmediate(done));
    assert.equal(drained, false, "H2/TLS close is not incoming-stream close");
    releases.shift()!();
    await new Promise<void>(done => setImmediate(done));
    assert.equal(drained, false, "pushes queued after the first push also retain root drain");
    for (const release of releases.splice(0)) release();
    await closing;
    assert.equal(drained, true);
  } finally {
    for (const release of releases.splice(0)) release();
  }
});

test("native peer observes push disabled before ordinary reusable evidence requests", async t => {
  let requests = 0;
  const f = await fixture(t, stream => {
    assert.equal(stream.pushAllowed, false);
    assert.throws(() => stream.pushStream({ ":path": "/not-allowed" }, () => {}),
      { code: "ERR_HTTP2_PUSH_DISABLED" });
    requests++; reply(stream);
  });
  for (let i = 0; i < 2; i++) {
    const exchange = start(f.channel);
    assert.deepEqual(await exchange.result, Buffer.alloc(0)); await exchange.closed;
  }
  assert.equal(requests, 2);
});
