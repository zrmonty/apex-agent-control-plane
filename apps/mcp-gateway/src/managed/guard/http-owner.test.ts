import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer, ClientRequest, IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { connect, type AddressInfo, type Socket } from "node:net";
import { test, type TestContext } from "node:test";
import { certificate, key } from "../authority/testing-tls.js";
import { GuardedTlsConnector } from "./tls-connector.js";
import { OwnedHttpClient, type OwnedHttpRequest } from "./http-owner.js";

async function fixture(t: TestContext, handle: (req: IncomingMessage, res: ServerResponse) => void,
  afterTunnel?: () => void, now?: () => bigint) {
  const sockets = new Set<Socket>();
  const track = (s: Socket) => { sockets.add(s); s.on("error", () => {}); s.once("close", () => sockets.delete(s)); };
  const server = createHttpsServer({ key, cert: certificate, ca: certificate, requestCert: true,
    rejectUnauthorized: true, ALPNProtocols: ["http/1.1"] }, handle);
  server.on("connection", track); server.on("tlsClientError", () => {});
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const upstreamPort = (server.address() as AddressInfo).port;
  // TEST ONLY loopback CONNECT relay; no real guard policy or kernel proof.
  const guard = createServer(); guard.on("connection", track);
  guard.on("connect", (_req, socket, head) => {
    const remote = connect(upstreamPort, "127.0.0.1"); track(remote);
    socket.once("close", () => remote.destroy()); remote.once("close", () => socket.destroy());
    remote.once("connect", () => {
      afterTunnel?.(); socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) remote.write(head); socket.pipe(remote).pipe(socket);
    });
  });
  guard.listen(0, "127.0.0.1"); await once(guard, "listening");
  const connector = new GuardedTlsConnector({ address: "127.0.0.1", port: (guard.address() as AddressInfo).port }, [{
    id: "upstream", host: "grpc-contract-test", port: upstreamPort, alpn: "http/1.1",
    authentication: "mutual_tls", ca: certificate, cert: certificate, key,
  }]);
  const client = new OwnedHttpClient(connector, { destinationId: "upstream", url: `https://grpc-contract-test:${upstreamPort}/mcp` }, now);
  t.after(async () => {
    await client.close(); await connector.close();
    for (const socket of sockets) socket.destroy();
    await Promise.all([server, guard].map(s => new Promise<void>(done => s.close(() => done()))));
  });
  return { client, connector };
}
function request(beforeWrite: () => void = () => {}): OwnedHttpRequest {
  const started = process.hrtime.bigint();
  return { method: "POST", body: Buffer.from('{"jsonrpc":"2.0","method":"tools/call","id":1}'),
    startedAtMonotonicNs: started, deadlineMonotonicNs: started + 30_000_000_000n, beforeWrite };
}
async function body(value: AsyncIterable<Uint8Array>): Promise<string> {
  const chunks: Uint8Array[] = []; for await (const chunk of value) chunks.push(chunk);
  return Buffer.concat(chunks).toString();
}

test("native HTTP waits for guarded TLS then writes once and owns the complete response body", async t => {
  let received = 0, gate = 0;
  const f = await fixture(t, (req, res) => {
    received++; assert.equal(gate, 1); assert.equal(req.url, "/mcp");
    assert.equal(req.headers.host?.startsWith("grpc-contract-test:"), true);
    assert.equal(req.headers["content-type"], "application/json");
    const chunks: Buffer[] = []; req.on("data", chunk => chunks.push(chunk));
    req.on("end", () => {
      assert.equal(Buffer.concat(chunks).toString(), '{"jsonrpc":"2.0","method":"tools/call","id":1}');
      res.writeHead(200, { "content-type": "application/json" }); res.end('{"result":"real body"}');
    });
  });
  const exchange = f.client.start(request(() => { gate++; }));
  const response = await exchange.result; assert.equal(response.status, 200);
  assert.equal(await body(response.body), '{"result":"real body"}');
  await exchange.closed; assert.equal(received, 1); assert.equal(gate, 1);
});

test("revocation during tunnel preparation prevents every HTTP header and business byte", async t => {
  let allowed = true, received = 0, checked = 0;
  const f = await fixture(t, (_req, res) => { received++; res.end(); }, () => { allowed = false; });
  const exchange = f.client.start(request(() => { checked++; if (!allowed) throw new Error("PRIVATE_REASON"); }));
  await assert.rejects(exchange.result, /^Error: managed HTTP refused safely$/);
  await exchange.closed; assert.equal(checked, 1); assert.equal(received, 0);
});

test("cancel after headers aborts an active SSE body and waits actual cleanup", async t => {
  const f = await fixture(t, (_req, res) => {
    res.writeHead(200, { "content-type": "text/event-stream" }); res.write("data: first\n\n");
  });
  const exchange = f.client.start(request());
  const response = await exchange.result;
  const iterator = response.body[Symbol.asyncIterator]();
  assert.equal(Buffer.from((await iterator.next()).value!).toString(), "data: first\n\n");
  const waiting = assert.rejects(iterator.next(), /^Error: managed HTTP refused safely$/);
  let closed = false; void exchange.closed.then(() => { closed = true; });
  await Promise.resolve(); assert.equal(closed, false);
  exchange.cancel(); await waiting; await exchange.closed; assert.equal(closed, true);
});

test("cancelled empty body cannot later be delivered as successful completion", async t => {
  const f = await fixture(t, (_req, res) => { res.writeHead(204); res.end(); });
  const exchange = f.client.start(request());
  const response = await exchange.result;
  exchange.cancel(); await exchange.closed;
  await assert.rejects(body(response.body), /^Error: managed HTTP refused safely$/);
});

test("body reading retains the original deadline after response headers", async t => {
  let now = process.hrtime.bigint();
  const f = await fixture(t, (_req, res) => {
    res.writeHead(200, { "content-type": "text/event-stream" }); res.write("data: buffered\n\n");
  }, undefined, () => now);
  const input = { ...request(), startedAtMonotonicNs: now, deadlineMonotonicNs: now + 30_000_000_000n };
  const exchange = f.client.start(input); const response = await exchange.result;
  now = input.deadlineMonotonicNs;
  await assert.rejects(body(response.body), /^Error: managed HTTP refused safely$/); await exchange.closed;
});

test("oversized response body refuses and closes without passing an oversized chunk", async t => {
  const f = await fixture(t, (_req, res) => {
    res.writeHead(200, { "content-type": "application/json" }); res.end(Buffer.alloc(1_048_577, 120));
  });
  const exchange = f.client.start(request()); const response = await exchange.result;
  let delivered = 0;
  await assert.rejects(async () => {
    for await (const chunk of response.body) delivered += chunk.length;
  }, /^Error: managed HTTP refused safely$/);
  assert.ok(delivered <= 1_048_576); await exchange.closed;
});

test("async final authority callback is rejected without an upstream request or unhandled rejection", async t => {
  let received = 0;
  const f = await fixture(t, (_req, res) => { received++; res.end(); });
  const exchange = f.client.start(request(() => Promise.reject(new Error("PRIVATE_ASYNC_REASON"))));
  await assert.rejects(exchange.result, /^Error: managed HTTP refused safely$/);
  await exchange.closed; assert.equal(received, 0);
});

test("redirect response is not followed or replayed", async t => {
  let received = 0;
  const f = await fixture(t, (_req, res) => { received++; res.writeHead(307, { location: "https://evil.invalid" }); res.end(); });
  const exchange = f.client.start(request());
  await assert.rejects(exchange.result, /^Error: managed HTTP refused safely$/);
  await exchange.closed; assert.equal(received, 1);
});

test("authority is rechecked after native request socket assignment, not before a queued end", async t => {
  let allowed = true, received = 0, checked = 0;
  const f = await fixture(t, (_req, res) => { received++; res.end("unexpected write"); });
  const original = ClientRequest.prototype.onSocket;
  t.mock.method(ClientRequest.prototype, "onSocket", function (this: ClientRequest, socket: Socket) {
    // Real Node assignment is queued by onSocket. Revoke before that queue
    // runs, after TLS preparation and HTTP request construction have begun.
    queueMicrotask(() => { allowed = false; });
    return original.call(this, socket);
  });
  const exchange = f.client.start(request(() => { checked++; if (!allowed) throw new Error("revoked"); }));
  await assert.rejects(exchange.result, /^Error: managed HTTP refused safely$/);
  await exchange.closed; assert.equal(received, 0); assert.equal(checked, 1);
});

test("one SSE cancellation preserves a different request group", async t => {
  const f = await fixture(t, (_req, res) => {
    res.writeHead(200, { "content-type": "text/event-stream" }); res.write("data: independent\n\n");
  });
  const first = f.client.start(request()), second = f.client.start(request());
  const firstResponse = await first.result, secondResponse = await second.result;
  const firstIterator = firstResponse.body[Symbol.asyncIterator](), secondIterator = secondResponse.body[Symbol.asyncIterator]();
  await firstIterator.next();
  first.cancel(); await first.closed;
  assert.equal(Buffer.from((await secondIterator.next()).value!).toString(), "data: independent\n\n");
  second.cancel(); await second.closed;
});

test("shutdown before native socket assignment cannot send a late request", async t => {
  let received = 0;
  const f = await fixture(t, (_req, res) => { received++; res.end(); });
  const original = ClientRequest.prototype.onSocket;
  let closing: Promise<void> | undefined;
  t.mock.method(ClientRequest.prototype, "onSocket", function (this: ClientRequest, socket: Socket) {
    queueMicrotask(() => { closing = f.client.close(); });
    return original.call(this, socket);
  });
  const exchange = f.client.start(request());
  await assert.rejects(exchange.result, /^Error: managed HTTP refused safely$/);
  await exchange.closed; await closing;
  assert.equal(received, 0);
  assert.throws(() => f.client.start(request()), /managed HTTP refused safely/);
});

test("physical request close is required even after connector sockets have closed", async t => {
  const f = await fixture(t, (_req, res) => { res.writeHead(200); res.write("held body"); });
  const original = ClientRequest.prototype.emit;
  let reached!: () => void, release!: () => void;
  const held = new Promise<void>(done => { reached = done; });
  t.mock.method(ClientRequest.prototype, "emit", function (this: ClientRequest, event: string | symbol, ...args: unknown[]) {
    if (event === "close") { release = () => Reflect.apply(original, this, [event, ...args]); reached(); return true; }
    return Reflect.apply(original, this, [event, ...args]);
  });
  const exchange = f.client.start(request()); await exchange.result;
  exchange.cancel(); await held;
  let closed = false; void exchange.closed.then(() => { closed = true; });
  await f.connector.close(); await Promise.resolve(); assert.equal(closed, false);
  let rootClosed = false; const closing = f.client.close().then(() => { rootClosed = true; });
  await Promise.resolve(); assert.equal(rootClosed, false);
  release(); await exchange.closed; await closing;
});

for (const durationUs of [1n, 7n, 999n]) {
  test(`final gate time is charged at an exact ${durationUs}us deadline`, async t => {
    // Hold the reporting timer so this proves the synchronous final check, not
    // a millisecond timer expiring while the actual TLS fixture is preparing.
    const originalTimer = globalThis.setTimeout;
    t.mock.method(globalThis, "setTimeout", (callback: (...args: unknown[]) => void, delay?: number, ...args: unknown[]) =>
      originalTimer(callback, Math.max(delay ?? 0, 1000), ...args));
    let now = process.hrtime.bigint(), received = 0, gates = 0;
    const f = await fixture(t, (_req, res) => { received++; res.end(); }, undefined, () => now);
    const deadline = now + durationUs * 1000n;
    const exchange = f.client.start({ ...request(() => { gates++; now = deadline; }),
      startedAtMonotonicNs: now, deadlineMonotonicNs: deadline });
    await assert.rejects(exchange.result, /^Error: managed HTTP refused safely$/);
    await exchange.closed; assert.equal(received, 0); assert.equal(gates, 1);
  });
}

test("request headers and bytes cannot change during asynchronous preparation", async t => {
  let received = "";
  const f = await fixture(t, (req, res) => {
    assert.equal(req.headers["mcp-session-id"], "captured-session");
    req.on("data", chunk => { received += chunk.toString(); }); req.on("end", () => res.end());
  });
  const bytes = Buffer.from("original bytes");
  const input = { ...request(), body: bytes, sessionId: "captured-session" };
  const exchange = f.client.start(input); bytes.fill(120); input.sessionId = "changed-session";
  const response = await exchange.result; await body(response.body); await exchange.closed;
  assert.equal(received, "original bytes");
});

test("a complete body remains readable after its normal guarded connector closes", async t => {
  const f = await fixture(t, (_req, res) => { res.writeHead(200); res.end("complete buffered response"); });
  let nativeClosed!: Promise<void>;
  const open = f.connector.open.bind(f.connector);
  t.mock.method(f.connector, "open", (...args: Parameters<typeof open>) => {
    const exchange = open(...args); nativeClosed = exchange.closed; return exchange;
  });
  const exchange = f.client.start(request()); const response = await exchange.result;
  await nativeClosed;
  let closed = false; void exchange.closed.then(() => { closed = true; });
  await Promise.resolve(); assert.equal(closed, false);
  assert.equal(await body(response.body), "complete buffered response");
  await exchange.closed;
});

test("paused iterator retains its final buffered bytes after normal connection closure", async t => {
  let finish!: () => void;
  const f = await fixture(t, (_req, res) => { res.writeHead(200); res.write("first"); finish = () => res.end("last"); });
  let nativeClosed!: Promise<void>;
  const open = f.connector.open.bind(f.connector);
  t.mock.method(f.connector, "open", (...args: Parameters<typeof open>) => {
    const exchange = open(...args); nativeClosed = exchange.closed; return exchange;
  });
  const exchange = f.client.start(request()); const response = await exchange.result;
  const iterator = response.body[Symbol.asyncIterator]();
  assert.equal(Buffer.from((await iterator.next()).value!).toString(), "first");
  finish(); await nativeClosed;
  assert.equal(Buffer.from((await iterator.next()).value!).toString(), "last");
  assert.equal((await iterator.next()).done, true); await exchange.closed;
});

test("unconsumed complete body keeps its reporting timer after normal connector closure", async t => {
  let expire!: () => void;
  const originalTimer = globalThis.setTimeout;
  t.mock.method(globalThis, "setTimeout", (callback: (...args: unknown[]) => void, delay?: number, ...args: unknown[]) => {
    if (delay !== undefined && delay > 20_000 && delay <= 30_000) expire = () => callback(...args);
    return originalTimer(callback, delay, ...args);
  });
  const f = await fixture(t, (_req, res) => { res.writeHead(200); res.end("unconsumed until deadline"); });
  let nativeClosed!: Promise<void>;
  const open = f.connector.open.bind(f.connector);
  t.mock.method(f.connector, "open", (...args: Parameters<typeof open>) => {
    const exchange = open(...args); nativeClosed = exchange.closed; return exchange;
  });
  const exchange = f.client.start(request()); const response = await exchange.result;
  await nativeClosed; assert.equal(typeof expire, "function");
  expire(); await exchange.closed;
  await assert.rejects(body(response.body), /^Error: managed HTTP refused safely$/);
});

test("normal consumed body still owns capacity until its actual response close event", async t => {
  const f = await fixture(t, (_req, res) => { res.writeHead(200); res.end("owned response"); });
  let reached!: () => void, release!: () => void;
  const held = new Promise<void>(done => { reached = done; });
  const original = IncomingMessage.prototype.emit;
  t.mock.method(IncomingMessage.prototype, "emit", function (this: IncomingMessage, event: string | symbol, ...args: unknown[]) {
    if (event === "close" && this.statusCode === 200) {
      release = () => Reflect.apply(original, this, [event, ...args]); reached(); return true;
    }
    return Reflect.apply(original, this, [event, ...args]);
  });
  const exchange = f.client.start(request()); const response = await exchange.result;
  const reading = body(response.body); await held; await f.connector.close();
  let closed = false; void exchange.closed.then(() => { closed = true; });
  await Promise.resolve(); assert.equal(closed, false);
  release(); assert.equal(await reading, "owned response"); await exchange.closed;
});
