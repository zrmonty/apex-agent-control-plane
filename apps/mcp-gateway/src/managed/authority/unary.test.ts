import assert from "node:assert/strict";
import { once } from "node:events";
import { connect, createSecureServer, type ServerHttp2Stream, type IncomingHttpHeaders } from "node:http2";
import { connect as tlsConnect } from "node:tls";
import { test, type TestContext } from "node:test";
import { certificate, key } from "./testing-tls.js";
import { OwnedAuthorityChannel } from "./unary.js";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { RuntimeNetworkInspectionRequestSchema as NetworkRequest, RuntimeNetworkInspectionResponseSchema as NetworkResponse } from "@apex/contracts";
import { NetworkReadinessClient } from "./network-readiness.js";
import { binding } from "./business-testing.js";
import { readBinding } from "./grant-transport.js";
import { isDependencyUnavailable } from "./dependency-failure.js";

const path = "/apex.v1.ManagedRuntimeAuthority/RenewDeployment";
const credential = { token: "public-test-workload-token-not-a-secret", instanceProof: Buffer.alloc(32, 7) };

for (const placement of ["headers", "trailers"] as const) {
  for (const status of ["8", "14", "7", "16", "13", "014"]) {
    test(`actual authority ${placement} gRPC ${status} classifies only ordinary readiness refusal`, async t => {
      const { channel } = await fixture(t, stream => {
        stream.resume(); stream.on("end", () => {
          stream.respond({ ":status": 200, "content-type": "application/grpc",
            ...(placement === "headers" ? { "grpc-status": status } : {}) }, { waitForTrailers: placement === "trailers" });
          if (placement === "trailers") stream.on("wantTrailers", () => stream.sendTrailers({ "grpc-status": status }));
          stream.end();
        });
      });
      const job = channel.start("/apex.v1.ManagedNetworkReadiness/Check", Buffer.alloc(0));
      await assert.rejects(job.result, error => {
        assert.equal(String(error), "Error: managed authority refused safely");
        assert.equal(isDependencyUnavailable(error), status === "8" || status === "14"); return true;
      });
      await job.closed;
    });
  }
}

test("ordinary authority error status with a message body is terminal malformed framing", async t => {
  const { channel } = await fixture(t, stream => {
    stream.resume(); stream.on("end", () => {
      stream.respond({ ":status": 200, "content-type": "application/grpc" }, { waitForTrailers: true });
      stream.on("wantTrailers", () => stream.sendTrailers({ "grpc-status": "14" })); stream.end(frame(Buffer.from([8, 1])));
    });
  });
  const job = channel.start("/apex.v1.ManagedNetworkReadiness/Check", Buffer.alloc(0));
  await assert.rejects(job.result, error => { assert.equal(isDependencyUnavailable(error), false); return true; });
  await job.closed;
});

test("typed NETWORK nonce and original binding traverse the actual workload TLS channel", async t => {
  const hash = "c".repeat(64);
  let requests = 0;
  const { channel } = await fixture(t, (stream, headers) => {
    assert.equal(headers[":path"], "/apex.v1.ManagedNetworkReadiness/Check");
    const chunks: Buffer[] = [];
    stream.on("data", b => chunks.push(Buffer.from(b)));
    stream.on("end", () => {
      if (++requests === 1) {
        stream.respond({ ":status": 200, "content-type": "application/grpc", "grpc-status": "8" });
        stream.end(); return;
      }
      const body = Buffer.concat(chunks);
      assert.equal(body[0], 0); assert.equal(body.readUInt32BE(1), body.length - 5);
      const request = fromBinary(NetworkRequest, body.subarray(5));
      assert.deepEqual(readBinding(request.binding), binding); assert.equal(request.nonce.length, 32);
      const response = create(NetworkResponse, { schemaVersion: 1, binding: request.binding, nonce: request.nonce,
        networkBindingSha256: hash, gatewayProcessSha256: "d".repeat(64), guardProcessSha256: "e".repeat(64),
        confined: true, validForUs: 10_000_000n });
      stream.respond({ ":status": 200, "content-type": "application/grpc" }, { waitForTrailers: true });
      stream.on("wantTrailers", () => stream.sendTrailers({ "grpc-status": "0" }));
      stream.end(frame(toBinary(NetworkResponse, response)));
    });
  });
  const client = new NetworkReadinessClient(binding, hash, channel);
  const coldStart = process.hrtime.bigint(), busy = client.start(coldStart, coldStart + 2_000_000_000n);
  await assert.rejects(busy.result, error => {
    assert.equal(String(error), "Error: managed network readiness refused safely");
    assert.equal(isDependencyUnavailable(error), true); return true;
  });
  await busy.closed;
  const start = process.hrtime.bigint(), job = client.start(start, start + 2_000_000_000n);
  assert.deepEqual(await job.result, { validUntilMonotonicNs: start + 10_000_000_000n });
  await job.closed; await client.close();
  assert.equal(requests, 2);
});

test("network readiness uses workload credentials but cannot call the Controller-only agent service", async t => {
  const method = "/apex.v1.ManagedNetworkReadiness/Check";
  const { channel } = await fixture(t, (stream, headers) => {
    assert.equal(headers[":path"], method);
    assert.equal(headers.authorization, `Bearer ${credential.token}`);
    assert.equal(headers["apex-instance-proof-bin"], credential.instanceProof.toString("base64"));
    stream.resume();
    stream.on("end", () => {
      stream.respond({ ":status": 200, "content-type": "application/grpc" }, { waitForTrailers: true });
      stream.on("wantTrailers", () => stream.sendTrailers({ "grpc-status": "0" }));
      stream.end(frame(Buffer.from([8, 1])));
    });
  });
  assert.throws(() => channel.start("/apex.v1.RuntimeNetworkInspection/Check", Buffer.from([8, 1])));
  const exchange = channel.start(method, Buffer.from([8, 1]));
  assert.deepEqual(await exchange.result, Buffer.from([8, 1])); await exchange.closed;
});
function frame(payload: Uint8Array) {
  const output = Buffer.alloc(5 + payload.length);
  output.writeUInt32BE(payload.length, 1); output.set(payload, 5); return output;
}
async function fixture(t: TestContext, handle: (stream: ServerHttp2Stream, headers: IncomingHttpHeaders) => void,
  now?: () => bigint) {
  const sessions = new Set<import("node:http2").ServerHttp2Session>();
  const server = createSecureServer({ key, cert: certificate, ca: certificate,
    requestCert: true, rejectUnauthorized: true });
  server.on("session", session => { sessions.add(session); session.on("close", () => sessions.delete(session)); });
  server.on("stream", (stream, headers) => { stream.on("error", () => {}); handle(stream, headers); });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const port = (server.address() as import("node:net").AddressInfo).port;
  const session = connect(`https://grpc-contract-test:${port}`, { createConnection: () => tlsConnect({
    host: "127.0.0.1", port, servername: "grpc-contract-test", ca: certificate, cert: certificate, key,
    ALPNProtocols: ["h2"], rejectUnauthorized: true,
  }) });
  await once(session, "connect");
  const channel = new OwnedAuthorityChannel(session, credential, now);
  t.after(async () => {
    const closing = channel.close();
    session.destroy();
    for (const connection of sessions) connection.destroy();
    await closing;
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  });
  return { channel, session };
}

test("canonical unary framing and separate proof metadata traverse actual mutually authenticated TLS", async t => {
  let received!: Buffer;
  const { channel } = await fixture(t, (stream, headers) => {
    assert.equal(headers[":path"], path);
    assert.equal(headers.authorization, `Bearer ${credential.token}`);
    assert.equal(headers["apex-instance-proof-bin"], credential.instanceProof.toString("base64"));
    assert.equal(headers["grpc-timeout"], "10000000u");
    assert.equal(headers.te, "trailers");
    const chunks: Buffer[] = [];
    stream.on("data", chunk => chunks.push(Buffer.from(chunk)));
    stream.on("end", () => {
      received = Buffer.concat(chunks);
      stream.respond({ ":status": 200, "content-type": "application/grpc" }, { waitForTrailers: true });
      stream.on("wantTrailers", () => stream.sendTrailers({ "grpc-status": "0" }));
      stream.end(frame(Buffer.from([8, 7])));
    });
  });
  const exchange = channel.start(path, Buffer.from([8, 1]));
  assert.deepEqual(await exchange.result, Buffer.from([8, 7]));
  await exchange.closed;
  assert.deepEqual(received, frame(Buffer.from([8, 1])));
});

for (const elapsed of [9_999_999_000n, 10_000_000_000n, 10_000_000_001n]) {
test(`response at ${elapsed}ns checks the deadline before any overdue timer callback`, async t => {
  let now = 0n;
  const { channel } = await fixture(t, stream => {
    stream.resume(); stream.on("end", () => {
      now = elapsed;
      stream.respond({ ":status": 200, "content-type": "application/grpc" }, { waitForTrailers: true });
      stream.on("wantTrailers", () => stream.sendTrailers({ "grpc-status": "0" }));
      stream.end(frame(Buffer.from([8, 7])));
    });
  }, () => now);
  const exchange = channel.start(path, Buffer.from([8, 1]));
  if (elapsed < 10_000_000_000n) assert.deepEqual(await exchange.result, Buffer.from([8, 7]));
  else await assert.rejects(exchange.result, /managed authority refused safely/);
  await exchange.closed;
});
}

test("a broken monotonic clock closes the owned channel with redacted errors", async t => {
  let broken = true;
  const { channel } = await fixture(t, stream => stream.resume(), () => {
    if (broken) throw new Error("CLOCK_CANARY"); return 0n;
  });
  assert.throws(() => channel.start(path, Buffer.from([8, 1])), error => {
    assert.equal((error as Error).message, "managed authority refused safely"); return true;
  });
  broken = false;
  assert.throws(() => channel.start(path, Buffer.from([8, 1])), /managed authority refused safely/);
  await channel.close();
});

test("cancellation owns a real stream until close and channel close refuses later admission", async t => {
  const { channel } = await fixture(t, stream => { stream.resume(); });
  const exchange = channel.start(path, Buffer.from([8, 1]));
  const rejected = assert.rejects(exchange.result, /managed authority refused safely/);
  exchange.cancel();
  await rejected; await exchange.closed; await channel.close();
  assert.throws(() => channel.start(path, Buffer.from([8, 1])), /managed authority refused safely/);
});

for (const [name, body, status, contentType] of [
  ["compression", Buffer.from([1, 0, 0, 0, 0]), "0", "application/grpc"],
  ["truncated frame", Buffer.from([0, 0, 0, 0, 2, 8]), "0", "application/grpc"],
  ["multiple unary messages", Buffer.concat([frame(Buffer.from([8, 1])), frame(Buffer.from([8, 2]))]), "0", "application/grpc"],
  ["oversize message", frame(Buffer.alloc(65_537)), "0", "application/grpc"],
  ["remote denial", frame(Buffer.from([8, 1])), "7", "application/grpc"],
  ["wrong media type", frame(Buffer.from([8, 1])), "0", "text/plain"],
] as const) {
  test(`refuses ${name} and retains cleanup ownership`, async t => {
    const { channel } = await fixture(t, stream => {
      stream.resume();
      stream.on("end", () => {
        stream.respond({ ":status": 200, "content-type": contentType }, { waitForTrailers: true });
        stream.on("wantTrailers", () => { if (!stream.destroyed) stream.sendTrailers({ "grpc-status": status }); });
        stream.end(body);
      });
    });
    const exchange = channel.start(path, Buffer.from([8, 1]));
    await assert.rejects(exchange.result, /managed authority refused safely/);
    await exchange.closed;
  });
}

test("128 canceled results cannot free capacity while their actual stream close is held", async t => {
  const { channel, session } = await fixture(t, stream => stream.resume());
  const originalRequest = session.request.bind(session);
  const release: Array<() => void> = [];
  // Fault injection intercepts only cancellation dispatch; real sockets remain open.
  // This proves capacity is tied to native close, not result rejection or a timer.
  session.request = (...args: Parameters<typeof session.request>) => {
    const stream = originalRequest(...args);
    const originalClose = stream.close.bind(stream);
    stream.close = () => {};
    release.push(() => { stream.close = originalClose; stream.close(8); });
    return stream;
  };
  const exchanges = Array.from({ length: 128 }, () => channel.start(path, Buffer.from([8, 1])));
  const failures = exchanges.map(exchange => assert.rejects(exchange.result, /managed authority refused safely/));
  let physicallyClosed = 0;
  for (const exchange of exchanges) { void exchange.closed.then(() => { physicallyClosed++; }); exchange.cancel(); }
  await Promise.all(failures);
  assert.equal(physicallyClosed, 0);
  assert.throws(() => channel.start(path, Buffer.from([8, 1])), /managed authority refused safely/);
  for (const end of release) end();
  await Promise.all(exchanges.map(exchange => exchange.closed));
  assert.equal(physicallyClosed, 128);
  session.request = originalRequest;
  const next = channel.start(path, Buffer.from([8, 1]));
  const rejected = assert.rejects(next.result); next.cancel(); await rejected; await next.closed;
});

test("request method, payload and credential bounds refuse before dispatch", async t => {
  let dispatched = 0;
  const { channel, session } = await fixture(t, stream => { dispatched++; stream.resume(); });
  assert.throws(() => channel.start("/arbitrary.Service/Execute", Buffer.alloc(0)));
  assert.throws(() => channel.start(path, Buffer.alloc(65_537)));
  assert.throws(() => new OwnedAuthorityChannel(session, { ...credential, token: "untrusted\r\nheader" }));
  assert.throws(() => new OwnedAuthorityChannel(session, { ...credential, instanceProof: Buffer.alloc(31) }));
  await channel.close(); assert.equal(dispatched, 0);
});
