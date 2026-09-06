import assert from "node:assert/strict";
import { once } from "node:events";
import { connect, createSecureServer, type ServerHttp2Stream, type IncomingHttpHeaders } from "node:http2";
import { connect as tlsConnect } from "node:tls";
import { test, type TestContext } from "node:test";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { ManagedCallAuthorizationRequestSchema, ManagedCallAuthorizationDecisionSchema,
  ManagedCallCompletionSchema, ManagedCallCompletionReceiptSchema, ManagedPolicyRequestSchema,
  ManagedPolicySnapshotSchema } from "@apex/contracts";
import { certificate, key } from "./testing-tls.js";
import { OwnedAuthorityChannel } from "./unary.js";
import { AuthenticatedBusinessTransport } from "./business-transport.js";
import { wireBinding } from "./grant-transport.js";
import { admissionId, allowed, binding, callId, context, metadata, nonce, paths, peerReply, policy, receipt, request } from "./business-testing.js";

const credential = { token: "public-test-business-workload-token", instanceProof: Buffer.alloc(32, 7) };
function frame(payload: Uint8Array) {
  const bytes = Buffer.alloc(5 + payload.length);
  bytes.writeUInt32BE(payload.length, 1); bytes.set(payload, 5); return bytes;
}
function respond(stream: ServerHttp2Stream, payload: Uint8Array, status = "0") {
  stream.respond({ ":status": 200, "content-type": "application/grpc" }, { waitForTrailers: true });
  stream.on("wantTrailers", () => {
    if (!stream.destroyed) stream.sendTrailers({ "grpc-status": status, "grpc-message": "REMOTE_CANARY" });
  });
  stream.end(frame(payload));
}
async function fixture(t: TestContext, handle: (stream: ServerHttp2Stream, headers: IncomingHttpHeaders, bytes: Buffer) => void) {
  const sessions = new Set<import("node:http2").ServerHttp2Session>();
  const server = createSecureServer({ key, cert: certificate, ca: certificate, requestCert: true, rejectUnauthorized: true });
  server.on("session", session => { sessions.add(session); session.on("close", () => sessions.delete(session)); });
  server.on("stream", (stream, headers) => {
    stream.on("error", () => {});
    const chunks: Buffer[] = [];
    stream.on("data", chunk => chunks.push(Buffer.from(chunk)));
    stream.on("end", () => handle(stream, headers, Buffer.concat(chunks)));
  });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const port = (server.address() as import("node:net").AddressInfo).port;
  const session = connect(`https://grpc-contract-test:${port}`, { createConnection: () => tlsConnect({
    host: "127.0.0.1", port, servername: "grpc-contract-test", ca: certificate, cert: certificate, key,
    ALPNProtocols: ["h2"], rejectUnauthorized: true,
  }) });
  await once(session, "connect");
  const channel = new OwnedAuthorityChannel(session, credential);
  // Clock semantics have deterministic tests separately; this peer proves actual
  // framing, authenticated transport and cleanup with no CP/PG acceptance claim.
  const client = new AuthenticatedBusinessTransport({ ...metadata, channel, monotonicNowNs: () => 1001n });
  t.after(async () => {
    const closing = channel.close(); session.destroy();
    for (const connection of sessions) connection.destroy();
    await closing;
    await new Promise<void>((yes, no) => server.close(error => error ? no(error) : yes()));
  });
  return { channel, client, session };
}
function start(client: AuthenticatedBusinessTransport, kind: keyof typeof paths) {
  return kind === "policy" ? client.startPolicy(nonce) : kind === "authorize"
    ? client.startAuthorization(request(), context) : client.startCompletion(admissionId, callId);
}
for (const kind of ["policy", "authorize", "complete"] as const) {
  test(`actual mTLS ${kind} carries canonical protobuf, bearer and separate 32-byte proof`, async t => {
    let received = 0;
    const { client } = await fixture(t, (stream, headers, bytes) => {
      received++;
      assert.equal(headers[":path"], paths[kind]); assert.equal(headers.authorization, `Bearer ${credential.token}`);
      assert.equal(headers["apex-instance-proof-bin"], credential.instanceProof.toString("base64"));
      assert.equal(headers["grpc-timeout"], "10000000u");
      const payload = bytes.subarray(5);
      assert.equal(bytes[0], 0); assert.equal(bytes.readUInt32BE(1), payload.length);
      if (kind === "authorize") {
        assert.deepEqual(fromBinary(ManagedCallAuthorizationRequestSchema, payload), request());
        assert.deepEqual(payload, Buffer.from(toBinary(ManagedCallAuthorizationRequestSchema, request())));
      } else if (kind === "policy") {
        assert.deepEqual(fromBinary(ManagedPolicyRequestSchema, payload), create(ManagedPolicyRequestSchema, {
          binding: wireBinding(binding), nonce: Buffer.from(nonce, "hex"),
        }));
      } else assert.deepEqual(fromBinary(ManagedCallCompletionSchema, payload), create(ManagedCallCompletionSchema, {
        binding: wireBinding(binding), admissionId, callId,
      }));
      respond(stream, peerReply(paths[kind], payload));
    });
    const exchange = start(client, kind);
    const value = await exchange.result;
    if ("outcome" in value) assert.equal(value.outcome, "allowed");
    else if ("released" in value) assert.equal(value.released, true);
    else assert.equal(value.policyId, metadata.policyId);
    await exchange.closed; assert.equal(received, 1);
  });
  for (const failure of ["wrong reply", "malformed", "oversize", "grpc status"] as const) {
    test(`actual mTLS ${kind} refuses ${failure} without leaking remote text`, async t => {
      const { client } = await fixture(t, (stream, _headers, bytes) => {
        let payload = peerReply(paths[kind], bytes.subarray(5));
        if (failure === "wrong reply") payload = kind === "policy"
          ? toBinary(ManagedPolicySnapshotSchema, { ...policy(), nonce: Buffer.alloc(32) }) : kind === "authorize"
            ? toBinary(ManagedCallAuthorizationDecisionSchema, { ...allowed(), epoch: 24n })
            : toBinary(ManagedCallCompletionReceiptSchema, { ...receipt(), released: false });
        if (failure === "malformed") payload = Buffer.from([0xff]);
        if (failure === "oversize") payload = Buffer.alloc(16_385);
        respond(stream, payload, failure === "grpc status" ? "7" : "0");
      });
      const exchange = start(client, kind);
      await assert.rejects(exchange.result, { message: "managed business refused safely" });
      await exchange.closed;
    });
  }
}

test("business cancellation and root channel close own real streams until their native close", async t => {
  let received = 0;
  const { client, channel } = await fixture(t, () => { received++; });
  const exchange = client.startAuthorization(request(), context);
  const rejection = assert.rejects(exchange.result, { message: "managed business refused safely" });
  exchange.cancel(); await rejection; await exchange.closed;
  const second = client.startPolicy(nonce);
  const closed = assert.rejects(second.result, { message: "managed business refused safely" });
  await channel.close(); await closed; await second.closed;
  assert.throws(() => client.startCompletion(admissionId, callId), { message: "managed business refused safely" });
  assert.ok(received <= 2);
});

test("two business clients share the 128-stream ceiling through held native cancellation", async t => {
  const { client, channel, session } = await fixture(t, () => {});
  const other = new AuthenticatedBusinessTransport({ ...metadata, channel, monotonicNowNs: () => 1001n });
  const original = session.request.bind(session), release: Array<() => void> = [];
  session.request = (...args: Parameters<typeof session.request>) => {
    const stream = original(...args), close = stream.close.bind(stream);
    stream.close = () => {};
    release.push(() => { stream.close = close; stream.close(8); }); return stream;
  };
  const exchanges = Array.from({ length: 128 }, (_, i) => i % 2 ? other.startPolicy(nonce) : client.startAuthorization(request(), context));
  const failures = exchanges.map(x => assert.rejects(x.result));
  let physicallyClosed = 0;
  for (const x of exchanges) { void x.closed.then(() => { physicallyClosed++; }); x.cancel(); }
  await Promise.all(failures); assert.equal(physicallyClosed, 0);
  assert.throws(() => client.startCompletion(admissionId, callId));
  assert.throws(() => channel.start("/apex.v1.ManagedRuntimeAuthority/RenewDeployment", Buffer.alloc(0)));
  for (const end of release) end();
  await Promise.all(exchanges.map(x => x.closed)); assert.equal(physicallyClosed, 128);
  session.request = original;
  const next = other.startPolicy(nonce), rejected = assert.rejects(next.result);
  next.cancel(); await rejected; await next.closed;
});
