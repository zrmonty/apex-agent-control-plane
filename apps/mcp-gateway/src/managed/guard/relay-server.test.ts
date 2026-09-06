import assert from "node:assert/strict";
import { test } from "node:test";
import { create } from "@bufbuild/protobuf";
import { RuntimeNetworkGrantSchema } from "@apex/contracts";
import { compileGuardEgressPolicy } from "./egress-policy.js";
import { GuardEgressRelay, GuardIngressRelay } from "./relay-server.js";
import { ack, client, handshake, peer, read, testPolicy } from "./relay-testing.js";

test("semantic egress relays opaque bidirectional bytes over actual numeric TCP", { timeout: 5000 }, async t => {
  const upstream = await peer(t);
  const resolved: string[] = [];
  const relay = new GuardEgressRelay({ bindAddress: "127.0.0.1", port: 0, gatewayAddress: "127.0.0.1",
    outboundAddress: "127.0.0.1", policy: testPolicy(upstream.port), lookup(host, callback) {
      resolved.push(host); callback(null, [{ address: "127.0.0.1", family: 4 }]);
    } });
  t.after(() => relay.close());
  const endpoint = await relay.listen(), remote = await client(t, endpoint);
  const accepted = read(remote.socket, ack.length); remote.socket.write(handshake("allowed.example.test", upstream.port));
  assert.deepEqual(await accepted, ack); assert.deepEqual(resolved, ["allowed.example.test"]);
  const bytes = Buffer.from([0, 255, 22, 3, 1, 128, 0, 9]);
  const echoed = read(remote.socket, bytes.length); remote.socket.write(bytes);
  assert.deepEqual(await echoed, bytes); assert.equal(upstream.connections, 1);
  const other = Buffer.from("upstream-initiated"), incoming = read(remote.socket, other.length);
  [...upstream.sockets][0].write(other); assert.deepEqual(await incoming, other);
  remote.socket.destroy(); await remote.closed;
  const closing = relay.close(); assert.equal(relay.close(), closing); await closing;
});

test("semantic ingress is opaque and always connects to the fixed gateway 8080", { timeout: 5000 }, async t => {
  const gateway = await peer(t, socket => socket.pipe(socket), "127.0.0.21", 8080);
  const relay = new GuardIngressRelay({ bindAddress: "127.0.0.1", port: 0,
    edgeAddress: "127.0.0.1", gatewayAddress: "127.0.0.21", outboundAddress: "127.0.0.1" });
  t.after(() => relay.close());
  const endpoint = await relay.listen(), remote = await client(t, endpoint);
  const bytes = Buffer.from("CONNECT another.example:8081 HTTP/1.1\r\nHost: another.example:8081\r\n\r\n\0\xff", "latin1");
  const echoed = read(remote.socket, bytes.length); remote.socket.write(bytes);
  assert.deepEqual(await echoed, bytes); assert.equal(gateway.connections, 1);
  const response = Buffer.from([22, 3, 3, 0, 6, 254]), incoming = read(remote.socket, response.length);
  [...gateway.sockets][0].write(response); assert.deepEqual(await incoming, response);
  const closing = relay.close(); assert.equal(relay.close(), closing); await closing; await remote.closed;
});

for (const change of ["selector", "port", "source", "header", "head", "oversize", "version", "body", "duplicate Host", "method"] as const) {
  test(`reject ${change} before lookup or connection`, { timeout: 5000 }, async t => {
    const upstream = await peer(t); let lookups = 0;
    const relay = new GuardEgressRelay({ bindAddress: "127.0.0.1", port: 0, gatewayAddress: "127.0.0.1",
      outboundAddress: "127.0.0.1", policy: testPolicy(upstream.port), lookup() { lookups++; } });
    t.after(() => relay.close());
    const endpoint = await relay.listen(), remote = await client(t, endpoint, change === "source" ? "127.0.0.2" : "127.0.0.1");
    const host = "allowed.example.test", original = handshake(host, upstream.port);
    const body = change === "selector" ? handshake("unknown.example.test", upstream.port) :
      change === "port" ? handshake(host, upstream.port === 443 ? 444 : 443) :
      change === "header" ? original.replace("\r\n\r\n", "\r\nProxy-Authorization: CANARY\r\n\r\n") :
      change === "head" ? original + "TLS-before-ack" : change === "oversize" ? "A".repeat(2049) :
      change === "version" ? original.replace("HTTP/1.1", "HTTP/1.0") :
      change === "body" ? original.replace("\r\n\r\n", "\r\nContent-Length: 0\r\n\r\n") :
      change === "duplicate Host" ? original.replace("\r\n\r\n", `\r\nHost: ${host}:${upstream.port}\r\n\r\n`) :
      change === "method" ? original.replace("CONNECT", "GET") : original;
    remote.socket.write(body); await remote.closed;
    assert.equal(lookups, 0); assert.equal(upstream.connections, 0);
  });
}

test("real compiled policy refuses an unselected hostname before native DNS", { timeout: 5000 }, async t => {
  const grant = create(RuntimeNetworkGrantSchema, { grantId: "known", host: "allowed.example.test",
    port: 443, approvedCidrs: ["8.8.8.0/24"] });
  const policy = compileGuardEgressPolicy([grant], [grant], ["10.77.0.0/16"]);
  const relay = new GuardEgressRelay({ bindAddress: "127.0.0.1", port: 0, gatewayAddress: "127.0.0.1",
    outboundAddress: "127.0.0.1", policy });
  t.after(() => relay.close());
  const remote = await client(t, await relay.listen());
  remote.socket.write(handshake("unselected.invalid", 443)); await remote.closed;
});

for (const addresses of [["127.0.0.1", "127.0.0.2"], ["127.0.0.2"], ["not-numeric"], []]) {
  test(`all DNS answers must be numeric and permitted: ${addresses.join(",")}`, { timeout: 5000 }, async t => {
    const upstream = await peer(t);
    const relay = new GuardEgressRelay({ bindAddress: "127.0.0.1", port: 0, gatewayAddress: "127.0.0.1",
      outboundAddress: "127.0.0.1", policy: testPolicy(upstream.port), lookup(_host, done) {
        done(null, addresses.map(address => ({ address, family: 4 })));
      } });
    t.after(() => relay.close());
    const remote = await client(t, await relay.listen());
    remote.socket.write(handshake("allowed.example.test", upstream.port)); await remote.closed;
    assert.equal(upstream.connections, 0);
  });
}

test("literal selectors bypass lookup and connect exactly once", { timeout: 5000 }, async t => {
  const upstream = await peer(t); let lookups = 0;
  const relay = new GuardEgressRelay({ bindAddress: "127.0.0.1", port: 0, gatewayAddress: "127.0.0.1",
    outboundAddress: "127.0.0.1", policy: testPolicy(upstream.port, "127.0.0.1"), lookup() { lookups++; } });
  t.after(() => relay.close());
  const remote = await client(t, await relay.listen()), accepted = read(remote.socket, ack.length);
  remote.socket.write(handshake("127.0.0.1", upstream.port)); await accepted;
  assert.equal(lookups, 0); assert.equal(upstream.connections, 1);
});

test("opaque ingress refuses the wrong edge source without reaching the gateway", { timeout: 5000 }, async t => {
  const gateway = await peer(t, socket => socket.pipe(socket), "127.0.0.21", 8080);
  const relay = new GuardIngressRelay({ bindAddress: "127.0.0.1", port: 0, edgeAddress: "127.0.0.2",
    gatewayAddress: "127.0.0.21", outboundAddress: "127.0.0.1" });
  t.after(() => relay.close());
  const remote = await client(t, await relay.listen()); remote.socket.write("anything"); await remote.closed;
  assert.equal(gateway.connections, 0);
});

test("fragmented CONNECT is selected once and native pipe handles a paused peer", { timeout: 5000 }, async t => {
  const upstream = await peer(t, socket => { socket.pause(); }); let lookups = 0;
  const relay = new GuardEgressRelay({ bindAddress: "127.0.0.1", port: 0, gatewayAddress: "127.0.0.1",
    outboundAddress: "127.0.0.1", policy: testPolicy(upstream.port), lookup(_host, done) {
      lookups++; done(null, [{ address: "127.0.0.1", family: 4 }]);
    } });
  t.after(() => relay.close());
  const remote = await client(t, await relay.listen()), accepted = read(remote.socket, ack.length);
  const bytes = handshake("allowed.example.test", upstream.port);
  remote.socket.write(bytes.slice(0, 20));
  await new Promise<void>(done => setImmediate(done)); assert.equal(lookups, 0);
  remote.socket.write(bytes.slice(20)); await accepted;
  const body = Buffer.alloc(2 * 1024 * 1024, 0x96), echoed = read(remote.socket, body.length);
  remote.socket.write(body);
  const target = [...upstream.sockets][0]; target.pipe(target); target.resume();
  assert.deepEqual(await echoed, body); assert.equal(lookups, 1); assert.equal(upstream.connections, 1);
});

test("native DNS failure, synchronous lookup failure and an oversized answer set close silently", { timeout: 5000 }, async t => {
  for (const mode of ["callback", "throw", "oversize", "family"] as const) {
    const relay = new GuardEgressRelay({ bindAddress: "127.0.0.1", port: 0, gatewayAddress: "127.0.0.1",
      outboundAddress: "127.0.0.1", policy: testPolicy(443), lookup(_host, done) {
        if (mode === "throw") throw new Error("LOOKUP_CANARY");
        if (mode === "callback") done(new Error("LOOKUP_CANARY"), []);
        if (mode === "oversize") done(null, Array(33).fill({ address: "127.0.0.1", family: 4 }));
        if (mode === "family") done(null, [{ address: "127.0.0.1", family: 6 }]);
      } });
    t.after(() => relay.close());
    const remote = await client(t, await relay.listen()); let received = 0;
    remote.socket.on("data", bytes => { received += bytes.length; });
    remote.socket.write(handshake("allowed.example.test", 443)); await remote.closed;
    await relay.close(); assert.equal(received, 0);
  }
});
