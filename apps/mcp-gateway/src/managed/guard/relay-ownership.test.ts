import assert from "node:assert/strict";
import { test } from "node:test";
import { Socket } from "node:net";
import type { RelayLookup } from "./relay-types.js";
import { GuardEgressRelay, GuardIngressRelay } from "./relay-server.js";
import { ack, client, deferred, handshake, peer, read, testPolicy } from "./relay-testing.js";

test("128 cancelled sockets retain capacity until held DNS callbacks settle; shutdown cannot connect late", { timeout: 10000 }, async t => {
  const upstream = await peer(t), pending: Array<Parameters<RelayLookup>[1]> = [];
  const all = deferred<void>(), next = deferred<void>(); let lookups = 0;
  const relay = new GuardEgressRelay({ bindAddress: "127.0.0.1", port: 0, gatewayAddress: "127.0.0.1",
    outboundAddress: "127.0.0.1", policy: testPolicy(upstream.port), lookup(_host, done) {
      pending.push(done); lookups++;
      if (lookups === 128) all.resolve(); if (lookups === 129) next.resolve();
    } });
  t.after(async () => {
    const closing = relay.close(); for (const done of pending.splice(0)) done(new Error("TEST_CANCEL"), []); await closing;
  });
  const endpoint = await relay.listen();
  const remotes = await Promise.all(Array.from({ length: 128 }, () => client(t, endpoint)));
  for (const remote of remotes) remote.socket.write(handshake("allowed.example.test", upstream.port));
  await all.promise;
  for (const remote of remotes) remote.socket.destroy();
  await Promise.all(remotes.map(x => x.closed));
  const overflow = await client(t, endpoint); overflow.socket.write(handshake("allowed.example.test", upstream.port));
  await overflow.closed; assert.equal(lookups, 128);
  // One completed callback frees exactly one slot, despite its result arriving late.
  pending.shift()!(null, [{ address: "127.0.0.1", family: 4 }]);
  const admitted = await client(t, endpoint); admitted.socket.write(handshake("allowed.example.test", upstream.port));
  await next.promise; admitted.socket.destroy(); await admitted.closed;
  const closing = relay.close(); assert.equal(relay.close(), closing);
  let closed = false; void closing.then(() => { closed = true; });
  await new Promise<void>(done => setImmediate(done));
  assert.equal(closed, false); assert.equal(upstream.connections, 0);
  for (const done of pending.splice(0)) done(null, [{ address: "127.0.0.1", family: 4 }]);
  await closing; assert.equal(closed, true); assert.equal(upstream.connections, 0);
  await assert.rejects(relay.listen(), { message: "guard relay refused safely" });
});

for (const failure of ["timer", "late DNS", "head during DNS", "clock throws", "clock backwards"] as const) {
  test(`${failure} cannot release pending DNS or create a socket after cancellation`, { timeout: 5000 }, async t => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const upstream = await peer(t), entered = deferred<void>();
    let now = 1000n, broken = false, callback: Parameters<RelayLookup>[1] | undefined;
    const relay = new GuardEgressRelay({ bindAddress: "127.0.0.1", port: 0, gatewayAddress: "127.0.0.1",
      outboundAddress: "127.0.0.1", policy: testPolicy(upstream.port), monotonicNowNs() {
        if (broken) throw new Error("CLOCK_CANARY"); return now;
      }, lookup(_host, done) { callback = done; entered.resolve(); } });
    t.after(async () => { const closing = relay.close(); callback?.(new Error("CANCEL"), []); await closing; });
    const remote = await client(t, await relay.listen());
    remote.socket.write(handshake("allowed.example.test", upstream.port)); await entered.promise;
    if (failure === "head during DNS") remote.socket.write(Buffer.from([22, 3, 1]));
    else if (failure === "timer") { now += 10_000_000_000n; t.mock.timers.tick(10_000); }
    else {
      if (failure === "late DNS") now += 10_000_000_000n;
      if (failure === "clock throws") broken = true;
      if (failure === "clock backwards") now = 999n;
      callback!(null, [{ address: "127.0.0.1", family: 4 }]); callback = undefined;
    }
    await remote.closed;
    const closing = relay.close(); let closed = false; void closing.then(() => { closed = true; });
    await new Promise<void>(done => setImmediate(done));
    if (callback) {
      assert.equal(closed, false); callback(null, [{ address: "127.0.0.1", family: 4 }]); callback = undefined;
    }
    await closing; assert.equal(upstream.connections, 0);
  });
}

test("recheck after policy pin prevents a ready callback from beating an overdue timer", { timeout: 5000 }, async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const upstream = await peer(t); let now = 0n;
  const policy = testPolicy(upstream.port);
  const relay = new GuardEgressRelay({ bindAddress: "127.0.0.1", port: 0, gatewayAddress: "127.0.0.1",
    outboundAddress: "127.0.0.1", monotonicNowNs: () => now, policy: { select(host, port) {
      const route = policy.select(host, port);
      return { ...route, pin(answers) { const pin = route.pin(answers); now = 10_000_000_000n; return pin; } };
    } }, lookup(_host, done) { done(null, [{ address: "127.0.0.1", family: 4 }]); } });
  t.after(() => relay.close());
  const remote = await client(t, await relay.listen()); remote.socket.write(handshake("allowed.example.test", upstream.port));
  await remote.closed; assert.equal(upstream.connections, 0);
});

test("established traffic outlives ten seconds and either peer ending closes both native sockets", { timeout: 5000 }, async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const upstream = await peer(t); let now = 0n;
  const relay = new GuardEgressRelay({ bindAddress: "127.0.0.1", port: 0, gatewayAddress: "127.0.0.1",
    outboundAddress: "127.0.0.1", policy: testPolicy(upstream.port, "127.0.0.1"), monotonicNowNs: () => now });
  t.after(() => relay.close());
  const endpoint = await relay.listen(), remote = await client(t, endpoint), accepted = read(remote.socket, ack.length);
  remote.socket.write(handshake("127.0.0.1", upstream.port)); await accepted;
  now = 11_000_000_000n; t.mock.timers.tick(11_000);
  const echoed = read(remote.socket, 4); remote.socket.write("live"); assert.equal((await echoed).toString(), "live");
  const upstreamSocket = [...upstream.sockets][0], upstreamClosed = new Promise<void>(done => upstreamSocket.once("close", () => done()));
  upstreamSocket.end(); await remote.closed; await upstreamClosed;
  const second = await client(t, endpoint), ack2 = read(second.socket, ack.length);
  second.socket.write(handshake("127.0.0.1", upstream.port)); await ack2;
  const target = [...upstream.sockets][0], targetClosed = new Promise<void>(done => target.once("close", () => done()));
  second.socket.end(); await second.closed; await targetClosed;
});

test("close before or during listen cannot leave a late native listener", { timeout: 5000 }, async () => {
  const options = { bindAddress: "127.0.0.1", port: 0, edgeAddress: "127.0.0.1",
    gatewayAddress: "127.0.0.21", outboundAddress: "127.0.0.1" };
  const dormant = new GuardIngressRelay(options), closed = dormant.close();
  assert.equal(dormant.close(), closed); await closed;
  await assert.rejects(dormant.listen(), { message: "guard relay refused safely" });
  const pending = new GuardIngressRelay(options), listen = pending.listen();
  const rejected = assert.rejects(listen, { message: "guard relay refused safely" });
  await pending.close(); await rejected;
});

test("128 established jobs retain capacity while only outgoing native destroy is held", { timeout: 10000 }, async t => {
  const upstream = await peer(t), held = new Set<Socket>(), allHeld = deferred<void>();
  const originalDestroy = Socket.prototype.destroy;
  // Fault injection delays the actual native teardown, not a replacement closed
  // promise. Only guard sockets connected to this exact component peer are held.
  Socket.prototype.destroy = function (error?: Error): Socket {
    if (this.remotePort === upstream.port && this.localAddress === "127.0.0.1") {
      held.add(this); if (held.size === 128) allHeld.resolve(); return this;
    }
    return originalDestroy.call(this, error);
  };
  const relay = new GuardEgressRelay({ bindAddress: "127.0.0.1", port: 0, gatewayAddress: "127.0.0.1",
    outboundAddress: "127.0.0.1", policy: testPolicy(upstream.port, "127.0.0.1") });
  t.after(async () => {
    Socket.prototype.destroy = originalDestroy;
    for (const socket of held) socket.destroy();
    await relay.close();
  });
  const endpoint = await relay.listen(), remotes = await Promise.all(Array.from({ length: 128 }, () => client(t, endpoint)));
  await Promise.all(remotes.map(async remote => {
    const accepted = read(remote.socket, ack.length);
    remote.socket.write(handshake("127.0.0.1", upstream.port)); await accepted;
  }));
  for (const remote of remotes) remote.socket.destroy();
  await Promise.all(remotes.map(remote => remote.closed)); await allHeld.promise;
  const overflow = await client(t, endpoint); overflow.socket.write(handshake("127.0.0.1", upstream.port));
  await overflow.closed; assert.equal(upstream.connections, 128);
  const closing = relay.close(); let closed = false; void closing.then(() => { closed = true; });
  await new Promise<void>(done => setImmediate(done)); assert.equal(closed, false);
  Socket.prototype.destroy = originalDestroy; for (const socket of held) socket.destroy();
  await closing; assert.equal(closed, true);
});

test("late native connect cannot publish the CONNECT acknowledgement", { timeout: 5000 }, async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let now = 0n;
  const upstream = await peer(t, socket => { now = 10_000_000_000n; socket.resume(); });
  const relay = new GuardEgressRelay({ bindAddress: "127.0.0.1", port: 0, gatewayAddress: "127.0.0.1",
    outboundAddress: "127.0.0.1", policy: testPolicy(upstream.port, "127.0.0.1"), monotonicNowNs: () => now });
  t.after(() => relay.close());
  const remote = await client(t, await relay.listen()); let received = 0;
  remote.socket.on("data", bytes => { received += bytes.length; });
  remote.socket.write(handshake("127.0.0.1", upstream.port)); await remote.closed;
  assert.equal(upstream.connections, 1); assert.equal(received, 0);
});

test("established native idle timeout tears down both actual peers", { timeout: 5000 }, async t => {
  const upstream = await peer(t), timers: Array<{ delay: number; fire: () => void }> = [];
  const original = Socket.prototype.setTimeout;
  t.mock.method(Socket.prototype, "setTimeout", function (this: Socket, delay: number, callback?: () => void) {
    if (this.remotePort === upstream.port && callback) timers.push({ delay, fire: callback });
    return original.call(this, delay, callback);
  });
  const relay = new GuardEgressRelay({ bindAddress: "127.0.0.1", port: 0, gatewayAddress: "127.0.0.1",
    outboundAddress: "127.0.0.1", policy: testPolicy(upstream.port, "127.0.0.1") });
  t.after(() => relay.close());
  const remote = await client(t, await relay.listen()), accepted = read(remote.socket, ack.length);
  remote.socket.write(handshake("127.0.0.1", upstream.port)); await accepted;
  const target = [...upstream.sockets][0], targetClosed = new Promise<void>(done => target.once("close", () => done()));
  assert.equal(timers.length, 1); assert.equal(timers[0].delay, 60_000);
  timers[0].fire(); await remote.closed; await targetClosed;
});
