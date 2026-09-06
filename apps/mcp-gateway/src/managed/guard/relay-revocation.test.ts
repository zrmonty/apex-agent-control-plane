import assert from "node:assert/strict";
import { test } from "node:test";
import { GuardEgressRelay } from "./relay-server.js";
import { client, deferred, handshake, peer, testPolicy } from "./relay-testing.js";

test("relay publishes revocation before held native DNS ownership physically drains", async t => {
  const upstream = await peer(t), entered = deferred<void>(); let done!: Parameters<NonNullable<ConstructorParameters<typeof GuardEgressRelay>[0]["lookup"]>>[1];
  const relay = new GuardEgressRelay({ bindAddress: "127.0.0.1", port: 0, gatewayAddress: "127.0.0.1",
    outboundAddress: "127.0.0.1", policy: testPolicy(upstream.port), lookup(_host, callback) { done = callback; entered.resolve(); } });
  t.after(() => relay.close());
  const remote = await client(t, await relay.listen()); remote.socket.write(handshake("allowed.example.test", upstream.port));
  await entered.promise; let closed = false;
  const closing = relay.close().then(() => { closed = true; });
  try {
    assert(relay.revoked instanceof Promise); await relay.revoked; await remote.closed;
    assert.equal(closed, false);
  } finally { done(null, [{ address: "127.0.0.1", family: 4 }]); await closing; }
  assert.equal(closed, true); assert.equal(upstream.connections, 0);
});
