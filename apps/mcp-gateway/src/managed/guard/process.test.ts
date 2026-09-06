import assert from "node:assert/strict";
import { test } from "node:test";
import { startGuard } from "./process/job.js";
import { FakeRelay, setup } from "./process/fixture.js";
import { deferred } from "./relay-testing.js";
const tick = () => new Promise<void>(done => setImmediate(done));

test("guard process composes fixed stage, strict config and both derived relay bindings", async () => {
  const s = setup(), owner = startGuard(s.options, s.deps, s.gate);
  const ready = await owner.result;
  assert.equal(s.state().loads, 1); assert.equal(s.state().disposed, 1);
  assert.equal(s.relays.length, 2); assert(s.relays.every(relay => relay.bound));
  assert.deepEqual(s.relays.map(relay => [relay.options.bindAddress, relay.options.port]),
    [["10.88.0.19", 18080], ["10.89.0.18", 8080]]);
  assert.equal(ready.addresses.gateway, "10.88.0.18");
  owner.cancel(); await owner.revoked; await owner.closed;
  assert(s.relays.every(relay => relay.closes === 1)); assert.equal(s.gate.held, undefined); assert.equal(s.state().fatals, 0);
  assert.equal(s.state().cancels, 1, "stage cancellation is dispatched once despite relay revocation callbacks");
});

test("captured guard launch cannot be redirected after dispatch", async () => {
  const s = setup(), owner = startGuard(s.options, s.deps, s.gate);
  s.env.APEX_NETWORK_BINDING_SHA256 = "c".repeat(64); s.env.APEX_STAGE_MANIFEST_SHA256 = "d".repeat(64);
  await owner.result; owner.cancel(); await owner.closed;
});
test("cancel before queued dispatch has no stage or relay effects and capacity recovers", async () => {
  const s = setup(), owner = startGuard(s.options, s.deps, s.gate); owner.cancel();
  await assert.rejects(owner.result); await owner.revoked; await owner.closed;
  assert.equal(s.state().loads, 0); assert.equal(s.relays.length, 0);
  const next = startGuard(s.options, s.deps, s.gate); await next.result; next.cancel(); await next.closed;
});
test("original queued startup time cannot restart a fresh ten seconds", async () => {
  const s = setup(), owner = startGuard(s.options, s.deps, s.gate);
  s.time.time = 10_000_000_000n; await assert.rejects(owner.result); await owner.closed;
  assert.equal(s.state().loads, 0);
});
test("either relay revocation closes both listeners without waiting for another request", async () => {
  for (const index of [0, 1]) {
    const s = setup(), owner = startGuard(s.options, s.deps, s.gate); await owner.result;
    s.relays[index].revoke(); await owner.revoked; await owner.closed;
    assert(s.relays.every(relay => relay.closes === 1)); assert.equal(s.gate.held, undefined);
  }
});
test("partially bound listener failure closes both actual owners", async () => {
  const s = setup(), held = deferred<void>(), relays: FakeRelay[] = [];
  const deps = { ...s.deps, ingress(options: Parameters<typeof s.deps.ingress>[0]) {
    const relay = new FakeRelay(options); relay.listenHook = () => Promise.reject(new Error("BIND-CANARY"));
    relay.closeHook = () => held.promise; relays.push(relay); return relay;
  } };
  const owner = startGuard(s.options, deps, s.gate); await assert.rejects(owner.result, /^Error: guard process refused safely$/);
  let closed = false; void owner.closed.then(() => { closed = true; }); await tick();
  assert.equal(closed, false); assert.equal(s.relays[0].closes, 1); assert.equal(relays[0].closes, 1);
  held.resolve(); await owner.closed; assert.equal(s.gate.held, undefined);
});
test("late constructor return after cancellation remains adopted and physically closed", async () => {
  const s = setup(), held = deferred<void>(); let owner: ReturnType<typeof startGuard>, relay: FakeRelay | undefined;
  const deps = { ...s.deps, egress(options: Parameters<typeof s.deps.egress>[0]) {
    owner.cancel(); relay = new FakeRelay(options); relay.closeHook = () => held.promise; return relay;
  } };
  owner = startGuard(s.options, deps, s.gate); await assert.rejects(owner.result); await tick();
  assert.equal(relay!.closes, 1); assert.equal(relay!.bound, false); assert(s.gate.held);
  held.resolve(); await owner.closed;
});
test("a second relay constructor failure closes the first and never publishes ready", async () => {
  const s = setup(), deps = { ...s.deps, ingress() { throw new Error("PRIVATE-FACTORY-CANARY"); } };
  const owner = startGuard(s.options, deps, s.gate); await assert.rejects(owner.result, /^Error: guard process refused safely$/);
  await owner.closed; assert.equal(s.relays.length, 1); assert.equal(s.relays[0].closes, 1);
});
test("unexpected bound address/port/family refuses rather than publishing requested metadata", async () => {
  for (const change of [{ address: "127.0.0.1" }, { port: 1 }, { family: 6 as const }]) {
    const s = setup(), deps = { ...s.deps, egress(options: Parameters<typeof s.deps.egress>[0]) {
      const relay = new FakeRelay(options); s.relays.push(relay);
      relay.listenHook = () => Promise.resolve({ address: options.bindAddress, port: options.port, family: 4, ...change }); return relay;
    } };
    const owner = startGuard(s.options, deps, s.gate); await assert.rejects(owner.result); await owner.closed;
    assert(s.relays.every(relay => relay.closes === 1));
  }
});
test("expiry conservatively subtracts the full wall-clock millisecond uncertainty", async () => {
  const s = setup(1001n), owner = startGuard(s.options, s.deps, s.gate); await owner.result;
  s.time.time = 999n; s.relays[0].options.monotonicNowNs!();
  s.time.time = 1000n; assert.throws(() => s.relays[0].options.monotonicNowNs!());
  await owner.revoked; await owner.closed;
  const short = setup(1000n), refused = startGuard(short.options, short.deps, short.gate);
  await assert.rejects(refused.result); await refused.closed; assert.equal(short.relays.length, 0);
});
test("wall-clock expiry jump and regression revoke both relays at the handshake fence", async () => {
  for (const direction of [-1, 60000]) {
    const s = setup(); let wall = Number(s.wall / 1000n);
    const owner = startGuard(s.options, { ...s.deps, unixMs: () => wall }, s.gate); await owner.result;
    wall += direction; assert.throws(() => s.relays[0].options.monotonicNowNs!()); await owner.closed;
    assert(s.relays.every(relay => relay.closes === 1));
  }
});
test("startup bind completing at the original ten-second boundary refuses", async () => {
  const s = setup(), held = deferred<Awaited<ReturnType<FakeRelay["listen"]>>>();
  const deps = { ...s.deps, ingress(options: Parameters<typeof s.deps.ingress>[0]) {
    const relay = new FakeRelay(options); relay.listenHook = () => held.promise; s.relays.push(relay); return relay;
  } };
  const owner = startGuard(s.options, deps, s.gate), rejected = assert.rejects(owner.result); await tick();
  s.time.time = 10_000_000_000n; held.resolve({ address: "10.89.0.18", port: 8080, family: 4 });
  await rejected; await owner.closed; assert(s.relays.every(relay => relay.closes === 1));
});

test("unknown material disposal is not retried or converted into physical close", async () => {
  const s = setup(); let disposals = 0;
  const deps = { ...s.deps, load() { return { result: Promise.resolve({ files: s.files, manifestSha256: s.manifest,
    dispose() { disposals++; throw new Error("uncertain disposal"); } }), closed: Promise.resolve(), cancel() {} }; } };
  const owner = startGuard(s.options, deps, s.gate); await assert.rejects(owner.result);
  let closed = false; void owner.closed.then(() => { closed = true; });
  await new Promise<void>(done => setImmediate(done));
  assert.equal(disposals, 1); assert.equal(closed, false); assert(s.gate.held);
  s.time.advance(5000); assert.equal(s.state().fatals, 1);
});
