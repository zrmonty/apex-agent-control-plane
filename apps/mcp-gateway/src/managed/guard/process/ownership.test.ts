import assert from "node:assert/strict";
import { test } from "node:test";
import { startGuard } from "./job.js";
import { FakeRelay, setup } from "./fixture.js";
import { deferred } from "../relay-testing.js";
import type { Material } from "./types.js";
const tick = () => new Promise<void>(done => setImmediate(done));

test("cancelled late stage result/close retains ownership and disposes late bytes once", async () => {
  const s = setup(), material = deferred<Material>(), closed = deferred<void>(); let disposed = 0, cancelled = 0;
  const owner = startGuard(s.options, { ...s.deps, load() { return { result: material.promise, closed: closed.promise,
    cancel() { cancelled++; } }; } }, s.gate);
  const rejected = assert.rejects(owner.result); await tick(); owner.cancel(); await rejected;
  let drained = false; void owner.closed.then(() => { drained = true; });
  s.time.advance(5000); assert.equal(s.state().fatals, 1); assert.equal(cancelled, 1);
  material.resolve({ files: s.files, manifestSha256: s.manifest, dispose() { disposed++; } }); await tick();
  assert.equal(disposed, 1); assert.equal(drained, false); assert.equal(s.relays.length, 0);
  closed.resolve(); await owner.closed; assert.equal(drained, true); assert.equal(s.gate.held, undefined);
});
test("startup timeout cleanup grace stays anchored across a late timer wake", async () => {
  const s = setup(), material = deferred<Material>(), closed = deferred<void>();
  const owner = startGuard(s.options, { ...s.deps, load() { return { result: material.promise, closed: closed.promise, cancel() {} }; } }, s.gate);
  const rejected = assert.rejects(owner.result); await tick(); s.time.advance(15000); await rejected;
  assert.equal(s.state().fatals, 1); assert(s.gate.held);
  material.resolve({ files: s.files, manifestSha256: s.manifest, dispose() {} }); closed.resolve(); await owner.closed;
});
test("rejected stage physical receipt never manufactures closed despite successful byte result", async () => {
  const s = setup(); const owner = startGuard(s.options, { ...s.deps, load() {
    return { result: Promise.resolve({ files: s.files, manifestSha256: s.manifest, dispose() {} }),
      closed: Promise.reject(new Error("CLOSE-CANARY")), cancel() {} };
  } }, s.gate);
  await assert.rejects(owner.result); let closed = false; void owner.closed.then(() => { closed = true; }); await tick();
  s.time.advance(5000); assert.equal(closed, false); assert.equal(s.state().fatals, 1); assert(s.gate.held);
});
test("held relay close prevents capacity reuse beyond watchdog; receipt releases exactly once", async () => {
  const s = setup(), held = deferred<void>();
  const deps = { ...s.deps, egress(options: Parameters<typeof s.deps.egress>[0]) {
    const relay = new FakeRelay(options); relay.closeHook = () => held.promise; s.relays.push(relay); return relay;
  } };
  const owner = startGuard(s.options, deps, s.gate); await owner.result;
  let closed = false; void owner.closed.then(() => { closed = true; }); owner.cancel(); await tick();
  const blocked = startGuard(s.options, s.deps, s.gate); await assert.rejects(blocked.result);
  s.time.advance(5000); assert.equal(s.state().fatals, 1); s.time.advance(5000); assert.equal(s.state().fatals, 1);
  assert.equal(closed, false); assert(s.relays.every(relay => relay.closes === 1));
  held.resolve(); await owner.closed;
  const next = startGuard(s.options, s.deps, s.gate); await next.result; next.cancel(); await next.closed;
});
test("rejected relay close is retained; throwing/reentrant fatal callback cannot free it", async () => {
  const s = setup(); let owner: ReturnType<typeof startGuard>, fatals = 0;
  const options = { ...s.options, onFatal() { fatals++; owner.cancel(); throw new Error("FATAL-CANARY"); } };
  const deps = { ...s.deps, egress(options: Parameters<typeof s.deps.egress>[0]) {
    const relay = new FakeRelay(options); relay.closeHook = () => Promise.reject(new Error("CLOSE-CANARY")); return relay;
  } };
  owner = startGuard(options, deps, s.gate); await owner.result; owner.cancel(); await tick();
  let closed = false; void owner.closed.then(() => { closed = true; });
  s.time.advance(5000); s.time.advance(5000); await tick();
  assert.equal(fatals, 1); assert.equal(closed, false); assert(s.gate.held);
});

test("regressed monotonic cleanup clock never extends the five-second watchdog", async () => {
  const s = setup(), held = deferred<void>(), waits: number[] = [];
  s.time.time = 100_000_000_000n;
  const deps = { ...s.deps, timers: { now: () => s.time.now(), after(ms: number, callback: () => void) {
    waits.push(ms); return s.time.after(ms, callback);
  } }, egress(options: Parameters<typeof s.deps.egress>[0]) {
    const relay = new FakeRelay(options); relay.closeHook = () => held.promise; s.relays.push(relay); return relay;
  } };
  const owner = startGuard(s.options, deps, s.gate); let closed = false; void owner.closed.then(() => { closed = true; });
  try {
    await owner.result; s.time.time = 101_000_000_000n; s.relays[0].options.monotonicNowNs!();
    s.time.time = 0n; assert.throws(() => s.relays[0].options.monotonicNowNs!()); await owner.revoked;
    s.time.advance(5000); await tick();
    assert.equal(s.state().fatals, 1, "regressed clock cannot renew cleanup grace");
    assert(waits.every(ms => ms <= 5000)); assert.equal(closed, false); assert(s.gate.held);
  } finally { held.resolve(); owner.cancel(); await owner.closed; }
});

test("later watchdog observation cannot regress below the stop-time sample", async () => {
  const s = setup(), held = deferred<void>(); let watchdog: (() => void) | undefined;
  s.time.time = 100_000_000_000n;
  const deps = { ...s.deps, timers: { now: () => s.time.now(), after(ms: number, callback: () => void) {
    if (ms === 5000) watchdog = callback; return s.time.after(ms, callback);
  } }, egress(options: Parameters<typeof s.deps.egress>[0]) {
    const relay = new FakeRelay(options); relay.closeHook = () => held.promise; return relay;
  } };
  const owner = startGuard(s.options, deps, s.gate);
  try {
    await owner.result; s.time.time = 105_000_000_000n; owner.cancel(); assert(watchdog);
    s.time.time = 102_000_000_000n; watchdog();
    assert.equal(s.state().fatals, 1, "cleanup lower bound includes the last valid stop observation");
    watchdog(); assert.equal(s.state().fatals, 1); assert(s.gate.held);
  } finally { held.resolve(); await owner.closed; }
});

for (const wallRegression of [false, true]) test(`ordinary cleanup keeps exact five seconds (wall regression ${wallRegression})`, async () => {
  const s = setup(), held = deferred<void>(); let wall = Number(s.wall / 1000n);
  s.time.time = 100_000_000_000n;
  const deps = { ...s.deps, unixMs: () => wall, egress(options: Parameters<typeof s.deps.egress>[0]) {
    const relay = new FakeRelay(options); relay.closeHook = () => held.promise; s.relays.push(relay); return relay;
  } };
  const owner = startGuard(s.options, deps, s.gate);
  try {
    await owner.result;
    if (wallRegression) { wall--; assert.throws(() => s.relays[0].options.monotonicNowNs!()); } else owner.cancel();
    s.time.advance(4999); assert.equal(s.state().fatals, 0);
    s.time.advance(1); assert.equal(s.state().fatals, 1); s.time.advance(5000); assert.equal(s.state().fatals, 1);
    assert(s.gate.held);
  } finally { held.resolve(); await owner.closed; }
});

test("every cleanup wake advances its own accepted monotonic lower bound", async () => {
  const s = setup(), held = deferred<void>(), callbacks: (() => void)[] = [];
  s.time.time = 100_000_000_000n;
  const deps = { ...s.deps, timers: { now: () => s.time.now(), after(ms: number, callback: () => void) {
    if (ms > 1000) callbacks.push(callback); return s.time.after(ms, callback);
  } }, egress(options: Parameters<typeof s.deps.egress>[0]) {
    const relay = new FakeRelay(options); relay.closeHook = () => held.promise; return relay;
  } };
  const owner = startGuard(s.options, deps, s.gate);
  try {
    await owner.result; owner.cancel(); assert.equal(callbacks.length, 1);
    s.time.time = 101_000_000_000n; callbacks[0](); assert.equal(callbacks.length, 2); assert.equal(s.state().fatals, 0);
    s.time.time = 100_500_000_000n; callbacks[1](); assert.equal(s.state().fatals, 1);
    assert.equal(callbacks.length, 2); assert(s.gate.held);
  } finally { held.resolve(); await owner.closed; }
});
