import assert from "node:assert/strict";
import { test } from "node:test";
import { startLoad, type Gate } from "./stage-reader/job.js";
import { deferred, FakeFiles, FakeTime, fixtureHash } from "./stage-reader/fixture.js";
import type { ManagedStageLoadOptions } from "./stage-reader/types.js";
const tick = () => new Promise<void>(resolve => setImmediate(resolve));
function setup() {
  const fs = new FakeFiles(), time = new FakeTime(), gate: Gate = {};
  let fatals = 0;
  const options: ManagedStageLoadOptions = { expectedManifestSha256: fixtureHash(fs.files),
    toolSecretReferences: [], onFatal() { fatals++; } };
  return { fs, time, gate, options, fatals: () => fatals,
    start: () => startLoad(options, fs, time, gate) };
}
test("late open after timeout remains owned; grace fires once and slot stays reserved", async () => {
  const s = setup(), held = deferred<void>();
  s.fs.hook = (kind, path) => kind === "open" && path === "/" ? held.promise : undefined;
  const load = s.start(); const rejected = assert.rejects(load.result, /^Error: managed stage load rejected$/);
  let closed = false; void load.closed.then(() => { closed = true; });
  await tick(); s.time.advance(5000); await rejected;
  assert.equal(closed, false); assert.equal(s.fs.closed.length, 0);
  await assert.rejects(s.start().result);
  s.time.advance(4999); assert.equal(s.fatals(), 0);
  s.time.advance(1); assert.equal(s.fatals(), 1);
  s.time.advance(9000); assert.equal(s.fatals(), 1);
  held.resolve(); await load.closed;
  assert.equal(s.fs.opened.length, 1); assert.equal(s.fs.closed.length, 1);
  s.fs.hook = undefined;
  (await s.start().result).dispose();
});
test("held read is not closed or wiped early after cancellation", async () => {
  const s = setup(), held = deferred<void>(); let reads = 0;
  const path = "/apex/runtime/authority-profile.json";
  s.fs.hook = (kind, current) => kind === "read" && current === path && ++reads === 2 ? held.promise : undefined;
  const load = s.start(), rejected = assert.rejects(load.result);
  await tick();
  const buffer = s.fs.readBuffers.get(path)!; assert.deepEqual(buffer.subarray(0, 2), Buffer.from("{}"));
  load.cancel(); await rejected;
  assert.deepEqual(buffer.subarray(0, 2), Buffer.from("{}"));
  assert.equal(s.fs.closed.length, 0); await assert.rejects(s.start().result);
  held.resolve(); await load.closed; assert.equal(s.fs.paths.size, 0);
  assert(buffer.every(byte => byte === 0));
});
test("held close delays both success and physical closed; timeout never frees slot", async () => {
  const s = setup(), held = deferred<void>(); let entered = false;
  s.fs.hook = kind => { if (kind === "close" && !entered) { entered = true; return held.promise; } };
  const load = s.start(), rejected = assert.rejects(load.result);
  await tick(); assert(entered); assert(s.gate.held);
  s.time.advance(5000); await rejected; await assert.rejects(s.start().result);
  s.time.advance(5000); assert.equal(s.fatals(), 1);
  held.resolve(); await load.closed; assert.equal(s.fs.paths.size, 0);
});
test("failed close leaves closed pending and retains slot even after fatal", async () => {
  const s = setup();
  s.fs.hook = (kind, path) => { if (kind === "close" && path === "/") throw new Error("private OS detail"); };
  const load = s.start(); await assert.rejects(load.result, /^Error: managed stage load rejected$/);
  let closed = false; void load.closed.then(() => { closed = true; });
  await tick(); s.time.advance(5000); await tick();
  assert.equal(s.fatals(), 1); assert.equal(closed, false); assert(s.gate.held);
  await assert.rejects(s.start().result);
});
test("late opendir is closed after cancel without enumeration", async () => {
  const s = setup(), held = deferred<void>(); let enumerated = false;
  s.fs.hook = kind => { if (kind === "opendir") return held.promise; if (kind === "dirread") enumerated = true; };
  const load = s.start(), rejected = assert.rejects(load.result); await tick();
  load.cancel(); await rejected; held.resolve(); await load.closed;
  assert.equal(s.fs.directoryClosed, 1); assert.equal(enumerated, false);
});
test("preflight time consumes the original work budget, not a newly armed five seconds", async () => {
  const s = setup(), held = deferred<void>();
  s.fs.hook = kind => kind === "lstat" ? held.promise : undefined;
  const load = s.start(), rejected = assert.rejects(load.result);
  // The API returned, but the initial microtask has not run yet.
  s.time.time = 2000000000n;
  await tick(); s.time.advance(3000);
  let reported = false; void load.result.catch(() => { reported = true; }); await tick();
  assert.equal(reported, true);
  held.resolve(); await rejected; await load.closed;
});
test("late timer wake cannot restart cleanup grace beyond the original deadline", async () => {
  const s = setup(), held = deferred<void>();
  s.fs.hook = kind => kind === "lstat" ? held.promise : undefined;
  const load = s.start(), rejected = assert.rejects(load.result); await tick();
  s.time.advance(10000); await rejected;
  assert.equal(s.fatals(), 1);
  held.resolve(); await load.closed;
});
test("clock cancellation/reentrancy cannot start another load or I/O", async () => {
  const s = setup(); let load: ReturnType<typeof s.start>, refused = false;
  const options = { ...s.options, monotonicNowNs() {
    void assert.rejects(s.start().result).then(() => { refused = true; }); load.cancel(); return 0n;
  } };
  load = startLoad(options, s.fs, s.time, s.gate);
  await assert.rejects(load.result); await load.closed; await tick();
  assert(refused); assert.equal(s.fs.opened.length, 0);
});
test("every syscall completion checks monotonic time even without a timer wake", async () => {
  const s = setup();
  s.fs.hook = kind => { if (kind === "lstat") s.time.time = 5000000000n; };
  const load = s.start(); await assert.rejects(load.result); await load.closed;
  assert.equal(s.fs.opened.length, 0);
});
test("regressing or throwing supplied clocks refuse before I/O continues", async () => {
  for (const throwing of [true, false]) {
    const s = setup(); let samples = 0;
    const load = startLoad({ ...s.options, monotonicNowNs() {
      if (throwing) throw new Error("private clock error");
      return ++samples === 1 ? 1n : 0n;
    } }, s.fs, s.time, s.gate);
    await assert.rejects(load.result, /^Error: managed stage load rejected$/); await load.closed;
    assert.equal(s.fs.opened.length, 0);
  }
});
test("cancel before first microtask owns no I/O; success cancel disposes transferred bytes", async () => {
  const s = setup(), load = s.start(); load.cancel(); load.cancel();
  await assert.rejects(load.result); await load.closed; assert.equal(s.fs.opened.length, 0);
  const next = s.start(), stage = await next.result; await next.closed;
  next.cancel(); assert(Object.values(stage.files).every(bytes => bytes.every(byte => byte === 0)));
});
