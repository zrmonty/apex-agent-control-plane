import assert from "node:assert/strict";
import { test } from "node:test";
import type { HealthMaterialLoad, HealthFileSystem } from "./types.js";
import { fixture, paths, rejects, wiped, flush } from "./test-fixture.js";
import { isolatedGate, startLoad } from "./job.js";

function deferred() {
  let resolve!: () => void, reject!: (error: Error) => void;
  const promise = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
type Stage = "lstat" | "open" | "stat" | "read" | "close";
/** Simulated OS operations only. FileHandle.close must wait for pending reads/
 * stats, so this fixture also retains its fake descriptor until those settle. */
function delayed(stage: Stage) {
  const f = fixture(), gate = deferred(), ended = deferred();
  let entered = false, pending = false, writable: Buffer | undefined;
  async function pause() {
    entered = true; pending = true;
    try { await gate.promise; } finally { pending = false; ended.resolve(); }
  }
  const os: HealthFileSystem = { ...f.os,
    async lstat(path) { const value = await f.os.lstat(path); if (stage === "lstat" && path === paths[0]) await pause(); return value; },
    async open(path, flags) {
      const handle = await f.os.open(path, flags);
      if (stage === "open" && path === paths[0]) await pause();
      let firstStat = true, firstRead = true;
      return { ...handle,
        async stat() {
          if (stage === "stat" && firstStat) { firstStat = false; await pause(); }
          return handle.stat();
        },
        async read(buffer, offset, length) {
          if (stage === "read" && firstRead) {
            firstRead = false; writable = buffer; buffer.fill(77); await pause();
            buffer.fill(0); // Simulated OS writes remain possible until gate ends.
          }
          return handle.read(buffer, offset, length);
        },
        async close() {
          if (stage === "close") await pause();
          else if (pending) await ended.promise;
          return handle.close();
        },
      };
    },
  };
  return { ...f, os, gate, get entered() { return entered; }, get writable() { return writable; } };
}
function watch(job: HealthMaterialLoad) {
  let settled = false;
  void job.completion.then(() => { settled = true; }, () => { settled = true; });
  return () => settled;
}

test("cancel before acquisition performs no filesystem calls and remains idempotent", async () => {
  const f = fixture(), job = f.start(); job.cancel(); job.cancel();
  await rejects(job.completion);
  assert.equal(f.calls.length, 0); assert.equal(f.time.scheduled, 0); assert.equal(f.counts.fatal, 0);
});

for (const stage of ["lstat", "open", "stat", "read", "close"] as Stage[]) {
  test(`cancellation retains pending ${stage} ownership until actual simulated termination`, async () => {
    const f = delayed(stage), job = f.start(f.options, f.os), settled = watch(job);
    await flush(); assert.ok(f.entered, "must reach actual injected OS operation");
    job.cancel(); job.cancel(); await flush();
    assert.equal(settled(), false, "cancellation is not I/O termination");
    assert.ok(!f.calls.includes(`open:${paths[1]}`));
    if (f.writable) assert.ok(f.writable.every(byte => byte === 77), "pending writable storage is not erased/reused");
    f.gate.resolve(); await rejects(job.completion);
    assert.equal(f.counts.active, 0); assert.equal(f.counts.closed, stage === "lstat" ? 0 : 1);
    assert.ok(wiped(f.buffers)); if (f.writable) assert.ok(wiped([f.writable]));
    assert.ok(!f.calls.includes(`open:${paths[1]}`)); assert.equal(f.counts.fatal, 0);
    assert.equal(f.time.scheduled, 0);
  });
}

test("late valid read cannot succeed when the absolute work deadline elapsed before its timer ran", async () => {
  const f = delayed("read"), job = f.start(f.options, f.os), settled = watch(job);
  await flush(); assert.ok(f.entered);
  f.time.advance(2000000000n, false); assert.equal(settled(), false);
  f.gate.resolve(); await rejects(job.completion);
  assert.equal(f.counts.closed, 1); assert.equal(f.counts.active, 0);
  assert.ok(!f.calls.includes(`open:${paths[1]}`)); assert.ok(wiped(f.buffers));
});

test("cleanup grace fires fatal once but does not release pending read storage or settle completion", async () => {
  const f = delayed("read"), job = f.start(f.options, f.os), settled = watch(job);
  await flush(); assert.ok(f.entered);
  job.cancel(); f.time.advance(5000000000n); await flush();
  assert.equal(f.counts.fatal, 1); assert.equal(settled(), false);
  assert.equal(f.counts.active, 1); assert.ok(f.writable!.every(byte => byte === 77));
  job.cancel(); f.time.advance(5000000000n); await flush(); assert.equal(f.counts.fatal, 1);
  f.gate.resolve(); await rejects(job.completion);
  assert.equal(f.counts.active, 0); assert.equal(f.counts.closed, 1); assert.ok(wiped([f.writable!]));
  assert.equal(f.time.scheduled, 0);
});

test("late read settlement still exposes an already elapsed cleanup grace when its timer was delayed", async () => {
  const f = delayed("read"), job = f.start(f.options, f.os);
  await flush(); assert.ok(f.entered); job.cancel(); f.time.advance(5000000000n, false);
  f.gate.resolve(); await rejects(job.completion);
  assert.equal(f.counts.fatal, 1); assert.equal(f.counts.active, 0); assert.ok(wiped([f.writable!]));
});

test("reentrant currentness and Clock cancellation cannot authorize first acquisition", async () => {
  for (const callback of ["owner", "clock"]) {
    const f = fixture(); let job: HealthMaterialLoad;
    const options = { ...f.options,
      owner: { ...f.options.owner, isCurrent() { if (callback === "owner") job.cancel(); return true; } },
      clock: { now() { if (callback === "clock") job.cancel(); return f.time.clock.now(); } },
    };
    job = f.start(options); await rejects(job.completion);
    assert.equal(f.calls.length, 0); assert.equal(f.counts.fatal, 0); assert.equal(f.time.scheduled, 0);
  }
});

test("owner loss after final token closure refuses handoff and wipes loader-owned scratch", async () => {
  const f = fixture(), open = f.os.open;
  await rejects(f.start(f.options, { ...f.os, async open(path, flags) {
    const handle = await open(path, flags);
    return { ...handle, async close() { await handle.close(); if (path === paths[2]) f.counts.current = false; } };
  } }).completion);
  assert.equal(f.counts.closed, 3); assert.equal(f.counts.active, 0); assert.ok(wiped(f.buffers));
});

test("late OS lstat/open/stat/read failures are observed safely and prevent follow-on acquisition", async () => {
  for (const stage of ["lstat", "stat", "read"] as Stage[]) {
    const f = delayed(stage), job = f.start(f.options, f.os);
    await flush(); assert.ok(f.entered);
    f.gate.reject(new Error("OS_PRIVATE_PATH_MUST_NOT_ESCAPE")); await rejects(job.completion);
    assert.equal(f.counts.active, 0); assert.ok(!f.calls.includes(`open:${paths[1]}`));
    if (f.writable) assert.ok(wiped([f.writable]));
  }
  // An open rejection transfers no descriptor. A late successful open is
  // separately covered above and must transfer its handle solely for closing.
  const f = fixture(), gate = deferred();
  const job = f.start(f.options, { ...f.os, async open() { await gate.promise; throw new Error("OS_PRIVATE_PATH_MUST_NOT_ESCAPE"); } });
  await flush(); job.cancel(); gate.resolve(); await rejects(job.completion);
  assert.equal(f.counts.active, 0); assert.equal(f.counts.closed, 0);
});

test("bad opened metadata latches failure before an unresponsive close starts cleanup", async () => {
  const f = fixture(), gate = deferred(), open = f.os.open; let closing = false;
  const job = f.start(f.options, { ...f.os, async open(path, flags) {
    const handle = await open(path, flags);
    return { ...handle, async stat() { return { ...await handle.stat(), uid: 0n }; },
      async close() { closing = true; await gate.promise; await handle.close(); } };
  } });
  const settled = watch(job); await flush(); assert.ok(closing);
  f.time.advance(5000000000n, false); // Grace starts at metadata failure, not at a later work timer.
  gate.resolve(); await rejects(job.completion);
  assert.equal(f.counts.fatal, 1); assert.equal(f.counts.closed, 1); assert.equal(settled(), true);
});

test("a failed close never masquerades as confirmed descriptor cleanup", async () => {
  const f = fixture(), open = f.os.open;
  const job = f.start(f.options, { ...f.os, async open(path, flags) {
    const handle = await open(path, flags);
    return { ...handle, async close() { await handle.close(); throw new Error("OS_PRIVATE_CLOSE_MUST_NOT_ESCAPE"); } };
  } });
  const settled = watch(job); await flush();
  assert.equal(settled(), false); f.time.advance(5000000000n); await flush();
  assert.equal(f.counts.fatal, 1); assert.equal(settled(), false);
  assert.ok(wiped(f.buffers)); assert.equal(f.counts.active, 0);
  // Deliberately unresolved ownership: the loader cannot know the test double
  // closed before rejecting. A real owner must terminate the failed process.
});

for (const state of ["active", "cancelled", "fatal"] as const) {
  test(`the fixed-mount gate rejects replacement while an ${state} job still owns I/O`, async () => {
    const f = delayed("read"), first = f.start(f.options, f.os);
    const firstSettled = watch(first); await flush(); assert.ok(f.entered);
    if (state !== "active") first.cancel();
    if (state === "fatal") f.time.advance(5000000000n);
    const calls = f.calls.length;
    const second = f.start(); let denied = false;
    await second.completion.then(value => value.dispose(), () => { denied = true; });
    const callsAfterSecond = f.calls.length;
    first.cancel(); f.gate.resolve(); await rejects(first.completion);
    assert.ok(denied, "overlap must refuse, never reserve replacement I/O");
    assert.equal(callsAfterSecond, calls, "gate refusal occurs before any filesystem call");
    assert.equal(firstSettled(), true); assert.equal(f.counts.active, 0);
    const replacement = await f.start().completion; replacement.dispose();
    assert.equal(f.counts.active, 0);
  });
}

test("success releases only the descriptor-job gate while prior token ownership stays separate", async () => {
  const f = fixture(), first = await f.start().completion;
  const second = await f.start().completion;
  assert.equal(f.counts.closed, 6); assert.equal(f.counts.active, 0);
  assert.ok(first.tokenBytes.equals(f.token) && second.tokenBytes.equals(f.token));
  first.dispose(); assert.ok(wiped([first.tokenBytes])); assert.ok(second.tokenBytes.equals(f.token));
  second.dispose(); assert.ok(wiped([second.tokenBytes]));
});

test("a consumed early cleanup wake rearms once against the original deadline while read I/O stays unresolved", async () => {
  const f = delayed("read"), gate = isolatedGate();
  const wakes = new Set<{ at: bigint; callback(): void }>();
  const timers = { monotonicNs: () => f.time.ns, after(ms: number, callback: () => void) {
    const wake = { at: f.time.ns + BigInt(ms) * 1000000n, callback }; wakes.add(wake);
    return () => { wakes.delete(wake); };
  } };
  let reentrantDenial: Promise<void> | undefined;
  const options = { ...f.options, onFatal() {
    f.counts.fatal++; job.cancel(); reentrantDenial = rejects(start().completion);
  } };
  const start = () => startLoad(options, f.os, timers, gate);
  const job = start(), settled = watch(job);
  try {
    await flush(); assert.ok(f.entered); job.cancel(); await flush();
    assert.equal(wakes.size, 1, "one cleanup wake owns the deadline");
    f.time.advance(4999000000n, false); // Consume the one-shot wake exactly1ms early.
    const early = [...wakes][0]; wakes.delete(early); early.callback();
    const afterEarly = wakes.size;
    const subsequentWakeCounts: number[] = [];
    for (let i = 0; i < 2; i++) {
      const wake = [...wakes][0];
      if (wake) { wakes.delete(wake); wake.callback(); }
      subsequentWakeCounts.push(wakes.size);
    }
    f.time.advance(2000000n, false); // Original deadline+1ms, no I/O settlement.
    for (const wake of [...wakes]) if (wake.at <= f.time.ns && wakes.delete(wake)) wake.callback();
    await flush();
    assert.equal(f.counts.fatal, 1, "early wake must not lose eventual fatal escalation");
    assert.equal(afterEarly, 1, "replace the consumed wake without accumulating timers");
    assert.deepEqual(subsequentWakeCounts, [1, 1]);
    await reentrantDenial; assert.ok(reentrantDenial, "fatal callback exercised reentrant cancel/start");
    assert.equal(settled(), false); assert.equal(f.counts.active, 1);
    assert.ok(f.writable!.every(byte => byte === 77), "pending OS storage remains writable and unwiped");
    const calls = f.calls.length; await rejects(start().completion);
    assert.equal(f.calls.length, calls, "fatal cannot authorize replacement I/O");
    job.cancel(); f.time.advance(5000000000n, false);
    for (const wake of [...wakes]) if (wake.at <= f.time.ns && wakes.delete(wake)) wake.callback();
    assert.equal(f.counts.fatal, 1); assert.equal(wakes.size, 0);
  } finally { job.cancel(); f.gate.resolve(); await rejects(job.completion); }
  assert.equal(f.counts.active, 0); assert.equal(f.counts.closed, 1);
  assert.ok(wiped([f.writable!, ...f.buffers])); assert.equal(wakes.size, 0);
  const healthy = await start().completion;
  assert.deepEqual(healthy.binding, f.expected); healthy.dispose();
  assert.equal(f.counts.closed, 4); assert.equal(f.counts.active, 0); assert.equal(wakes.size, 0);
});
