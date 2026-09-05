import assert from "node:assert/strict";
import { test } from "node:test";
import type { HealthMaterialLoad, HealthMaterialLoadOptions } from "./types.js";
import { fixture, paths, rejects, wiped, flush } from "./test-fixture.js";

test("passive expected metadata is defensively copied before currentness or clock can mutate its source", async () => {
  for (const callback of ["owner", "clock"]) {
    const f = fixture(), expected = structuredClone(f.expected);
    let seen = false;
    function mutate() {
      if (seen) return; seen = true;
      (expected.launch.materials[0] as { version: string }).version = "changed-after-copy";
    }
    const loaded = await f.start({ ...f.options, owner: { expected, isCurrent(binding) {
      assert.deepEqual(binding, f.expected); assert.notEqual(binding, expected);
      if (callback === "owner") mutate(); return true;
    } }, clock: { now() { if (callback === "clock") mutate(); return f.time.clock.now(); } } }).completion;
    assert.ok(seen); assert.deepEqual(loaded.binding, f.expected); loaded.dispose();
    assert.equal(f.counts.closed, 3); assert.equal(f.counts.active, 0);
  }
});

test("input Proxy and accessor traps never run even when they could return valid owner data", async () => {
  for (const target of ["options-proxy", "binding-proxy", "owner", "expected", "isCurrent", "now", "onFatal", "config"]) {
    const f = fixture(); let executed = 0;
    const get = () => { executed++; throw new Error("INPUT_MUST_NOT_EXECUTE"); };
    const owner = { ...f.options.owner }, clock = { ...f.options.clock };
    let options: HealthMaterialLoadOptions = { ...f.options, owner, clock };
    if (target === "options-proxy") options = new Proxy(options, { get, ownKeys: get, getOwnPropertyDescriptor: get });
    else if (target === "binding-proxy") owner.expected = new Proxy(f.expected, { get, ownKeys: get, getOwnPropertyDescriptor: get });
    else if (target === "config") {
      const expected = { ...f.expected }; Object.defineProperty(expected, "config", { get }); owner.expected = expected;
    } else {
      const object = target === "expected" || target === "isCurrent" ? owner : target === "now" ? clock : options;
      Object.defineProperty(object, target, { get });
    }
    await rejects(f.start(options).completion);
    assert.equal(executed, 0); assert.equal(f.calls.length, 0); assert.equal(f.time.scheduled, 0);
  }
});

for (const callback of ["owner", "clock"] as const) {
  test(`the first ${callback} callback cannot reenter a replacement load`, async () => {
    const f = fixture(); let nested: Promise<void> | undefined;
    function enter() { nested ??= rejects(f.start().completion); }
    const options = { ...f.options,
      owner: { ...f.options.owner, isCurrent() { if (callback === "owner") enter(); return true; } },
      clock: { now() { if (callback === "clock") enter(); return f.time.clock.now(); } },
    };
    const loaded = await f.start(options).completion;
    await nested; loaded.dispose();
    assert.equal(f.counts.closed, 3); assert.equal(f.counts.active, 0);
  });
}

test("decoded token is wiped when currentness cancels after decoding and before handoff", async () => {
  const f = fixture(), allocated: Buffer[] = [], original = Buffer.alloc;
  let job: HealthMaterialLoad, afterClose = 0;
  // This bounded allocation latch observes only mutable loader output; never
  // displays credential bytes, and is safely restored even on assertion failure.
  Buffer.alloc = ((...args: Parameters<typeof Buffer.alloc>) => {
    const buffer = original(...args); if (buffer.length === 32) allocated.push(buffer); return buffer;
  }) as typeof Buffer.alloc;
  try {
    job = f.start({ ...f.options, owner: { ...f.options.owner, isCurrent() {
      if (f.calls.at(-1) === `close:${paths[2]}` && ++afterClose === 2) job.cancel();
      return true;
    } } });
    await rejects(job.completion);
    assert.equal(allocated.length, 1, "must reach decoded token allocation before cancellation");
    assert.ok(wiped(allocated)); assert.ok(wiped(f.buffers)); assert.equal(f.counts.closed, 3);
  } finally { Buffer.alloc = original; }
});

test("backwards or throwing clocks after a pending read cannot accept late valid data", async () => {
  for (const invalid of ["backwards", "throws"]) {
    const f = fixture(), open = f.os.open;
    let release!: () => void, entered = false, bad = false;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const options = { ...f.options, clock: { now() {
      if (bad && invalid === "throws") throw new Error("CLOCK_PRIVATE_MUST_NOT_ESCAPE");
      const sampled = f.time.clock.now();
      return bad ? { ...sampled, monotonicNs: sampled.monotonicNs - 1n } : sampled;
    } } };
    const job = f.start(options, { ...f.os, async open(path, flags) {
      const handle = await open(path, flags);
      return { ...handle, async read(buffer, offset, length) {
        entered = true; await gate; return handle.read(buffer, offset, length);
      } };
    } });
    await flush(); assert.ok(entered); bad = true; release(); await rejects(job.completion);
    assert.equal(f.counts.closed, 1); assert.equal(f.counts.active, 0); assert.ok(wiped(f.buffers));
    assert.ok(!f.calls.includes(`open:${paths[1]}`));
  }
});

for (const point of ["first-lstat", "open-0", "open-1", "open-2", "read-0", "read-1", "read-2"] as const) {
  test(`a valid Clock sample invalidating the owner immediately before ${point} prevents that I/O`, async () => {
    const f = fixture(); let adjacentSamples = 0, lostAt: number | undefined;
    const index = point === "first-lstat" ? 0 : Number(point.at(-1));
    const marker = point.startsWith("open") ? `lstat:${paths[index]}` : `stat:${paths[index]}`;
    const job = f.start({ ...f.options, clock: { now() {
      const atPoint = point === "first-lstat" ? f.calls.length === 0 : f.calls.at(-1) === marker;
      if (atPoint && ++adjacentSamples === 2) {
        f.counts.current = false; lostAt = f.calls.length; // No cancel, throw or invalid clock sample.
      }
      return f.time.clock.now();
    } } });
    await rejects(job.completion); assert.notEqual(lostAt, undefined, "must reach selected guard");
    assert.deepEqual(f.calls.slice(lostAt).filter(call => !call.startsWith("close:")), [], "no I/O except cleanup after loss");
    assert.equal(f.counts.active, 0); assert.ok(wiped(f.buffers));
    assert.equal(f.counts.closed, point.startsWith("read") ? index + 1 : point.startsWith("open") ? index : 0);
    f.counts.current = true;
    const replacement = await f.start().completion; replacement.dispose();
    assert.equal(f.counts.active, 0); assert.equal(f.time.scheduled, 0);
  });
}

for (const afterCloseGuard of [1, 2, 3, 4]) {
  test(`Clock-only owner loss at post-token-close guard ${afterCloseGuard} cannot hand off a token`, async () => {
    const f = fixture(), allocated: Buffer[] = [], original = Buffer.alloc;
    let samples = 0, reached = false;
    Buffer.alloc = ((...args: Parameters<typeof Buffer.alloc>) => {
      const buffer = original(...args); if (buffer.length === 32) allocated.push(buffer); return buffer;
    }) as typeof Buffer.alloc;
    try {
      const job = f.start({ ...f.options, clock: { now() {
        if (f.calls.at(-1) === `close:${paths[2]}` && ++samples === afterCloseGuard) {
          f.counts.current = false; reached = true; // Only currentness changes.
        }
        return f.time.clock.now();
      } } });
      // Clean even an incorrectly successful RED result without hiding rejection.
      const outcome = await job.completion.then(value => { value.dispose(); return "accepted"; }, async error => {
        await rejects(Promise.reject(error)); return "rejected";
      });
      assert.ok(reached, "must reach selected post-close callback");
      assert.equal(outcome, "rejected", "invalidated owner must not receive decoded token");
      assert.equal(allocated.length, afterCloseGuard === 1 ? 0 : 1, "no decoding after a failed close-boundary guard");
      assert.ok(wiped(allocated)); assert.ok(wiped(f.buffers));
      assert.equal(f.counts.closed, 3); assert.equal(f.counts.active, 0); assert.equal(f.time.scheduled, 0);
    } finally { Buffer.alloc = original; }
  });
}

test("healthy owner callbacks cannot consume a fresh work allowance after Clock sampling", async () => {
  for (const consumeBudget of [false, true]) {
    const f = fixture(); let sampled = false;
    const job = f.start({ ...f.options,
      clock: { now() { sampled = true; return f.time.clock.now(); } },
      owner: { ...f.options.owner, isCurrent() {
        if (sampled && consumeBudget) f.time.advance(2000000000n, false);
        return true;
      } },
    });
    if (consumeBudget) { await rejects(job.completion); assert.equal(f.calls.length, 0); }
    else {
      const healthy = await job.completion; assert.deepEqual(healthy.binding, f.expected); healthy.dispose();
      assert.equal(f.counts.closed, 3);
    }
    assert.equal(f.counts.active, 0); assert.equal(f.time.scheduled, 0);
  }
});
