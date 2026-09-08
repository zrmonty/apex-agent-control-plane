import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { FakeTime, deferred } from "../stage-reader/fixture.js";
import { runHealthObservationProcess, diagnostic } from "./process.js";
import type { ObservationOptions } from "./owner.js";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";

function fixture(extra: string[] = [], reentrant = false) {
  const events = new EventEmitter(), time = new FakeTime(), result = deferred<string | undefined>();
  const output: string[] = [], errors: string[] = []; let calls = 0, terminated = 0, input!: ObservationOptions;
  const done = runHealthObservationProcess(extra, {}, options => {
    calls++; input = options; if (reentrant) events.emit("SIGTERM");
    return result.promise.then(text => text === undefined ? undefined : { text, validUntilMonotonicNs: 10_000_000_000n });
  }, { on: events.on.bind(events), removeListener: events.removeListener.bind(events), timers: time,
    async write(line) { output.push(line); }, error(line) { errors.push(line); }, terminate() { terminated++; } });
  return { done, result, events, time, output, errors, stats: () => ({ calls, terminated }), input: () => input };
}
test("fixed process emits one bounded canonical line only on completed observation", async () => {
  const f = fixture(); f.result.resolve('{"observedAtUnixUs":"9007199254740993"}');
  assert.equal(await f.done, 0); assert.deepEqual(f.output,
    ['{"schemaVersion":1,"report":{"observedAtUnixUs":"9007199254740993"},"validForNs":"10000000000"}\n']);
  assert.deepEqual(f.errors, []);
});
test("unexpected argv is refused statically before the observation factory", async () => {
  const f = fixture(["--url=SENSITIVE"]); assert.equal(await f.done, 1);
  assert.equal(f.stats().calls, 0); assert.deepEqual(f.output, []); assert.deepEqual(f.errors, [diagnostic]);
});
for (const signal of ["SIGTERM", "SIGINT"] as const) {
  test(`${signal} during owned observation must fail, never print ready`, async () => {
    const f = fixture(); let settled = false; void f.done.then(() => { settled = true; });
    f.events.emit(signal); await Promise.resolve(); assert.equal(settled, false); assert.equal(f.input().signal.aborted, true);
    f.result.resolve("{}"); assert.equal(await f.done, 1); assert.deepEqual(f.output, []); assert.deepEqual(f.errors, [diagnostic]);
  });
}
test("reentrant startup signal is adopted without emitting output", async () => {
  const f = fixture([], true); f.result.resolve("{}"); assert.equal(await f.done, 1);
  assert.equal(f.input().signal.aborted, true); assert.deepEqual(f.output, []); assert.deepEqual(f.errors, [diagnostic]);
});
test("fatal and outer deadline terminate once without resolving held physical work", async () => {
  const f = fixture(); let settled = false; void f.done.then(() => { settled = true; });
  f.input().onFatal(); f.time.advance(7000); await Promise.resolve();
  assert.equal(f.stats().terminated, 1); assert.equal(settled, false);
  assert.deepEqual(f.output, []); assert.deepEqual(f.errors, [diagnostic]);
});
test("clock expiry after observation but before output cannot publish", async () => {
  const f = fixture(); f.time.time = 7_000_000_000n; f.result.resolve("{}");
  assert.equal(await f.done, 1); assert.deepEqual(f.output, []); assert.deepEqual(f.errors, [diagnostic]);
});
test("refusal/rejection and oversize or multiline output are static failures", async () => {
  for (const value of [undefined, "x".repeat(8193), "{}\n{}", "{}\r"]) {
    const f = fixture(); f.result.resolve(value); assert.equal(await f.done, 1);
    assert.deepEqual(f.output, []); assert.deepEqual(f.errors, [diagnostic]);
  }
  const f = fixture(); f.result.reject(Error("SENSITIVE")); assert.equal(await f.done, 1);
  assert.deepEqual(f.output, []); assert.deepEqual(f.errors, [diagnostic]);
});

test("actual fixed executable rejects unexpected argument and absent agent environment without stdout", async () => {
  for (const args of [["--url=SENSITIVE"], []]) {
    const result = await new Promise<{ code: number | string | null | undefined; stdout: string; stderr: string }>(resolve => {
      execFile(process.execPath, ["--import", "tsx", fileURLToPath(new URL("../health-process.ts", import.meta.url)), ...args],
        { timeout: 3000, maxBuffer: 16384, windowsHide: true, env: {} }, (error, stdout, stderr) => {
          resolve({ code: error?.code, stdout, stderr });
        });
    });
    assert.equal(result.code, 1); assert.equal(result.stdout, ""); assert.equal(result.stderr, diagnostic);
  }
});

test("failure diagnostic flush remains owned by the original watchdog, even for rejected argv", async () => {
  const events = new EventEmitter(), time = new FakeTime(), flush = deferred<void>();
  let writes = 0, terminated = 0, settled = false;
  const done = runHealthObservationProcess(["bad"], {}, async () => { assert.fail("must not start"); }, {
    on: events.on.bind(events), removeListener: events.removeListener.bind(events), timers: time,
    async write() { assert.fail("no report"); }, error() { writes++; return flush.promise; }, terminate() { terminated++; },
  });
  void done.then(() => { settled = true; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(settled, false); assert.equal(writes, 1);
  time.advance(6999); assert.equal(terminated, 0);
  events.emit("SIGTERM"); time.advance(1);
  assert.equal(terminated, 1); assert.equal(writes, 1); assert.equal(settled, false);
  flush.resolve(); assert.equal(await done, 1);
});

test("held stdout plus signal cannot succeed; diagnostic gets only the original remaining budget", async () => {
  const events = new EventEmitter(), time = new FakeTime(), output = deferred<void>(), error = deferred<void>();
  let terminated = 0, errors = 0;
  const done = runHealthObservationProcess([], {}, async () => ({ text: "{}", validUntilMonotonicNs: 10_000_000_000n }), {
    on: events.on.bind(events), removeListener: events.removeListener.bind(events), timers: time,
    write: () => output.promise, error: () => { errors++; return error.promise; }, terminate() { terminated++; },
  });
  await new Promise(resolve => setImmediate(resolve)); time.advance(6000); events.emit("SIGINT");
  output.resolve(); await new Promise(resolve => setImmediate(resolve));
  time.advance(999); assert.equal(terminated, 0); time.advance(1);
  assert.equal(terminated, 1); assert.equal(errors, 1);
  error.resolve(); assert.equal(await done, 1);
});

test("actual executable owns asynchronous stderr write failure without an uncaught stack", async () => {
  const entry = new URL("../health-process.ts", import.meta.url).href;
  const script = `import { Writable } from 'node:stream';
    Object.defineProperty(process, 'stderr', { value: new Writable({ write(_b,_e,cb) {
      setImmediate(() => cb(Error('PRIVATE_STDIO_FAILURE'))); } }) });
    process.argv = [process.execPath, 'health-process', 'bad']; await import(${JSON.stringify(entry)});`;
  const result = await new Promise<{code: unknown; stdout: string; stderr: string}>(resolve => {
    execFile(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script],
      { timeout: 3000, windowsHide: true, maxBuffer: 16384 }, (error, stdout, stderr) => resolve({ code: error?.code, stdout, stderr }));
  });
  assert.equal(result.code, 1); assert.equal(result.stdout, ""); assert.equal(result.stderr, "");
});
