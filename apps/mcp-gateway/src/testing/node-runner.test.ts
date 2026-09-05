import assert from "node:assert/strict";
import { ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { NodeRunError, runNode } from "./node-runner.js";

const cwd = fileURLToPath(new URL("../../", import.meta.url));
const entrypoint = "src/testing/node-child.ts";

test("owns the actual TypeScript entrypoint PID without a CLI launcher descendant", async () => {
  const result = await runNode({ cwd, entrypoint, args: ["identity"] });
  assert.equal(result.code, 0);
  assert.equal(result.stderr.length, 0);
  assert.deepEqual(JSON.parse(result.stdout.toString("utf8")), { pid: result.pid, parent: process.pid });
  assert.throws(() => process.kill(result.pid!, 0), { code: "ESRCH" });
});

test("a deadline is an explicit failure and the hanging owned child is reaped before settlement", async () => {
  const started = performance.now();
  await assert.rejects(() => runNode({ cwd, entrypoint, args: ["hang"], timeoutMs: 500 }),
    (error: unknown) => {
      assert.ok(error instanceof NodeRunError);
      assert.match(error.message, /timeout/);
      const result = error.result;
      assert.equal(result.reaped, true);
      assert.throws(() => process.kill(result.pid!, 0), { code: "ESRCH" });
      return true;
    });
  assert.ok(performance.now() - started < 2500, "deadline plus cleanup must settle before the fixture safety fuse");
});

test("retains exactly the independent stdout/stderr UTF-8 byte budgets without truncating legal output", async () => {
  const result = await runNode({ cwd, entrypoint, args: ["exact-utf8"] });
  assert.equal(result.code, 0);
  assert.equal(result.stdout.byteLength, 16384);
  assert.equal(result.stderr.byteLength, 16384);
  assert.equal(result.stdout.toString("utf8"), "€".repeat(5461) + "x");
  assert.equal(result.stderr.toString("utf8"), "é".repeat(8192));
});

for (const stream of ["stdout", "stderr"] as const) {
  test(`${stream} flooding rejects on overflow, retains bounded bytes and reaps the owned child`, async () => {
    await assert.rejects(() => runNode({ cwd, entrypoint, args: [`${stream}-flood`], timeoutMs: 2000 }),
      (error: unknown) => {
        assert.ok(error instanceof NodeRunError);
        assert.equal(error.reason, `${stream}-overflow`);
        assert.equal(error.result[stream].byteLength, 16384);
        assert.ok(error.result.stdout.byteLength <= 16384 && error.result.stderr.byteLength <= 16384);
        assert.equal(error.result.reaped, true);
        assert.equal(error.cleanupTimedOut, false);
        assert.throws(() => process.kill(error.result.pid!, 0), { code: "ESRCH" });
        return true;
      });
  });
}

test("multibyte output overflow remains an explicit failure even if the child exits normally", async () => {
  await assert.rejects(() => runNode({ cwd, entrypoint, args: ["overflow-on-exit"] }), (error: unknown) => {
    assert.ok(error instanceof NodeRunError);
    assert.equal(error.reason, "stdout-overflow");
    assert.equal(error.result.stdout.byteLength, 16384);
    assert.equal(error.result.stderr.byteLength, 0);
    assert.equal(error.result.reaped, true);
    assert.throws(() => process.kill(error.result.pid!, 0), { code: "ESRCH" });
    return true;
  });
});

for (const mode of ["ignore-term", "soft-exit"] as const) {
  test(`deadline remains a failure with the ${mode} handler, with POSIX signal semantics where supported`, async t => {
    const started = performance.now();
    await assert.rejects(() => runNode({ cwd, entrypoint, args: [mode], timeoutMs: 1000 }), (error: unknown) => {
      assert.ok(error instanceof NodeRunError);
      assert.equal(error.reason, "timeout");
      assert.equal(error.result.stdout.toString("utf8"), "ready", "the signal handler was installed before the deadline");
      assert.equal(error.result.reaped, true);
      assert.equal(error.cleanupTimedOut, false);
      assert.throws(() => process.kill(error.result.pid!, 0), { code: "ESRCH" });
      if (process.platform !== "win32") {
        if (mode === "ignore-term") assert.equal(error.result.signal, "SIGKILL");
        else assert.equal(error.result.code, 0, "a graceful zero exit must not erase the timeout");
      } else {
        assert.notEqual(error.result.code, 0);
        t.diagnostic("Windows force-terminates SIGTERM; real ignored/graceful POSIX signal handling is not claimed exercised.");
      }
      return true;
    });
    assert.ok(performance.now() - started < 2500, "teardown must finish before the fixture's safety fuse");
  });
}

test("escalates when soft-signal delivery reports success without exiting the real owned child", async t => {
  // Signal-delivery system boundary only. Windows cannot ignore real SIGTERM;
  // keep spawning, the hard kill, OS reaping and PID-existence checks real.
  const kill = ChildProcess.prototype.kill;
  t.mock.method(ChildProcess.prototype, "kill", function(this: ChildProcess, signal?: NodeJS.Signals | number) {
    return signal === "SIGTERM" ? true : kill.call(this, signal);
  });
  await assert.rejects(() => runNode({ cwd, entrypoint, args: ["hang"], timeoutMs: 500 }), (error: unknown) => {
    assert.ok(error instanceof NodeRunError);
    assert.equal(error.reason, "timeout");
    assert.equal(error.result.signal, "SIGKILL");
    assert.equal(error.result.reaped, true);
    assert.equal(error.cleanupTimedOut, false);
    assert.throws(() => process.kill(error.result.pid!, 0), { code: "ESRCH" });
    return true;
  });
});

test("spawn failure settles with static diagnostics and no owned child or retained output", async () => {
  await assert.rejects(() => runNode({ cwd: `${cwd}/SENSITIVE-missing-directory`, entrypoint }), (error: unknown) => {
    assert.ok(error instanceof NodeRunError);
    assert.equal(error.reason, "spawn");
    assert.equal(error.message, "node test child spawn");
    assert.equal(error.result.pid, undefined);
    assert.equal(error.result.stdout.byteLength, 0);
    assert.equal(error.result.stderr.byteLength, 0);
    assert.equal(error.cleanupTimedOut, false);
    return true;
  });
});

test("the cleanup deadline settles failure even when the process close notification is withheld", async t => {
  // Model a delayed pipe-close notification at Node's system boundary. The
  // entrypoint, OS exit/reap and PID checks remain real, with no extra child.
  const emit = ChildProcess.prototype.emit;
  const delayedCloses: NodeJS.Timeout[] = [];
  t.mock.method(ChildProcess.prototype, "emit", function(this: ChildProcess, event: string | symbol, ...args: unknown[]) {
    if (event === "close" && this.spawnargs.includes(entrypoint)) {
      delayedCloses.push(setTimeout(() => Reflect.apply(emit, this, [event, ...args]), 2500));
      return true;
    }
    return Reflect.apply(emit, this, [event, ...args]);
  });
  const started = performance.now();
  try {
    await assert.rejects(() => runNode({ cwd, entrypoint, args: ["identity"], timeoutMs: 500 }), (error: unknown) => {
      assert.ok(error instanceof NodeRunError);
      assert.equal(error.reason, "timeout");
      assert.equal(error.cleanupTimedOut, true);
      assert.equal(error.result.code, 0, "an exited child must not erase the missing-close failure");
      assert.equal(error.result.reaped, true);
      assert.throws(() => process.kill(error.result.pid!, 0), { code: "ESRCH" });
      return true;
    });
    assert.ok(performance.now() - started < 2300, "settlement cannot wait for the withheld close event");
  } finally { delayedCloses.forEach(clearTimeout); }
});
