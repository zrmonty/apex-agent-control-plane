import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { NodeRunError, runNode } from "./node-runner.js";

const cwd = fileURLToPath(new URL("../../", import.meta.url));

test("bounded owned runner supports a response-driven dialogue and closes its consumer exactly once", async () => {
  let write: (input: string) => void;
  let complete: () => void;
  let closed = 0, received = "";
  const result = await runNode({ cwd, entrypoint: "src/testing/node-dialogue-child.ts", dialogue: {
    start: async send => {
      write = send;
      await new Promise<void>(resolve => { complete = resolve; });
    },
    receive: chunk => {
      received += chunk.toString("utf8");
      if (received === "ready\n") write("ping\n");
      if (received === "ready\npong\n") complete();
    },
    close: () => { closed++; },
  } });
  assert.equal(result.code, 0);
  assert.equal(received, "ready\npong\n");
  assert.equal(result.stdout.toString("utf8"), received);
  assert.equal(result.stderr.byteLength, 0);
  assert.equal(closed, 1);
  assert.equal(result.reaped, true);
  assert.throws(() => process.kill(result.pid!, 0), { code: "ESRCH" });
});

for (const stage of ["start", "receive", "close"] as const) {
  test(`dialogue ${stage} errors remain static failures with reaped child and closed consumer`, async () => {
    let closed = 0;
    await assert.rejects(() => runNode({ cwd, entrypoint: "src/testing/node-child.ts", args: ["identity"], dialogue: {
      start: async () => { if (stage === "start") throw new Error("SENSITIVE"); },
      receive: () => { if (stage === "receive") throw new Error("SENSITIVE"); },
      close: () => { closed++; if (stage === "close") throw new Error("SENSITIVE"); },
    } }), (error: unknown) => {
      assert.ok(error instanceof NodeRunError);
      assert.equal(error.message, "node test child io");
      assert.equal(error.result.reaped, true);
      assert.throws(() => process.kill(error.result.pid!, 0), { code: "ESRCH" });
      return true;
    });
    assert.equal(closed, 1);
  });
}

for (const mode of ["hang", "stdout-flood", "stderr-flood", "identity"] as const) {
  test(`unfinished ${mode} dialogue cannot bypass deadlines, byte budgets or consumer cleanup`, async () => {
    let closed = 0, forwardedBytes = 0;
    let complete: () => void;
    await assert.rejects(() => runNode({ cwd, entrypoint: "src/testing/node-child.ts", args: [mode], timeoutMs: 500, dialogue: {
      start: () => new Promise<void>(resolve => { complete = resolve; }),
      receive: chunk => { forwardedBytes += chunk.byteLength; },
      close: () => { closed++; complete(); },
    } }), (error: unknown) => {
      assert.ok(error instanceof NodeRunError);
      assert.equal(error.reason, mode === "hang" ? "timeout" : mode === "identity" ? "io" : mode.replace("flood", "overflow"));
      assert.ok(error.result.stdout.byteLength <= 16384 && error.result.stderr.byteLength <= 16384);
      assert.equal(error.result.reaped, true);
      assert.equal(error.cleanupTimedOut, false);
      assert.throws(() => process.kill(error.result.pid!, 0), { code: "ESRCH" });
      return true;
    });
    assert.ok(forwardedBytes <= 16384, "consumer never sees an overflowing chunk");
    assert.equal(closed, 1);
  });
}
