import test from "node:test";
import assert from "node:assert/strict";
import { Writable } from "node:stream";
import { EventEmitter } from "node:events";
import { spawn } from "node:child_process";
import { ownHealthOutput } from "./process-host.js";
import { runHealthObservationProcess, diagnostic } from "./process.js";
import { FakeTime } from "../stage-reader/fixture.js";

test("real Writable callback-before-error remains owned through diagnostic completion", async () => {
  const order: string[] = [], errors: string[] = [];
  const stdout = new Writable({ write(_data, _encoding, callback) {
    setImmediate(() => { order.push("callback"); callback(Error("PRIVATE_STDIO")); });
  } });
  const stderr = new Writable({ write(data, _encoding, callback) { errors.push(data.toString()); callback(); } });
  const output = ownHealthOutput(stdout, stderr);
  stdout.on("error", () => order.push("event"));
  const events = new EventEmitter(); let terminated = 0;
  const result = await runHealthObservationProcess([], {}, async () => ({ text: "{}", validUntilMonotonicNs: 10_000_000_000n }), {
    ...output, on: events.on.bind(events), removeListener: events.removeListener.bind(events),
    timers: new FakeTime(), terminate() { terminated++; },
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(result, 1); assert.deepEqual(order, ["callback", "event"]);
  assert.deepEqual(errors, [diagnostic]); assert.equal(terminated, 0);
  assert.ok(stdout.listenerCount("error") > 0); assert.ok(stderr.listenerCount("error") > 0);
});

test("actual closed stdout consumer fails statically through the real process output owner", async () => {
  const host = new URL("./process-host.ts", import.meta.url).href;
  const runner = new URL("./process.ts", import.meta.url).href;
  const timers = new URL("../stage-reader/fs.ts", import.meta.url).href;
  const script = `import { ownHealthOutput } from ${JSON.stringify(host)};
    import { runHealthObservationProcess } from ${JSON.stringify(runner)};
    import { localTimers } from ${JSON.stringify(timers)};
    const output = ownHealthOutput(process.stdout, process.stderr);
    const released = new Promise(resolve => process.once('message', resolve));
    process.send('ready'); await released;
    process.exitCode = await runHealthObservationProcess([], {}, async () => ({ text: '{}', validUntilMonotonicNs: localTimers.now() + 9000000000n }), {
      ...output, timers: localTimers, on: process.on.bind(process), removeListener: process.removeListener.bind(process),
      terminate: () => process.exit(1) }); process.disconnect();`;
  const result = await new Promise<{code: unknown; stdout: string; stderr: string}>(resolve => {
    const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script],
      { windowsHide: true, stdio: ["ignore", "pipe", "pipe", "ipc"] });
    const out = child.stdout!, err = child.stderr!;
    let stdout = "", stderr = "";
    const watchdog = setTimeout(() => child.kill(), 3000);
    out.on("data", data => { stdout += data; }); err.on("data", data => { stderr += data; });
    child.once("message", () => {
      out.once("close", () => child.send("consumer closed")); out.destroy();
    });
    child.once("close", code => { clearTimeout(watchdog); resolve({ code, stdout, stderr }); });
  });
  assert.equal(result.code, 1); assert.equal(result.stdout, ""); assert.equal(result.stderr, diagnostic);
});
