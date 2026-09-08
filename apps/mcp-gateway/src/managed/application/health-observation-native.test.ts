import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { decodeStrict, encodeJson, RuntimeHealthSampleSchema, ReadinessCheckStatus } from "@apex/contracts";
import { startManagedApplication, type ManagedApplication } from "../application.js";
import { nativeServices } from "./native-services.js";
import { bounded, cleanupFixture } from "./native-observation.js";

// Exact sealed child env; the parent's fixture selector is never inherited.
function observe(env: NodeJS.ProcessEnv, args: string[] = []) {
  // Only the test parent selects one of two fixed paths. Packaged mode mounts
  // no observer source over the image; its own tsc output and dependencies run.
  const entry = process.env.APEX_TEST_HEALTH_PACKAGED === "packaged-health-v1"
    ? "/app/apps/mcp-gateway/dist/managed/health-process.js" : "/component/health-process.mjs";
  const started = process.hrtime.bigint();
  const child = spawn(process.execPath, [entry, ...args], { env, stdio: ["ignore", "pipe", "pipe"] });
  const buffers = { stdout: Buffer.alloc(16385), stderr: Buffer.alloc(1024) };
  const lengths = { stdout: 0, stderr: 0 };
  let ended = false, failed = false;
  for (const kind of ["stdout", "stderr"] as const) child[kind].on("data", (bytes: Buffer) => {
    if (lengths[kind] + bytes.length > buffers[kind].length) { failed = true; child.kill("SIGKILL"); return; }
    bytes.copy(buffers[kind], lengths[kind]); lengths[kind] += bytes.length;
  });
  child.on("error", () => { failed = true; });
  const timer = setTimeout(() => { failed = true; child.kill("SIGKILL"); }, 11000);
  const closed = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve => {
    child.once("close", (code, signal) => { ended = true; clearTimeout(timer); resolve({ code, signal }); });
  });
  const reaped = () => assert.throws(() => process.kill(child.pid!, 0), { code: "ESRCH" });
  return {
    async result() {
      const result = await closed;
      assert.equal(failed, false, "watchdog/overflow/spawn failure is not a valid observation");
      assert.equal(result.signal, null); reaped();
      return { ...result, elapsedNs: process.hrtime.bigint() - started, stdout: buffers.stdout.subarray(0, lengths.stdout).toString("utf8"),
        stderr: buffers.stderr.subarray(0, lengths.stderr).toString("utf8") };
    },
    async cleanup() {
      if (!ended) { failed = true; child.kill("SIGKILL"); }
      await bounded(closed, 2000, "health observation child reap unproved"); reaped();
    },
  };
}

function assertReady(result: Awaited<ReturnType<ReturnType<typeof observe>["result"]>>) {
  assert.equal(result.code, 0); assert.equal(result.stderr, "");
  assert.equal(result.stdout.endsWith("\n"), true); assert.equal(result.stdout.split("\n").length, 2);
  const sample = decodeStrict(RuntimeHealthSampleSchema, result.stdout.trimEnd());
  assert.equal(result.stdout, JSON.stringify(encodeJson(RuntimeHealthSampleSchema, sample)) + "\n");
  assert.equal(sample.schemaVersion, 1);
  assert.ok(sample.validForNs > result.elapsedNs && sample.validForNs <= 10_000_000_000n);
  const report = sample.report!; assert.ok(report);
  assert.equal(report.live, true); assert.equal(report.ready, true);
  assert.equal(report.target!.generation, 9007199254740993n);
  assert.equal(report.checks.length, 9); assert.equal(new Set(report.checks.map(c => c.id)).size, 9);
  assert.ok(report.checks.every(c => c.status === ReadinessCheckStatus.PASS));
  assert.equal(report.stages.length, 9); assert.ok(report.stages.every(s => typeof s.durationUs === "bigint"));
  assert.ok(report.observedAtUnixUs > 0n);
}

for (const scenario of ["ready PREPARE", "wrong stage hash", "missing listener", "unexpected argument"] as const) {
  test(`fixed health observation executable: ${scenario}`, {
    timeout: 15000, skip: process.env.APEX_TEST_APPLICATION_ROOT !== "health-observation-native-v1",
  }, async t => {
    assert.equal(process.platform, "linux"); assert.equal(process.getuid!(), 10001);
    const fixture = JSON.parse(await readFile("/fixture/client.json", "utf8")) as { env: NodeJS.ProcessEnv };
    const services = await nativeServices();
    let owner: ManagedApplication | undefined, fatals = 0;
    t.after(async () => {
      if (owner) assert.equal(await cleanupFixture(owner, services.close), "fixture-cleaned");
      else await services.close();
    });
    if (scenario !== "missing listener") {
      owner = startManagedApplication({ env: fixture.env, onFatal() { fatals++; } });
      await owner.result;
      // SAME live stage/listener must support a valid, fully reaped observation
      // before mutating only the subsequent child's digest or argv. Otherwise an
      // unrelated stage/probe defect could mask ignoring either invalid input.
      const baseline = observe(fixture.env);
      t.after(() => baseline.cleanup());
      assertReady(await baseline.result());
    }
    const env = { ...fixture.env };
    if (scenario === "wrong stage hash") {
      assert.notEqual(env.APEX_STAGE_MANIFEST_SHA256, "0".repeat(64)); env.APEX_STAGE_MANIFEST_SHA256 = "0".repeat(64);
    }
    if (scenario !== "ready PREPARE") {
      const child = observe(env, scenario === "unexpected argument" ? ["SENSITIVE-ignored-argument"] : []);
      t.after(() => child.cleanup());
      const result = await child.result();
      assert.equal(result.code, 1); assert.equal(result.stdout, "");
      assert.equal(result.stderr, "GOVERNANCE_UNAVAILABLE: managed health observation refused safely\n");
      if (scenario === "missing listener") assert.deepEqual(services.methods, []);
    }
    if (owner) {
      owner.cancel(); await bounded(owner.closed, 4500, "actual application cleanup");
      assert.deepEqual(await owner.completionHandoff, []); assert.equal(fatals, 0);
    }
    assert.equal(services.stats().toolCalls, 0); assert.equal(services.stats().event, undefined);
    assert.ok(services.methods.every(method => !method.includes("ManagedCall")));
  });
}
