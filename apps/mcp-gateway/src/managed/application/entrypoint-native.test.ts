import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { request } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import { decodeStrict, ReadinessReportSchema, ReadinessCheckStatus } from "@apex/contracts";
import { nativeServices } from "./native-services.js";
import { bounded } from "./native-observation.js";

// The child runs the real bundled index with exactly the agent-owned env, not
// a test factory/profile or the parent fixture's APEX_TEST_* selector.
function executable(env: NodeJS.ProcessEnv) {
  const child = spawn(process.execPath, ["/component/entrypoint.mjs"], { env, stdio: ["ignore", "pipe", "pipe"] });
  let ended = false, failure = false;
  const stdout = Buffer.alloc(8192), stderr = Buffer.alloc(8192);
  let out = 0, err = 0;
  const capture = (kind: "stdout" | "stderr", bytes: Buffer) => {
    const target = kind === "stdout" ? stdout : stderr, offset = kind === "stdout" ? out : err;
    if (offset + bytes.length > target.length) { failure = true; child.kill("SIGKILL"); return; }
    bytes.copy(target, offset); if (kind === "stdout") out += bytes.length; else err += bytes.length;
  };
  child.stdout.on("data", bytes => capture("stdout", bytes)); child.stderr.on("data", bytes => capture("stderr", bytes));
  child.on("error", () => { failure = true; });
  const timer = setTimeout(() => { failure = true; child.kill("SIGKILL"); }, 15000);
  const closed = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve => {
    child.once("close", (code, signal) => { ended = true; clearTimeout(timer); resolve({ code, signal }); });
  });
  return { stopped: () => ended, signal: () => child.kill("SIGTERM"),
    async result() {
      const result = await closed;
      assert.equal(failure, false, "fixture timeout/overflow/spawn failure cannot become process success");
      assert.throws(() => process.kill(child.pid!, 0), { code: "ESRCH" });
      assert.equal(result.signal, null, "native signal death is not graceful process handling");
      assert.equal(out, 0);
      return { ...result, stderr: stderr.subarray(0, err).toString("utf8") };
    },
    async cleanup() {
      if (!ended) { failure = true; child.kill("SIGKILL"); }
      await bounded(closed, 2000, "fixture child reap unproved");
      assert.throws(() => process.kill(child.pid!, 0), { code: "ESRCH" });
    },
  };
}

function health(token: string) {
  return new Promise<ReturnType<typeof decodeStrict<typeof ReadinessReportSchema>>>((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port: 8081, path: "/readyz", agent: false,
      headers: { host: "127.0.0.1:8081", authorization: `Bearer ${token}` } }, response => {
      let body = ""; response.on("data", bytes => { body += String(bytes); if (body.length > 8192) req.destroy(Error("fixture health bound")); });
      response.on("end", () => {
        try { assert.equal(response.statusCode, 200); resolve(decodeStrict(ReadinessReportSchema, body)); } catch (error) { reject(error); }
      }); response.on("error", reject);
    });
    req.on("error", reject); req.setTimeout(500, () => req.destroy(Error("fixture health timeout"))); req.end();
  });
}
async function ready(child: ReturnType<typeof executable>, token: string) {
  const deadline = performance.now() + 7500;
  do {
    assert.equal(child.stopped(), false, "executable stopped before readiness");
    try {
      const report = await health(token);
      if (report.ready && report.checks.length === 9 && report.checks.every(c => c.status === ReadinessCheckStatus.PASS)) return;
    } catch { /* A not-yet-bound/cold listener is expected before actual startup. */ }
    await delay(20);
  } while (performance.now() < deadline);
  throw Error("executable readiness deadline");
}

for (const scenario of ["SIGTERM", "transport loss", "wrong stage hash"] as const) {
  test(`actual sealed managed entrypoint: ${scenario}`, {
    timeout: 20000, skip: process.env.APEX_TEST_APPLICATION_ROOT !== "entrypoint-native-v1",
  }, async t => {
    assert.equal(process.platform, "linux"); assert.equal(process.getuid!(), 10001);
    const fixture = JSON.parse(await readFile("/fixture/client.json", "utf8")) as { env: NodeJS.ProcessEnv };
    const services = await nativeServices();
    const env = { ...fixture.env };
    if (scenario === "wrong stage hash") { assert.notEqual(env.APEX_STAGE_MANIFEST_SHA256, "0".repeat(64)); env.APEX_STAGE_MANIFEST_SHA256 = "0".repeat(64); }
    const child = executable(env);
    t.after(async () => { await services.close(); await child.cleanup(); });
    if (scenario === "wrong stage hash") {
      assert.deepEqual(await child.result(), { code: 1, signal: null, stderr: "GOVERNANCE_UNAVAILABLE: managed application stopped safely\n" });
      assert.deepEqual(services.methods, []); return;
    }
    await ready(child, await readFile("/apex/runtime/health-token", "utf8"));
    assert.equal(services.stats().toolCalls, 0); assert.equal(services.stats().event, undefined);
    services.serve(); await bounded(services.applied, 5000, "SERVE applied acknowledgment deadline");
    if (scenario === "SIGTERM") assert.equal(child.signal(), true); else await services.close();
    const result = await bounded(child.result(), 6000, "managed executable shutdown deadline");
    assert.equal(result.code, scenario === "SIGTERM" ? 0 : 1);
    assert.equal(result.stderr, scenario === "SIGTERM" ? "" : "GOVERNANCE_UNAVAILABLE: managed application stopped safely\n");
  });
}
