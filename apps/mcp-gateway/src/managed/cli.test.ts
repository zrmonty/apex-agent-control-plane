import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";
import path from "node:path";

import { GatewayError } from "../contracts.js";
import type { ProxyRevisionConfig } from "./config.js";
import { FixedCliRunner, type SpawnedCliProcess } from "./cli.js";

const profile = {
  profileId: "portfolio-read",
  executableRef: "portfolio-cli",
  executableDigest: "sha256:" + "c".repeat(64),
  fixedArgv: ["read"],
  argvSchema: { fields: [{ name: "portfolioId", required: true }] },
  environmentAllowlist: ["LANG"],
  secretRefs: [],
  workingDirectory: "/tmp/apex",
  filesystemPolicy: "read-only",
  networkPolicy: "declared-egress",
  shell: false,
  timeoutMs: 1_000,
  maxOutputBytes: 1_024,
  allowedExitCodes: [0],
} as const;

const config = {
  cliProfiles: [profile],
} as unknown as ProxyRevisionConfig;

class FakeProcess extends EventEmitter implements SpawnedCliProcess {
  readonly stdout = new EventEmitter();
  readonly stderr = new EventEmitter();
  killed = false;

  kill(): void {
    this.killed = true;
  }
}

test("runs a fixed executable with typed argv, a sandbox cwd, and no shell", async () => {
  const child = new FakeProcess();
  let invocation: { command: string; args: readonly string[]; options: Record<string, unknown> } | undefined;
  const runner = new FixedCliRunner(config, {
    sandboxRoot: "C:/apex-sandbox",
    environment: { LANG: "C.UTF-8", SECRET_SHOULD_NOT_PASS: "hidden" },
    executableAllowlist: new Map([["portfolio-cli", { path: "/usr/local/bin/portfolio", digest: profile.executableDigest }]]),
    spawn(command, args, options) {
      invocation = { command, args, options };
      queueMicrotask(() => {
        child.stdout.emit("data", Buffer.from('{"status":"ok","token":"remove-me"}'));
        child.stderr.emit("data", Buffer.from("diagnostic"));
        child.emit("close", 0);
      });
      return child;
    },
  });
  const result = await runner.run("portfolio-read", { portfolioId: "northstar-401k" });

  assert.deepEqual(invocation?.args, ["read", "northstar-401k"]);
  assert.equal(invocation?.command, "/usr/local/bin/portfolio");
  assert.equal(invocation?.options.shell, false);
  assert.equal(invocation?.options.cwd, path.resolve("C:/apex-sandbox/apex"));
  assert.deepEqual(invocation?.options.env, { LANG: "C.UTF-8" });
  assert.deepEqual(result.stdout, { status: "ok" });
  assert.equal(result.stderrBytes, 10);
  assert.equal(child.killed, false);
});

test("rejects unknown profiles, unknown fields, and unsafe invocation values", async () => {
  const runner = new FixedCliRunner(config, {
    sandboxRoot: "C:/apex-sandbox",
    executableAllowlist: new Map([["portfolio-cli", { path: "/usr/local/bin/portfolio", digest: profile.executableDigest }]]),
  });
  await assert.rejects(() => runner.run("missing", {}));
  await assert.rejects(() => runner.run("portfolio-read", { portfolioId: "northstar-401k", extra: "x" }));
  await assert.rejects(() => runner.run("portfolio-read", { portfolioId: "$(id)" }));
});

test("fails safely on output overflow and disallowed exit codes", async () => {
  const child = new FakeProcess();
  const runner = new FixedCliRunner(config, {
    sandboxRoot: "C:/apex-sandbox",
    executableAllowlist: new Map([["portfolio-cli", { path: "/usr/local/bin/portfolio", digest: profile.executableDigest }]]),
    spawn(_command, _args, _options) {
      queueMicrotask(() => child.stdout.emit("data", Buffer.alloc(2_000)));
      return child;
    },
  });
  await assert.rejects(
    () => runner.run("portfolio-read", { portfolioId: "northstar-401k" }),
    (error: unknown) => error instanceof GatewayError && error.code === "ADAPTER_FAILED",
  );
  assert.equal(child.killed, true);
});

test("rejects a profile that is not fixed, bounded, and allowlisted", () => {
  assert.throws(
    () => new FixedCliRunner({ cliProfiles: [{ ...profile, shell: true }] } as unknown as ProxyRevisionConfig, { sandboxRoot: "C:/apex-sandbox" }),
    (error: unknown) => error instanceof GatewayError && error.code === "INVALID_INPUT",
  );
});
