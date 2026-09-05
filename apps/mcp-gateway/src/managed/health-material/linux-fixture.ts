/** TEST ONLY fixed Linux fixture entry. Not imported by production or .test.ts.
 * seed <case>: root, FRESH empty writable volume at /run/apex/runtime.
 * case <case>: UID/GID10001, same volume read-only, read-only root filesystem.
 * Both require the independent actual Rust artifact at /fixture/runtime-revision.json.
 * Main owns containers/mounts and teardown. No arbitrary path or recursive delete. */
import assert from "node:assert/strict";
import { constants } from "node:fs";
import { chmod, chown, link, lstat, readFile, readdir, readlink, symlink, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { createClock } from "../../telemetry/clock.js";
import { startHealthMaterialLoad } from "../health-material-loader.js";
import { GatewayError } from "../../contracts.js";

const ROOT = "/run/apex/runtime";
const names = ["runtime-revision.json", "launch-context.json", "health-token"];
const cases = ["valid", "config-limit", "launch-limit", "config-overflow", "launch-overflow",
  "symlink", "hardlink", "fifo", "wrong-uid", "wrong-gid", "wrong-mode", "missing-token",
  "short-token", "token-newline", "token-noncanonical"] as const;
type Case = typeof cases[number];
const positive = (name: Case) => name === "valid" || name === "config-limit" || name === "launch-limit";

function content(name: Case, original: readonly Buffer[]): Buffer[] {
  const files = original.map(value => Buffer.from(value));
  for (const [index, label, cap] of [[0, "config", 262144], [1, "launch", 16384]] as const) {
    if (name === `${label}-limit` || name === `${label}-overflow`) {
      const size = cap + (name === `${label}-overflow` ? 1 : 0);
      files[index] = Buffer.concat([files[index], Buffer.alloc(size - files[index].length, 32)]);
    }
  }
  if (name === "short-token") files[2] = files[2].subarray(0, 42);
  if (name === "token-newline") files[2] = Buffer.concat([files[2], Buffer.from("\n")]);
  if (name === "token-noncanonical") files[2][42] += 1;
  return files;
}

async function seed(name: Case, files: readonly Buffer[]): Promise<void> {
  assert.equal(process.getuid!(), 0, "seed requires separate root fixture container");
  assert.ok((await lstat(ROOT)).isDirectory());
  assert.equal((await readdir(ROOT)).length, 0, "fresh empty owned volume required");
  for (const [index, slot] of names.entries()) {
    if (index === 2 && ["symlink", "fifo", "missing-token"].includes(name)) continue;
    await writeFile(`${ROOT}/${slot}`, files[index], { flag: "wx", mode: 0o400 });
    await chown(`${ROOT}/${slot}`, 10001, 10001);
    await chmod(`${ROOT}/${slot}`, 0o400);
  }
  const token = `${ROOT}/health-token`;
  if (name === "symlink") {
    await writeFile(`${ROOT}/token-target`, files[2], { flag: "wx", mode: 0o400 });
    await chown(`${ROOT}/token-target`, 10001, 10001);
    await chmod(`${ROOT}/token-target`, 0o400);
    await symlink("token-target", token);
  }
  if (name === "hardlink") await link(token, `${ROOT}/token-hardlink`);
  if (name === "fifo") {
    execFileSync("mkfifo", ["-m", "400", token], { stdio: "ignore" });
    await chown(token, 10001, 10001); await chmod(token, 0o400);
  }
  if (name === "wrong-uid") await chown(token, 0, 10001);
  if (name === "wrong-gid") await chown(token, 10001, 0);
  if (name === "wrong-mode") await chmod(token, 0o440);
  await chown(ROOT, 10001, 10001); await chmod(ROOT, 0o500);
}

/** Prove the intended OS counterexample is provisioned; malformed setup cannot
 * masquerade as a passing refusal. Never read FIFO/symlink/wrong-owner token. */
async function checkFixture(name: Case, files: readonly Buffer[]): Promise<void> {
  for (const path of ["/", "/run", "/run/apex", ROOT]) assert.ok((await lstat(path)).isDirectory());
  for (const [index, slot] of names.entries()) {
    const path = `${ROOT}/${slot}`;
    if (index === 2 && name === "missing-token") {
      await assert.rejects(lstat(path), error => (error as NodeJS.ErrnoException).code === "ENOENT");
      continue;
    }
    const info = await lstat(path, { bigint: true });
    if (index === 2 && name === "symlink") { assert.ok(info.isSymbolicLink()); continue; }
    if (index === 2 && name === "fifo") { assert.ok(info.isFIFO()); continue; }
    assert.ok(info.isFile());
    assert.equal(info.uid, index === 2 && name === "wrong-uid" ? 0n : 10001n);
    assert.equal(info.gid, index === 2 && name === "wrong-gid" ? 0n : 10001n);
    assert.equal(info.mode, index === 2 && name === "wrong-mode" ? 0o100440n : 0o100400n);
    assert.equal(info.nlink, index === 2 && name === "hardlink" ? 2n : 1n);
    assert.equal(info.size, BigInt(files[index].length));
    if (index !== 2 || name !== "wrong-uid") {
      // A bounded, test-only prerequisite check; no bytes in assertion output.
      const bytes = await readFile(path);
      try { assert.ok(bytes.equals(files[index]), "exact test fixture contents required"); }
      finally { bytes.fill(0); }
    }
  }
}

async function stagedDescriptors(): Promise<number> {
  let count = 0;
  for (const fd of await readdir("/proc/self/fd")) {
    try { if ((await readlink(`/proc/self/fd/${fd}`)).startsWith(`${ROOT}/`)) count++; }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  }
  return count;
}
async function refused(promise: Promise<unknown>): Promise<void> {
  await assert.rejects(promise, error => error instanceof GatewayError &&
    error.message === "INVALID_INPUT: health material rejected safely" && !("cause" in error));
}

async function main(): Promise<void> {
  assert.equal(process.platform, "linux", "Linux required, no platform skip");
  assert.ok(constants.O_NOFOLLOW > 0 && constants.O_NONBLOCK > 0);
  assert.equal(process.env.APEX_RUNTIME_FIXTURE_PATH, "/fixture/runtime-revision.json");
  const [mode, rawCase, ...extra] = process.argv.slice(2);
  assert.equal(extra.length, 0); assert.ok(mode === "seed" || mode === "case");
  assert.ok(cases.includes(rawCase as Case)); const name = rawCase as Case;
  // Import after preconditions; no expected binding is constructed from staged files.
  const { fixtureData } = await import("./fixture-data.js");
  const data = fixtureData(), files = content(name, data.files);
  try {
    if (mode === "seed") await seed(name, files);
    else {
      assert.equal(process.getuid!(), 10001); assert.equal(process.getgid!(), 10001);
      await checkFixture(name, files); assert.equal(await stagedDescriptors(), 0);
      let fatals = 0;
      const options = { owner: { expected: data.expected, isCurrent: () => true },
        clock: createClock(), onFatal() { fatals++; } };
      // Synthetic test owner only, NOT evidence of authenticated staging.
      const first = startHealthMaterialLoad(options), overlap = startHealthMaterialLoad(options);
      // Attach both observations before awaiting either to avoid unhandled rejection.
      const firstResult = first.completion.then(value => ({ value }), error => ({ error }));
      await refused(overlap.completion);
      const result = await firstResult;
      if (positive(name)) {
        assert.ok("value" in result, "valid fixed mount must load");
        const loaded = result.value;
        assert.deepEqual(loaded.binding, data.expected);
        assert.ok(loaded.tokenBytes.length === 32 && loaded.tokenBytes.equals(data.token));
        assert.equal(await stagedDescriptors(), 0);
        const replacement = await startHealthMaterialLoad(options).completion;
        assert.ok(loaded.tokenBytes.equals(data.token), "job release does not dispose prior token");
        loaded.dispose(); first.cancel(); assert.ok(loaded.tokenBytes.every(byte => byte === 0));
        replacement.dispose(); assert.ok(replacement.tokenBytes.every(byte => byte === 0));
      } else {
        assert.ok("error" in result, "counterexample must refuse");
        await refused(Promise.reject(result.error));
      }
      assert.equal(fatals, 0); assert.equal(await stagedDescriptors(), 0);
    }
    process.stdout.write(`health-material fixture ${mode} ${name}: PASS\n`);
  } finally { data.token.fill(0); for (const bytes of [...data.files, ...files]) bytes.fill(0); }
}

// This test watchdog is process termination, NOT loader I/O-termination evidence.
// Production's 2s/5s limits are unchanged. The main harness also owns a deadline.
const watchdog = setTimeout(() => {
  process.stderr.write("health-material Linux fixture watchdog failure\n"); process.exit(1);
}, 9000);
void main().catch(() => {
  process.stderr.write("health-material Linux fixture failed safely\n"); process.exitCode = 1;
}).finally(() => { clearTimeout(watchdog); });
