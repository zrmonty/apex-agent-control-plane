import assert from "node:assert/strict";
import { test } from "node:test";
import { RuntimeConfigurationSchema, RuntimeLaunchContextSchema, RuntimeMaterialRole, encodeJson,
  type RuntimeConfiguration, type RuntimeLaunchContext } from "@apex/contracts";
import { clone } from "@bufbuild/protobuf";
import { runtimeManifestHash } from "../runtime-config.js";
import { launchContextHash, parseRuntimeLaunchContext } from "../launch-context.js";
import { fixture, paths, rejects, wiped } from "./test-fixture.js";

for (const [index, cap] of [[0, 262144], [1, 16384]]) {
  test(`slot ${index} accepts exact ${cap} bytes of valid original JSON with whitespace`, async () => {
    const f = fixture();
    f.files[index] = Buffer.concat([f.files[index], Buffer.alloc(cap - f.files[index].length, 32)]);
    const loaded = await f.start().completion;
    assert.deepEqual(loaded.binding, f.expected); loaded.dispose();
    assert.ok(f.buffers.every(b => b.length <= 262145));
    assert.ok(wiped(f.buffers));
  });
  test(`slot ${index} refuses ${cap + 1} bytes before acquiring that slot`, async () => {
    const f = fixture(); f.files[index] = Buffer.alloc(cap + 1, 32);
    await rejects(f.start().completion);
    assert.ok(!f.calls.includes(`open:${paths[index]}`));
    assert.ok(!f.calls.includes(`open:${paths[2]}`)); assert.equal(f.counts.active, 0);
  });
}

test("token slot rejects noncanonical sizes/alphabet/padding/Unicode/BOM/newline with static errors", async () => {
  const f0 = fixture();
  const good = f0.files[2];
  const noncanonical = Buffer.from(good); noncanonical[42] += 1; // U -> V: same decoded bytes, illegal padding bits.
  for (const token of [Buffer.alloc(0), good.subarray(0, 42), Buffer.concat([good, Buffer.from("A")]),
    Buffer.concat([good, Buffer.from("=")]), Buffer.concat([good, Buffer.from("\n")]),
    Buffer.concat([Buffer.from([239, 187, 191]), good]), Buffer.from("é".repeat(21) + "A"),
    Buffer.from("!".repeat(43)), Buffer.from(" ".repeat(43)), noncanonical]) {
    const f = fixture(); f.files[2] = token;
    await rejects(f.start().completion);
    assert.equal(f.counts.active, 0); assert.ok(wiped(f.buffers));
    assert.ok(f.buffers.every(buffer => buffer.length <= 262145));
  }
});

test("original duplicate and field-alias JSON survives file reading and fails before token acquisition", async () => {
  for (const index of [0, 1]) for (const alias of ["schemaVersion", "schema_version"]) {
    const f = fixture();
    const text = f.files[index].toString("utf8");
    f.files[index] = Buffer.from(text.replace("{", `{"${alias}":1,`));
    await rejects(f.start().completion);
    assert.ok(!f.calls.includes(`open:${paths[2]}`)); assert.equal(f.counts.active, 0);
  }
});

test("fatal UTF8 and BOM metadata refuses before any health token read", async () => {
  for (const index of [0, 1]) for (const prefix of [Buffer.from([255]), Buffer.from([239, 187, 191])]) {
    const f = fixture(); f.files[index] = Buffer.concat([prefix, f.files[index]]);
    await rejects(f.start().completion);
    assert.ok(!f.calls.includes(`open:${paths[2]}`)); assert.ok(wiped(f.buffers));
  }
});

test("independent full expected binding rejects re-signed configuration and launch relation changes", async () => {
  for (const field of ["config", "version", "reference", "profile", "instance", "fence", "order"] as const) {
    const f = fixture();
    const config = clone(RuntimeConfigurationSchema, f.expected.config as RuntimeConfiguration);
    const launch = clone(RuntimeLaunchContextSchema, f.expected.launch as RuntimeLaunchContext);
    if (field === "config") {
      config.spec!.governanceBinding!.rateLimit += 1;
      config.runtimeManifestHash = runtimeManifestHash(config);
      launch.runtimeManifestHash = config.runtimeManifestHash;
    } else if (field === "version") launch.materials[0].version = "v2";
    else if (field === "reference") launch.materials[0].reference = launch.health!.credentialRef = "secret://deployment/replacement";
    else if (field === "profile") launch.authorityProfileVersion = "v2";
    else if (field === "instance") launch.processInstanceId = "01992000-0000-7000-8000-000000000002";
    else if (field === "fence") launch.target!.fencingToken += 1n;
    else launch.materials.reverse(); // Ordered full material set, independently valid.
    launch.launchContextHash = launchContextHash(launch);
    f.files[0] = Buffer.from(JSON.stringify(encodeJson(RuntimeConfigurationSchema, config)));
    f.files[1] = Buffer.from(JSON.stringify(encodeJson(RuntimeLaunchContextSchema, launch)));
    await rejects(f.start().completion);
    assert.ok(!f.calls.includes(`open:${paths[2]}`)); assert.equal(f.counts.active, 0);
  }
});

test("a re-signed known non-health role change parses validly but mismatches the independent expected binding", async () => {
  const f = fixture(), launch = clone(RuntimeLaunchContextSchema, f.expected.launch as RuntimeLaunchContext);
  assert.equal(launch.materials[1].role, RuntimeMaterialRole.GOVERNANCE_CA);
  launch.materials[1].role = RuntimeMaterialRole.EVIDENCE_CA;
  launch.launchContextHash = launchContextHash(launch);
  const text = JSON.stringify(encodeJson(RuntimeLaunchContextSchema, launch));
  const parsed = parseRuntimeLaunchContext(text, f.expected.config); // Positive metadata/hash boundary control.
  assert.equal(parsed.materials[1].role, RuntimeMaterialRole.EVIDENCE_CA);
  assert.deepEqual(parsed.materials[0], f.expected.launch.materials[0]); // HEALTH_TOKEN relation unchanged.
  f.files[1] = Buffer.from(text);
  await rejects(f.start().completion);
  assert.ok(!f.calls.includes(`open:${paths[2]}`)); assert.equal(f.counts.closed, 2);
  assert.equal(f.counts.active, 0); assert.ok(wiped(f.buffers));
});

test("Linux final-entry metadata and required flags are fail-closed before open", async () => {
  for (const changed of [{ uid: 0n }, { gid: 0n }, { mode: 0o100600n }, { mode: 0o100440n },
    { mode: 0o104400n }, { mode: 0o120400n }, { mode: 0o40400n }, { mode: 0o10400n },
    { mode: 0o20400n }, { mode: 0o140400n }, { nlink: 2n }, { size: -1n }]) {
    const f = fixture(), lstat = f.os.lstat;
    await rejects(f.start(f.options, { ...f.os, lstat: async path => ({ ...await lstat(path),
      ...(path === paths[0] ? changed : {}) }) }).completion);
    assert.equal(f.counts.active, 0); assert.equal(f.counts.closed, 0);
  }
  for (const osChange of [{ platform: "win32" }, { flags: { readOnly: 0, noFollow: 0, nonblock: 2048 } },
    { flags: { readOnly: 0, noFollow: 131072, nonblock: 0 } }]) {
    const f = fixture(); await rejects(f.start(f.options, { ...f.os, ...osChange }).completion);
    assert.equal(f.calls.length, 0);
  }
});

test("literal ancestor symlinks refuse without claiming immutable-mount provenance", async () => {
  const f = fixture(), lstat = f.os.lstat;
  await rejects(f.start(f.options, { ...f.os, lstat: async path => ({ ...await lstat(path),
    ...(path === "/run/apex" ? { mode: 0o120777n } : {}) }) }).completion);
  assert.equal(f.counts.active, 0); assert.equal(f.counts.closed, 0);
});

test("opened identity and post-read metadata must describe the same unchanged file", async () => {
  for (const post of [false, true]) for (const changed of [{ dev: 8n }, { ino: 20n }, { uid: 0n },
    { gid: 0n }, { nlink: 2n }, { mode: 0o100600n }, { size: 1n }, { mtimeNs: 6n }, { ctimeNs: 7n }]) {
    const f = fixture(), open = f.os.open;
    await rejects(f.start(f.options, { ...f.os, async open(path, flags) {
      const handle = await open(path, flags); let stats = 0;
      return { ...handle, async stat() {
        const value = await handle.stat(); stats++;
        return { ...value, ...((post ? stats === 2 : stats === 1) ? changed : {}) };
      } };
    } }).completion);
    assert.equal(f.counts.active, 0); assert.equal(f.counts.closed, 1);
    assert.ok(!f.calls.includes(`open:${paths[1]}`)); assert.ok(wiped(f.buffers));
  }
});

test("growth and truncation during descriptor reads never accept a valid prefix", async () => {
  for (const grow of [true, false]) {
    const f = fixture(), open = f.os.open;
    await rejects(f.start(f.options, { ...f.os, async open(path, flags) {
      const handle = await open(path, flags); let first = true;
      return { ...handle, async read(buffer, offset, length) {
        if (first) { first = false; f.files[0] = grow ? Buffer.concat([f.files[0], Buffer.from(" ")]) : f.files[0].subarray(0, 8); }
        return handle.read(buffer, offset, length);
      } };
    } }).completion);
    assert.equal(f.counts.active, 0); assert.ok(wiped(f.buffers));
    assert.ok(!f.calls.includes(`open:${paths[1]}`));
  }
});
