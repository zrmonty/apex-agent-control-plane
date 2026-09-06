import assert from "node:assert/strict";
import { test } from "node:test";
import { startGuardLoad, startLoad, type Gate } from "../stage-reader/job.js";
import { deferred, FakeFiles, FakeTime, fixtureHash } from "../stage-reader/fixture.js";
import type { GuardStageLoadOptions } from "./stage-reader.js";
import { startGuardStageLoad } from "./stage-reader.js";

const tick = () => new Promise<void>(resolve => setImmediate(resolve));
function setup() {
  const fs = new FakeFiles(), time = new FakeTime(), gate: Gate = {};
  fs.files = { "guard-config.json": Buffer.from("{}") };
  let fatals = 0;
  const options: GuardStageLoadOptions = { expectedManifestSha256: fixtureHash(fs.files), onFatal() { fatals++; } };
  return { fs, time, gate, options, fatals: () => fatals,
    start: (input = options) => startGuardLoad(input, fs, time, gate) };
}

test("guard stage reads exactly its separate one-file inventory", async () => {
  const fs = new FakeFiles(); fs.files = { "guard-config.json": Buffer.from("{}") };
  const load = startGuardLoad({ expectedManifestSha256: fixtureHash(fs.files), onFatal() {} },
    fs, new FakeTime(), {});
  const material = await load.result; await load.closed;
  assert.deepEqual(Object.keys(material.files), ["guard-config.json"]);
  assert.equal(material.files["guard-config.json"].toString(), "{}");
  assert.equal(fs.paths.size, 0); material.dispose();
  assert(material.files["guard-config.json"].every(byte => byte === 0));
});

for (const size of [1, 262144]) test(`guard opaque byte boundary ${size} accepted`, async () => {
  const s = setup(); s.fs.files["guard-config.json"] = Buffer.alloc(size, 65);
  const material = await s.start({ ...s.options, expectedManifestSha256: fixtureHash(s.fs.files) }).result;
  assert.equal(material.files["guard-config.json"].length, size); material.dispose();
});
for (const size of [0, 262145]) test(`guard byte boundary ${size} refused before file open`, async () => {
  const s = setup(); s.fs.files["guard-config.json"] = Buffer.alloc(size);
  const load = s.start(); await assert.rejects(load.result); await load.closed;
  assert(!s.fs.opened.includes("/apex/runtime/guard-config.json"));
});

for (const mutation of ["missing", "extra", "duplicate", "wrong-hash", "gateway-stage"])
  test(`guard inventory isolation: ${mutation}`, async () => {
    const s = setup();
    if (mutation === "missing") s.fs.files = {};
    if (mutation === "extra") s.fs.files["workload-key"] = Buffer.from("must not read");
    if (mutation === "duplicate") s.fs.directoryNames = ["guard-config.json", "guard-config.json"];
    if (mutation === "wrong-hash") s.fs.files["guard-config.json"] = Buffer.from("[]");
    if (mutation === "gateway-stage") s.fs.files = new FakeFiles().files;
    const load = s.start(); await assert.rejects(load.result); await load.closed;
    assert.equal(s.fs.paths.size, 0);
    assert(!s.fs.opened.includes("/apex/runtime/workload-key"));
  });

test("gateway entry cannot read guard-only inventory", async () => {
  const s = setup(); const load = startLoad({ ...s.options, toolSecretReferences: [] }, s.fs, s.time, s.gate);
  await assert.rejects(load.result); await load.closed; assert.equal(s.fs.paths.size, 0);
});

for (const [label, change] of Object.entries({
  "upper hash": { expectedManifestSha256: "A".repeat(64) }, "short hash": { expectedManifestSha256: "a" },
  "null fatal": { onFatal: null }, "invalid clock": { monotonicNowNs: 1 },
  "tool refs": { toolSecretReferences: [] }, "path": { path: "/other" },
  "names": { names: new Map([["workload-key", 65536]]) }, "symbol": { [Symbol("extra")]: 1 },
})) test(`guard options reject ${label} before I/O`, async () => {
  const s = setup(), load = s.start({ ...s.options, ...change } as GuardStageLoadOptions);
  await assert.rejects(load.result); await load.closed; assert.equal(s.fs.opened.length, 0);
});

test("guard option accessors, proxies and inherited inputs are passive refusals", async () => {
  const s = setup(); let calls = 0;
  for (const input of [
    Object.defineProperty({ ...s.options }, "expectedManifestSha256", { get() { calls++; return s.options.expectedManifestSha256; } }),
    new Proxy(s.options, { ownKeys() { calls++; return []; } }), Object.create(s.options),
  ]) {
    const load = s.start(input); await assert.rejects(load.result); await load.closed;
  }
  assert.equal(calls, 0); assert.equal(s.fs.opened.length, 0);
});

test("guard captures digest and callbacks before I/O without retaining mutable options meaning", async () => {
  const s = setup(), input = { ...s.options };
  const load = s.start(input); input.expectedManifestSha256 = "0".repeat(64);
  input.onFatal = () => { throw new Error("mutated"); };
  const material = await load.result; await load.closed;
  assert.equal(material.manifestSha256, s.options.expectedManifestSha256); material.dispose();
});

for (const [field, value] of Object.entries({ mode: 0o100600n, uid: 0n, gid: 0n, nlink: 2n }))
  test(`guard file rejects ${field}`, async () => {
    const s = setup(), path = "/apex/runtime/guard-config.json";
    s.fs.metadata.set(path, { ...s.fs.info(path), [field]: value });
    const load = s.start(); await assert.rejects(load.result); await load.closed;
    assert(!s.fs.opened.includes(path));
  });

test("guard rejects writable or nested mounts", async () => {
  for (const kind of ["rw", "nested"]) {
    const s = setup();
    s.fs.mountinfo = kind === "rw" ? s.fs.mountinfo.replace("/apex/runtime ro", "/apex/runtime rw") :
      s.fs.mountinfo + "43 42 0:22 /file /apex/runtime/guard-config.json ro - ext4 /dev/test rw\n";
    const load = s.start(); await assert.rejects(load.result); await load.closed;
  }
});

test("guard late open retains shared gateway capacity through real close and one fatal", async () => {
  const s = setup(), held = deferred<void>();
  s.fs.hook = (kind, path) => kind === "open" && path === "/" ? held.promise : undefined;
  const load = s.start(), rejection = assert.rejects(load.result);
  let closed = false; void load.closed.then(() => { closed = true; });
  await tick(); s.time.advance(5000); await rejection;
  const gateway = new FakeFiles();
  await assert.rejects(startLoad({ expectedManifestSha256: fixtureHash(gateway.files), toolSecretReferences: [], onFatal() {} },
    gateway, s.time, s.gate).result);
  assert.equal(gateway.opened.length, 0); assert.equal(closed, false);
  s.time.advance(5000); assert.equal(s.fatals(), 1); s.time.advance(5000); assert.equal(s.fatals(), 1);
  held.resolve(); await load.closed; assert.equal(s.fs.paths.size, 0); assert.equal(s.gate.held, undefined);
});

test("guard held read is not wiped or closed by cancel until actual I/O returns", async () => {
  const s = setup(), held = deferred<void>(), path = "/apex/runtime/guard-config.json"; let reads = 0;
  s.fs.hook = (kind, current) => kind === "read" && current === path && ++reads === 2 ? held.promise : undefined;
  const load = s.start(), rejection = assert.rejects(load.result); await tick();
  const bytes = s.fs.readBuffers.get(path)!; assert.equal(bytes.subarray(0, 2).toString(), "{}");
  load.cancel(); await rejection; assert.equal(s.fs.closed.length, 0);
  assert.equal(bytes.subarray(0, 2).toString(), "{}");
  held.resolve(); await load.closed; assert(bytes.every(byte => byte === 0));
});

test("guard failed close never manufactures closed or capacity", async () => {
  const s = setup(); s.fs.hook = (kind, path) => { if (kind === "close" && path === "/") throw new Error("detail"); };
  const load = s.start(); await assert.rejects(load.result, /^Error: managed stage load rejected$/);
  let closed = false; void load.closed.then(() => { closed = true; });
  s.time.advance(5000); await tick(); assert.equal(closed, false); assert.equal(s.fatals(), 1);
  await assert.rejects(s.start().result); assert(s.gate.held);
});

test("guard queued preflight time consumes original deadline", async () => {
  const s = setup(), load = s.start(), rejection = assert.rejects(load.result);
  s.time.time = 5000000000n; await rejection; await load.closed; assert.equal(s.fs.opened.length, 0);
});

test("guard reentrant clock cannot acquire gateway or guard slot", async () => {
  const s = setup(); let observed = false, pending: Promise<void>[] = [];
  const load = s.start({ ...s.options, monotonicNowNs() {
    if (!observed) { observed = true; pending.push(assert.rejects(s.start().result)); }
    return 0n;
  } });
  const material = await load.result; await load.closed; await Promise.all(pending);
  assert(observed); material.dispose();
});

test("public guard entry refuses platform/path/filesystem bypass options", async () => {
  const s = setup(), load = startGuardStageLoad({ ...s.options, fs: s.fs, path: "/tmp" } as GuardStageLoadOptions);
  await assert.rejects(load.result); await load.closed; assert.equal(s.fs.opened.length, 0);
});
