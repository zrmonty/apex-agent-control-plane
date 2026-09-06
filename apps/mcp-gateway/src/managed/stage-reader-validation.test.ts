import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { startLoad } from "./stage-reader/job.js";
import { startManagedStageLoad } from "./stage-reader.js";
import { FakeFiles, FakeTime, fixtureHash } from "./stage-reader/fixture.js";
import type { ManagedStageLoadOptions, Metadata } from "./stage-reader/types.js";

async function denied(fs: FakeFiles, refs: string[] = [], hash = fixtureHash(fs.files)) {
  const load = startLoad({ expectedManifestSha256: hash, toolSecretReferences: refs, onFatal() {} }, fs, new FakeTime(), {});
  await assert.rejects(load.result, /^Error: managed stage load rejected$/); await load.closed;
  assert.equal(fs.paths.size, 0);
}
for (const name of ["runtime-revision.json", "launch-context.json", "authority-profile.json", "tool-bindings.json",
  "instance-proof", "health-token", "workload-key"]) test(`missing ${name} rejects complete stage`, async () => {
  const fs = new FakeFiles(); delete fs.files[name]; await denied(fs);
});
for (const name of ["extra", "manifest.json", "HEALTH-TOKEN", "../health-token", "é", "x".repeat(256)]) {
  test(`unexpected entry ${name.slice(0, 24)} refuses`, async () => {
    const fs = new FakeFiles(); fs.directoryNames = [...Object.keys(fs.files), name]; await denied(fs);
  });
}
test("duplicate directory entry is not silently deduplicated", async () => {
  const fs = new FakeFiles(); fs.directoryNames = [...Object.keys(fs.files), "health-token"]; await denied(fs);
});
test("same bytes under a changed filename or changed bytes cannot match the expected manifest", async () => {
  const fs = new FakeFiles(), hash = fixtureHash(fs.files); fs.files["workload-key"] = Buffer.from("changed");
  await denied(fs, [], hash);
});
const badFile: Partial<Metadata>[] = [
  { mode: 0o120400n }, { mode: 0o10400n }, { mode: 0o40400n }, { mode: 0o100440n },
  { mode: 0o104400n }, { uid: 0n }, { gid: 0n }, { nlink: 2n }, { size: 0n }, { size: 65537n },
];
badFile.forEach((change, i) => test(`regular file metadata invariant ${i} refuses before reading`, async () => {
  const fs = new FakeFiles(), path = "/apex/runtime/governance-key";
  fs.metadata.set(path, { ...fs.info(path), ...change }); await denied(fs);
}));
for (const path of ["/", "/apex", "/apex/runtime"]) {
  for (const field of ["uid", "gid", "mode"] as const) test(`${path} invalid ${field} refuses`, async () => {
    const fs = new FakeFiles(); fs.metadata.set(path, { ...fs.info(path), [field]: field === "mode" ? 0o40777n : 2n });
    await denied(fs);
  });
}
for (const field of ["dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtimeNs", "ctimeNs"] as const) {
  test(`changed ${field} after read refuses and closes`, async () => {
    const fs = new FakeFiles(), path = "/apex/runtime/authority-profile.json";
    fs.hook = (kind, current) => { if (kind === "read" && current === path) {
      const before = fs.info(path); fs.metadata.set(path, { ...before, [field]: before[field] + 1n });
    } };
    await denied(fs);
  });
}
test("ancestor replacement after opening stage is detected through held parent identity", async () => {
  const fs = new FakeFiles();
  fs.hook = kind => { if (kind === "dirread") fs.metadata.set("/apex", { ...fs.info("/apex"), ino: 900n }); };
  await denied(fs);
});
const mounts = [
  "42 21 0:21 /stage /apex/runtime rw - ext4 test rw\n",
  "42 21 0:21 /stage /apex/runtime-other ro - ext4 test rw\n",
  "99 21 0:21 /stage /apex/runtime ro - ext4 test rw\n",
  "42 21 0:21 /stage /apex/runtime ro - ext4 test rw\n43 42 0:22 / /apex/runtime/health-token ro - tmpfs test rw\n",
  "42 21 0:21 /stage /apex/runtime ro - ext4 test rw\n43 42 0:22 / /apex/runtime/nested ro - tmpfs test rw\n",
  "42 21 0:21 /stage /apex/runtime ro - ext4 test rw\n43 21 0:22 / /apex/runtime ro - tmpfs test rw\n",
  "42 21 0:21 /stage /apex/runtime ro - ext4 test rw", "x".repeat(1048577),
];
mounts.forEach((mountinfo, i) => test(`actual mount observation invariant ${i} refuses`, async () => {
  const fs = new FakeFiles(); fs.mountinfo = mountinfo; await denied(fs);
}));
test("file FD must belong to exactly the held read-only stage mount", async () => {
  const fs = new FakeFiles(); fs.fileMount = "43"; await denied(fs);
});
for (const fdinfo of ["", "mnt_id:\t0\n", "mnt_id:\t42\nmnt_id:\t42\n", "mnt_id:\t42x\n", "x".repeat(4097)]) {
  test(`missing malformed or oversized fdinfo length${fdinfo.length} refuses`, async () => {
    const fs = new FakeFiles(); fs.fdinfo = fdinfo; await denied(fs);
  });
}
test("Linux flags must actually exist, with no zero fallback", async () => {
  for (const key of ["directory", "noFollow", "nonblock"] as const) {
    const fs = new FakeFiles(); fs.flags[key] = 0; await denied(fs); assert.equal(fs.opened.length, 0);
  }
});
test("mount changed to writable during reads is rejected by the final observation", async () => {
  const fs = new FakeFiles(); fs.hook = (kind, path) => {
    if (kind === "read" && path.startsWith("/apex/runtime/")) fs.mountinfo = fs.mountinfo.replace("runtime ro", "runtime rw");
  }; await denied(fs);
});
test("short reads are assembled but premature EOF fails stat size equality", async () => {
  const fs = new FakeFiles(); fs.chunkSize = 1;
  const load = startLoad({ expectedManifestSha256: fixtureHash(fs.files), toolSecretReferences: [], onFatal() {} }, fs, new FakeTime(), {});
  (await load.result).dispose(); await load.closed;
  fs.eofAt = 1; await denied(fs);
});
for (const [name, cap] of [["runtime-revision.json", 262144], ["authority-profile.json", 262144],
  ["tool-bindings.json", 262144], ["launch-context.json", 16384], ["governance-key", 65536]] as const) {
  test(`${name} byte cap enforced before file open`, async () => {
    const fs = new FakeFiles(); fs.files[name] = Buffer.alloc(cap + 1, 65);
    await denied(fs); assert(!fs.opened.includes(`/apex/runtime/${name}`));
  });
}
for (const bytes of [Buffer.alloc(31), Buffer.alloc(33)]) test(`proof must be exactly32, not ${bytes.length}`, async () => {
  const fs = new FakeFiles(); fs.files["instance-proof"] = bytes; await denied(fs);
});
for (const token of ["A".repeat(42), "A".repeat(44), "A".repeat(42) + "B", "A".repeat(42) + "=", "!".repeat(43)]) {
  test(`health canonical encoding length${token.length} tail${token.at(-1)} rejects`, async () => {
    const fs = new FakeFiles(); fs.files["health-token"] = Buffer.from(token); await denied(fs);
  });
}
test("maximum fifty-file complete stage permits exact byte caps and hashes every tool", async () => {
  const fs = new FakeFiles(), refs = Array.from({ length: 32 }, (_, i) => `secret://tools/tool-${i}`);
  for (const ref of refs) fs.files[`tool-${createHash("sha256").update(ref).digest("hex")}`] = Buffer.alloc(65536, 7);
  for (const name of ["runtime-revision.json", "authority-profile.json", "tool-bindings.json"]) fs.files[name] = Buffer.alloc(262144, 65);
  fs.files["launch-context.json"] = Buffer.alloc(16384, 65);
  const load = startLoad({ expectedManifestSha256: fixtureHash(fs.files), toolSecretReferences: refs, onFatal() {} }, fs, new FakeTime(), {});
  const stage = await load.result; assert.equal(Object.keys(stage.files).length, 50); stage.dispose(); await load.closed;
  fs.directoryNames = [...Object.keys(fs.files), "extra"]; await denied(fs, refs);
});
test("a required tool file is not optional", async () => { await denied(new FakeFiles(), ["secret://tools/tool-1"]); });
for (const refs of [["secret://a", "secret://a"], ["secret://a/.."], ["secret://a//b"], ["secret://a/é"],
  ["secret://.a"], ["secret://a/../b"], Array(33).fill("secret://a"), ["secret://" + "a".repeat(256)]]) {
  test(`invalid reference set ${JSON.stringify(refs).slice(0, 55)} rejects without I/O`, async () => {
    const fs = new FakeFiles(); await denied(fs, refs); assert.equal(fs.opened.length, 0);
  });
}
test("accessor and proxy inputs cannot run untrusted callbacks", async () => {
  let entered = false;
  const fs = new FakeFiles(), base = { expectedManifestSha256: fixtureHash(fs.files), toolSecretReferences: [], onFatal() {} };
  for (const options of [new Proxy(base, { get() { entered = true; throw Error(); } }),
    { ...base, get toolSecretReferences() { entered = true; return []; } }]) {
    const load = startLoad(options, fs, new FakeTime(), {}); await assert.rejects(load.result); await load.closed;
  }
  assert.equal(entered, false); assert.equal(fs.opened.length, 0);
});
test("public Linux-only API has no platform/path/filesystem bypass", async () => {
  if (process.platform === "linux") return; // Actual Linux is covered separately, not represented by this check.
  const fs = new FakeFiles();
  const input = { expectedManifestSha256: fixtureHash(fs.files), toolSecretReferences: [], onFatal() {},
    path: "C:/elsewhere", platform: "linux", fs } as ManagedStageLoadOptions;
  const load = startManagedStageLoad(input); await assert.rejects(load.result); await load.closed;
  assert.equal(fs.opened.length, 0);
});
