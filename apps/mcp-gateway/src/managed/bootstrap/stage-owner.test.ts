import assert from "node:assert/strict";
import test from "node:test";
import { startOwnedStage } from "./stage-owner/job.js";
import { ownerFixture, tick } from "./stage-owner/fixture.js";
import { isStatic } from "./stage-owner/fixture.js";
import { copyStageRole, copyStageTool, disposeStageOwner, startSealedStageBootstrap, type StageOwner } from "./stage-owner.js";
import { ROLES } from "../stage-reader/validation.js";

async function ready() {
  const f = ownerFixture(), h = startOwnedStage(f, f.load, f.time, f.gate);
  f.result.resolve(f.material); f.closed.resolve();
  return { f, h, owner: await h.result };
}

test("real ENV and joined documents produce immutable owned metadata", async () => {
  const f = ownerFixture(), h = startOwnedStage(f, f.load, f.time, f.gate);
  f.result.resolve(f.material); f.closed.resolve();
  const owner = await h.result;
  assert.deepEqual(Object.keys(owner), ["documents"]);
  assert.equal(owner.documents.binding.installationId, f.selection.installationId);
  assert.equal(owner.documents.tools.entries[0].reference, f.tools.entries[0].reference);
  assert(Object.isFrozen(owner.documents.tools.entries[0]));
  let closed = false; void h.closed.then(() => { closed = true; });
  await tick(); assert.equal(closed, false);
  h.cancel(); await h.closed;
  assert.equal(f.counts.disposals, 1);
});

for (const role of [...ROLES, "instance-proof"]) {
  test(`fresh bounded ${role} copies are independent and revoked on disposal`, async () => {
    const { f, h, owner } = await ready(), original = f.stage.files[role];
    const first = copyStageRole(owner, role), second = copyStageRole(owner, role);
    assert.deepEqual(first, original); assert.notEqual(first, second);
    first[0] ^= 255; assert.notEqual(first[0], original[0]);
    original[0] ^= 127; assert.notEqual(second[0], original[0]);
    disposeStageOwner(owner); disposeStageOwner(owner); await h.closed;
    assert.equal(f.counts.disposals, 1);
    for (const bytes of Object.values(f.stage.files)) assert(bytes.every(b => b === 0));
    assert(second.some(b => b !== 0)); // Already handed-out copies belong to the consumer.
    assert.throws(() => copyStageRole(owner, role), isStatic);
    assert.equal(owner.documents.binding.installationId, f.selection.installationId);
    first.fill(0); second.fill(0);
  });
}
test("tool copies resolve only joined published references, not role names or filenames", async () => {
  const { f, h, owner } = await ready();
  for (const entry of owner.documents.tools.entries) {
    const first = copyStageTool(owner, entry.reference), second = copyStageTool(owner, entry.reference);
    assert.deepEqual(first, f.stage.files[entry.filename]); first.fill(0);
    assert(second.some(b => b !== 0)); assert(f.stage.files[entry.filename].some(b => b !== 0)); second.fill(0);
    assert.throws(() => copyStageTool(owner, entry.filename), isStatic);
    assert.throws(() => copyStageRole(owner, entry.reference), isStatic);
  }
  for (const key of ["", "../governance-key", "/apex/runtime/governance-key", "runtime-revision.json", "toString",
    "secret://unpublished/token", "health-token", "instance-proof"]) assert.throws(() => copyStageTool(owner, key), isStatic);
  for (const key of ["", "../governance-key", "runtime-revision.json", "__proto__", "Governance-key"])
    assert.throws(() => copyStageRole(owner, key), isStatic);
  h.cancel(); await h.closed;
  assert.throws(() => copyStageTool(owner, f.tools.entries[0].reference), isStatic);
});
test("forged owners, proxies, getters and coercible selectors invoke no hooks", async () => {
  const { h, owner } = await ready(); let hooks = 0;
  const bad = () => { hooks++; throw new Error("SECRET-CANARY"); };
  const revoked = Proxy.revocable(owner, {}); revoked.revoke();
  for (const fake of [undefined, null, 7, "owner", {}, { get documents() { return bad(); } },
    { ...owner }, new Proxy(owner, { get: bad, getOwnPropertyDescriptor: bad, ownKeys: bad }), revoked.proxy]) {
    assert.throws(() => copyStageRole(fake as StageOwner, "governance-key"), isStatic);
    assert.throws(() => copyStageTool(fake as StageOwner, owner.documents.tools.entries[0].reference), isStatic);
    assert.throws(() => disposeStageOwner(fake as StageOwner), isStatic);
  }
  for (const key of [null, 1, ["governance-key"], { toString: bad }, new Proxy({}, { get: bad })]) {
    assert.throws(() => copyStageRole(owner, key as string), isStatic);
    assert.throws(() => copyStageTool(owner, key as string), isStatic);
  }
  assert.equal(hooks, 0); h.cancel(); await h.closed;
});
test("copy helpers never use Buffer getters, iterators, conversion or copy methods", async () => {
  const f = ownerFixture(); let hooks = 0;
  const bytes = f.stage.files["governance-key"], saved = Buffer.from(bytes);
  const bad = () => { hooks++; throw new Error("SECRET-CANARY"); };
  for (const key of ["length", "byteLength", "buffer", "byteOffset", "copy", "slice", "subarray", "valueOf", "toString"])
    Object.defineProperty(bytes, key, { get: bad });
  Object.defineProperty(bytes, Symbol.iterator, { get: bad });
  const h = startOwnedStage(f, f.load, f.time, f.gate); f.result.resolve(f.material); f.closed.resolve();
  const owner = await h.result, copy = copyStageRole(owner, "governance-key");
  assert.deepEqual(copy, saved); assert.equal(hooks, 0);
  disposeStageOwner(owner); await h.closed; assert.equal(hooks, 0); copy.fill(0); saved.fill(0);
});
test("ENV selection is copied before return and real public entry rejects invalid ENV", async () => {
  const f = ownerFixture(), hash = f.env.APEX_STAGE_MANIFEST_SHA256;
  const h = startOwnedStage(f, f.load, f.time, f.gate);
  f.env.APEX_STAGE_MANIFEST_SHA256 = "b".repeat(64); f.env.APEX_TOOL_SECRET_REFERENCES = "[]";
  await tick(); assert.equal(f.options().expectedManifestSha256, hash);
  assert(Object.isFrozen(f.options().toolSecretReferences));
  f.result.resolve(f.material); f.closed.resolve(); const owner = await h.result;
  disposeStageOwner(owner); await h.closed;
  const refused = startSealedStageBootstrap({ env: {}, onFatal() { assert.fail("no I/O"); } });
  await assert.rejects(refused.result, isStatic); await refused.closed;
});

for (const [name, make] of [
  ["empty", () => Buffer.alloc(0)], ["oversized", () => Buffer.alloc(65537)],
  ["shared", () => new Uint8Array(new SharedArrayBuffer(8))],
  ["proxy", () => new Proxy(Buffer.alloc(8), { get() { assert.fail("source proxy trap"); } })],
] as const) {
  test(`invalid captured secret ${name} fails before publication and disposes`, async () => {
    const f = ownerFixture(), original = f.stage.files["governance-key"];
    f.stage.files["governance-key"] = make() as Buffer;
    const h = startOwnedStage(f, f.load, f.time, f.gate);
    f.result.resolve({ ...f.material, dispose() {
      // The deliberately non-reader value is not an allocation owned by the real
      // reader. Restore it before exercising the honest fixture wipe.
      f.stage.files["governance-key"] = original; f.material.dispose();
    } });
    f.closed.resolve(); await assert.rejects(h.result, isStatic); await h.closed;
    assert.equal(f.counts.disposals, 1);
  });
}
test("maximum role and tool buffers remain independently bounded copies", async () => {
  const f = ownerFixture(), entry = f.tools.entries[0];
  f.stage.files["governance-key"] = Buffer.alloc(65536, 7); f.stage.files[entry.filename] = Buffer.alloc(65536, 9);
  const h = startOwnedStage(f, f.load, f.time, f.gate); f.result.resolve(f.material); f.closed.resolve();
  const owner = await h.result, role = copyStageRole(owner, "governance-key"), tool = copyStageTool(owner, entry.reference);
  assert.equal(role.length, 65536); assert.equal(tool.length, 65536);
  h.cancel(); await h.closed; assert(role.every(b => b === 7)); assert(tool.every(b => b === 9)); role.fill(0); tool.fill(0);
});
