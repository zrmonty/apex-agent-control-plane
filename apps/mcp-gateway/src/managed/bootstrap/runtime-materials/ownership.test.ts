import test from "node:test";
import assert from "node:assert/strict";
import { materialFixture, now } from "./fixture.js";
import { createManagedRuntimeMaterials, disposeRuntimeMaterials, type RuntimeMaterials } from "../runtime-materials.js";
import { copyStageRole, disposeStageOwner } from "../stage-owner.js";

for (const failure of [false, true]) test(`explicit constructor allocations wipe on ${failure ? "late upstream failure" : "owner disposal"}`, async t => {
  const f = await materialFixture(f => {
    if (failure) f.stage.files[f.tools.entries[0].filename] = Buffer.from("invalid-upstream-after-TLS-preflight");
  });
  t.after(async () => { disposeStageOwner(f.stageOwner); await f.bootstrap.closed; });
  const before = copyStageRole(f.stageOwner, "governance-key"), captured: Buffer[] = [];
  const original = Buffer.alloc;
  let owner: RuntimeMaterials | undefined;
  try {
    // Narrow process-local instrumentation of explicit Buffer.alloc paths only.
    // Not JS/native key/string/whole-process zeroization evidence.
    Buffer.alloc = ((...args: Parameters<typeof Buffer.alloc>) => {
      const value = original(...args); captured.push(value); return value;
    }) as typeof Buffer.alloc;
    if (failure) assert.throws(() => createManagedRuntimeMaterials(f.stageOwner, now), /managed runtime materials refused safely/);
    else {
      owner = createManagedRuntimeMaterials(f.stageOwner, now);
      assert.ok(captured.some(bytes => bytes.includes("PRIVATE KEY")));
      disposeRuntimeMaterials(owner);
    }
  } finally { Buffer.alloc = original; if (owner) disposeRuntimeMaterials(owner); }
  try {
    assert.ok(captured.length >= 20);
    assert.equal(captured.filter(bytes => bytes.some(value => value !== 0)).length, 0);
    assert.deepEqual(copyStageRole(f.stageOwner, "governance-key"), before); assert.equal(f.counts.disposals, 0);
  } finally { before.fill(0); disposeStageOwner(f.stageOwner); await f.bootstrap.closed; }
});
