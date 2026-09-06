import test from "node:test";
import assert from "node:assert/strict";
import { materialFixture, now } from "./fixture.js";
import { assertRuntimeMaterialsStage, createManagedRuntimeMaterials, disposeRuntimeMaterials, type RuntimeMaterials } from "../runtime-materials.js";
import { disposeStageOwner, type StageOwner } from "../stage-owner.js";
test("equal metadata cannot replace the exact live source stage", async (t) => {
    const a = await materialFixture(), b = await materialFixture();
    const material = createManagedRuntimeMaterials(a.stageOwner, now);
    t.after(async () => {
        disposeRuntimeMaterials(material);
        disposeStageOwner(a.stageOwner);
        disposeStageOwner(b.stageOwner);
        await Promise.all([a.bootstrap.closed, b.bootstrap.closed]);
    });
    assert.deepEqual(a.stageOwner.documents.binding, b.stageOwner.documents.binding);
    assert.throws(() => assertRuntimeMaterialsStage(material, b.stageOwner));
});
test("forged material and stage objects are refused without reading traps", () => {
    let reads = 0;
    const hostile = new Proxy({}, { get() { reads++; throw Error("trap"); } });
    assert.throws(() => assertRuntimeMaterialsStage(hostile as RuntimeMaterials, hostile as StageOwner));
    assert.equal(reads, 0);
});
for (const disposed of ["stage", "materials"] as const)
    test(`exact source check refuses disposed ${disposed}`, async (t) => {
        const f = await materialFixture(), material = createManagedRuntimeMaterials(f.stageOwner, now);
        t.after(async () => { disposeRuntimeMaterials(material); disposeStageOwner(f.stageOwner); await f.bootstrap.closed; });
        assert.doesNotThrow(() => assertRuntimeMaterialsStage(material, f.stageOwner));
        if (disposed === "stage")
            disposeStageOwner(f.stageOwner);
        else
            disposeRuntimeMaterials(material);
        assert.throws(() => assertRuntimeMaterialsStage(material, f.stageOwner));
    });
