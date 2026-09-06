import test from "node:test";
import assert from "node:assert/strict";
import { materialFixture, now } from "../bootstrap/runtime-materials/fixture.js";
import { createManagedRuntimeMaterials, disposeRuntimeMaterials } from "../bootstrap/runtime-materials.js";
import { disposeStageOwner } from "../bootstrap/stage-owner.js";
import { capture } from "./capture.js";
import { copyStageRole } from "../bootstrap/stage-owner.js";
test("v1 stage cannot configure live guarded control transports", async (t) => {
    const f = await materialFixture(), materials = createManagedRuntimeMaterials(f.stageOwner, now);
    t.after(async () => { disposeRuntimeMaterials(materials); disposeStageOwner(f.stageOwner); await f.bootstrap.closed; });
    assert.throws(() => capture(f.stageOwner, materials));
});
test("v2 captures exact separated roles without consuming the caller stage", async (t) => {
    const f = await materialFixture(f => Object.assign(f.env, { APEX_MCP_MANAGED_BOOTSTRAP: "sealed-stage-v2",
        APEX_MCP_NETWORK_PROFILE: "isolated-bridge-v1", APEX_MCP_GUARD_ADDRESS: "10.96.0.3", APEX_MCP_NETWORK_BINDING_SHA256: "b".repeat(64) }));
    const materials = createManagedRuntimeMaterials(f.stageOwner, now);
    t.after(async () => { disposeRuntimeMaterials(materials); disposeStageOwner(f.stageOwner); await f.bootstrap.closed; });
    const value = capture(f.stageOwner, materials);
    assert.deepEqual(value.guard, { address: "10.96.0.3", port: 18080 });
    assert.equal(value.governanceToken.toString(), "synthetic-dedicated-governance-token");
    assert.equal(value.evidenceToken.toString(), "synthetic-dedicated-evidence-token");
    assert.deepEqual(value.proof, copyStageRole(f.stageOwner, "instance-proof"));
    assert.notDeepEqual(value.destinations[0].cert, value.destinations[1].cert);
    for (const [index, purpose] of ["governance", "evidence"].entries()) {
        const profile = f.stageOwner.documents.authority.profile[purpose as "governance" | "evidence"];
        assert.equal(value.destinations[index].host, profile.tls_server_name);
        assert.equal(value.destinations[index].port, Number(new URL(profile.endpoint).port) || 443);
        assert.equal(value.destinations[index].alpn, "h2");
    }
    value.dispose();
    value.dispose();
    for (const bytes of [value.proof, value.governanceToken, value.evidenceToken, ...value.destinations.flatMap(d => [d.ca, d.cert, d.key])])
        assert.ok(bytes.every(byte => byte === 0));
    assert.equal(f.counts.disposals, 0);
    assert.ok(copyStageRole(f.stageOwner, "governance-key").some(byte => byte !== 0));
});
