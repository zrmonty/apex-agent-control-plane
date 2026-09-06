import test from "node:test";
import assert from "node:assert/strict";
import { setup, turn } from "./fixture.js";
import { startPair } from "./job.js";
import type { Options } from "./types.js";
import { disposeStageOwner } from "../bootstrap/stage-owner.js";
import { disposeRuntimeMaterials } from "../bootstrap/runtime-materials.js";

test("active option boundaries never invoke property traps", async t => {
    const f = await setup(); t.after(() => f.dispose());
    let traps = 0;
    const accessor = { ...f.options };
    Object.defineProperty(accessor, "stage", { get() { traps++; throw Error("canary"); } });
    const proxy = new Proxy(f.options, { ownKeys() { traps++; throw Error("canary"); } });
    for (const input of [accessor, proxy, { ...f.options, extra: true }, { ...f.options, onFatal: undefined }]) {
        const h = startPair(input as Options, f.deps, f.gate);
        await assert.rejects(h.result, /managed control transports refused safely/); await h.closed;
        assert.equal(f.gate.held, undefined);
    }
    assert.equal(traps, 0); assert.equal(f.connections.length, 0);
});
for (const clock of ["negative mono", "wrong mono", "NaN wall", "negative wall", "unsafe wall", "expired wall"])
    test(`invalid ${clock} refuses before connections`, async t => {
        const f = await setup(); t.after(() => f.dispose());
        const deps = { ...f.deps };
        if (clock === "negative mono") f.time.now = () => -1n;
        else if (clock === "wrong mono") f.time.now = () => 0 as unknown as bigint;
        else deps.unixMs = () => clock === "NaN wall" ? NaN : clock === "negative wall" ? -1 :
            clock === "unsafe wall" ? Number.MAX_SAFE_INTEGER + 1 : Number((f.materials.notAfterUnixUs + 999n) / 1000n);
        const h = startPair(f.options, deps, f.gate);
        await assert.rejects(h.result); await h.closed;
        assert.equal(f.connections.length, 0); assert.equal(f.gate.held, undefined); assert.equal(f.fatals(), 0);
    });
test("independent credential copies precede the first trusted clock callback", { timeout: 5000 }, async t => {
    const f = await setup(); let first = true;
    f.time.now = () => {
        if (first) { first = false; disposeRuntimeMaterials(f.materials); disposeStageOwner(f.options.stage); }
        return f.time.time;
    };
    const h = startPair(f.options, f.deps, f.gate);
    t.after(async () => { h.cancel(); await h.closed; await f.dispose(); });
    await turn(); for (const c of f.connections) c.ready(); await h.result;
    assert.equal(f.credentials[0].token, "synthetic-dedicated-governance-token");
    assert.ok(f.credentials[0].instanceProof.some(byte => byte !== 0));
    h.cancel(); await h.closed;
});
