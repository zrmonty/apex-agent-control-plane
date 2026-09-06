import test from "node:test";
import assert from "node:assert/strict";
import { setup, turn } from "./fixture.js";
import { startPair } from "./job.js";
import type { Handle } from "./types.js";
for (const boundary of ["connection", "authority", "evidence"] as const)
    test(`cancel reentry adopts late ${boundary} owner`, { timeout: 5000 }, async (t) => {
        const f = await setup();
        let h: Handle;
        const deps = { ...f.deps };
        if (boundary === "connection")
            deps.connect = options => {
                const c = f.deps.connect(options);
                f.connections.at(-1)!.hold = true;
                h.cancel();
                return c;
            };
        else if (boundary === "authority")
            deps.authority = (...args) => {
                const c = f.deps.authority(...args);
                f.channels.at(-1)!.hold = true;
                h.cancel();
                return c;
            };
        else
            deps.evidence = (...args) => {
                const c = f.deps.evidence(...args);
                f.channels.at(-1)!.hold = true;
                h.cancel();
                return c;
            };
        h = startPair(f.options, deps, f.gate);
        t.after(async () => { h.cancel(); for (const c of f.connections)
            c.receipt.resolve(); for (const c of f.channels)
            c.receipt.resolve(); await h.closed; await f.dispose(); });
        await turn();
        for (const c of f.connections)
            c.ready();
        await assert.rejects(h.result);
        await turn();
        let closed = false;
        void h.closed.then(() => { closed = true; });
        await turn();
        assert.equal(closed, false);
        assert.ok(f.gate.held);
        const rejected = startPair(f.options, f.deps, f.gate);
        await assert.rejects(rejected.result);
        await rejected.closed;
        f.time.advance(5000);
        assert.equal(f.fatals(), 1);
        for (const c of f.connections)
            c.receipt.resolve();
        for (const c of f.channels)
            c.receipt.resolve();
        await h.closed;
        assert.equal(f.gate.held, undefined);
        for (const c of f.connections)
            assert.equal(c.cancels, 1);
        for (const c of f.channels)
            assert.equal(c.closes, 1);
    });
test("a rejected physical receipt remains owned after once-only fatal", { timeout: 5000 }, async (t) => {
    const f = await setup(), h = startPair(f.options, f.deps, f.gate);
    t.after(() => f.dispose());
    await turn();
    for (const c of f.connections)
        c.ready();
    await h.result;
    f.channels[0].hold = true;
    h.cancel();
    f.channels[0].receipt.reject(Error("receipt canary"));
    await turn();
    let closed = false;
    void h.closed.then(() => { closed = true; });
    f.time.advance(5000);
    await turn();
    assert.equal(f.fatals(), 1);
    assert.equal(closed, false);
    assert.ok(f.gate.held);
    h.cancel();
    f.time.advance(5000);
    assert.equal(f.fatals(), 1);
    // Controlled rejected promise models permanent uncertainty; no actual native owner is leaked.
});
test("fatal callback reentry cannot replace a pair with held native ownership", { timeout: 5000 }, async (t) => {
    const f = await setup();
    let count = 0, replacement: Handle | undefined;
    const h = startPair({ ...f.options, onFatal() { count++; replacement = startPair(f.options, f.deps, f.gate); h.cancel(); throw Error("fatal canary"); } }, f.deps, f.gate);
    t.after(async () => { h.cancel(); for (const c of f.channels)
        c.receipt.resolve(); await h.closed; await f.dispose(); });
    await turn();
    for (const c of f.connections)
        c.ready();
    await h.result;
    f.channels[0].hold = true;
    h.cancel();
    f.time.advance(5000);
    await turn();
    assert.equal(count, 1);
    await assert.rejects(replacement!.result);
    await replacement!.closed;
    f.time.advance(5000);
    assert.equal(count, 1);
    assert.ok(f.gate.held);
    f.channels[0].receipt.resolve();
    await h.closed;
});
for (const boundary of ["second connection", "evidence channel"] as const)
    test(`${boundary} constructor failure drains adopted resources`, { timeout: 5000 }, async (t) => {
        const f = await setup();
        let attempts = 0;
        const deps = { ...f.deps };
        if (boundary === "second connection")
            deps.connect = options => { if (++attempts === 2)
                throw Error("constructor canary"); return f.deps.connect(options); };
        else
            deps.evidence = () => { throw Error("constructor canary"); };
        const h = startPair(f.options, deps, f.gate);
        t.after(async () => { h.cancel(); await h.closed; await f.dispose(); });
        await turn();
        for (const c of f.connections)
            c.ready();
        await assert.rejects(h.result, /managed control transports refused safely/);
        await h.closed;
        for (const c of f.connections)
            assert.equal(c.cancels, 1);
        for (const c of f.channels)
            assert.equal(c.closes, 1);
        assert.equal(f.gate.held, undefined);
    });
test("immediate cancellation does no connection work and preserves caller material", { timeout: 5000 }, async (t) => {
    const f = await setup(), h = startPair(f.options, f.deps, f.gate);
    t.after(() => f.dispose());
    h.cancel();
    await assert.rejects(h.result);
    await h.closed;
    assert.equal(f.connections.length, 0);
    assert.equal(f.f.counts.disposals, 0);
    assert.equal(f.gate.held, undefined);
});
