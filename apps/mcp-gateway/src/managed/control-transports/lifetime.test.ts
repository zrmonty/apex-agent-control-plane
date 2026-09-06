import test from "node:test";
import assert from "node:assert/strict";
import { setup, turn } from "./fixture.js";
import { startPair } from "./job.js";
import type { TestContext } from "node:test";
import type { Handle } from "./types.js";
function cleanup(t: TestContext, f: Awaited<ReturnType<typeof setup>>, h: Handle) {
    t.after(async () => { h.cancel(); for (const c of f.connections)
        c.receipt.resolve(); for (const c of f.channels)
        c.receipt.resolve(); await h.closed; await f.dispose(); });
}
test("published pair still revokes on native wall expiry", { timeout: 5000 }, async (t) => {
    const f = await setup();
    let wall = f.deps.unixMs();
    const h = startPair(f.options, { ...f.deps, unixMs: () => wall }, f.gate);
    t.after(async () => { h.cancel(); for (const c of f.connections)
        c.receipt.resolve(); for (const c of f.channels)
        c.receipt.resolve(); await h.closed; await f.dispose(); });
    await turn();
    for (const c of f.connections)
        c.ready();
    await h.result;
    let revoked = false;
    void h.revoked.then(() => { revoked = true; });
    wall = Number((f.materials.notAfterUnixUs + 999n) / 1000n);
    f.time.advance(1000);
    await turn();
    assert.equal(revoked, true);
});
test("logical revocation cannot release a held channel or connection", { timeout: 5000 }, async (t) => {
    const f = await setup(), h = startPair(f.options, f.deps, f.gate);
    cleanup(t, f, h);
    await turn();
    for (const c of f.connections)
        c.ready();
    await h.result;
    f.connections[1].hold = true;
    f.channels[0].hold = true;
    let closed = false;
    void h.closed.then(() => { closed = true; });
    h.cancel();
    await h.revoked;
    await turn();
    assert.equal(closed, false);
    assert.ok(f.gate.held);
    const rejected = startPair(f.options, f.deps, f.gate);
    await assert.rejects(rejected.result);
    await rejected.closed;
    f.connections[1].receipt.resolve();
    await turn();
    assert.equal(closed, false);
    f.time.advance(4999);
    assert.equal(f.fatals(), 0);
    f.time.advance(1);
    assert.equal(f.fatals(), 1);
    h.cancel();
    f.time.advance(5000);
    assert.equal(f.fatals(), 1);
    assert.ok(f.gate.held);
    f.channels[0].receipt.resolve();
    await h.closed;
    assert.equal(f.gate.held, undefined);
    for (const c of f.channels)
        assert.equal(c.closes, 1);
    for (const c of f.connections)
        assert.equal(c.cancels, 1);
});
test("second handshake failure closes a successfully constructed first channel", { timeout: 5000 }, async (t) => {
    const f = await setup(), h = startPair(f.options, f.deps, f.gate);
    cleanup(t, f, h);
    await turn();
    f.connections[0].ready();
    await turn();
    assert.equal(f.channels.length, 1);
    f.connections[1].response.reject(Error("peer canary"));
    await assert.rejects(h.result, /managed control transports refused safely/);
    await h.closed;
    assert.equal(f.channels[0].closes, 1);
    assert.equal(f.gate.held, undefined);
});
test("both pending handshakes expire against their original start", { timeout: 5000 }, async (t) => {
    const f = await setup(), h = startPair(f.options, f.deps, f.gate);
    cleanup(t, f, h);
    await turn();
    f.time.advance(9999);
    await turn();
    assert.ok(f.gate.held);
    assert.equal(f.connections[0].cancels, 0);
    f.time.advance(1);
    await assert.rejects(h.result);
    await h.closed;
    assert.equal(f.channels.length, 0);
});
for (const event of ["goaway", "error", "close", "frameError"])
    test(`${event} revokes both published control channels`, { timeout: 5000 }, async (t) => {
        const f = await setup(), h = startPair(f.options, f.deps, f.gate);
        cleanup(t, f, h);
        await turn();
        for (const c of f.connections)
            c.ready();
        await h.result;
        f.connections[0].session.emit(event, Error("peer canary"));
        await h.revoked;
        await h.closed;
        assert.equal(f.channels.length, 2);
        for (const c of f.channels)
            assert.equal(c.closes, 1);
    });
test("a cleanup-clock regression is fatal without releasing physical capacity", { timeout: 5000 }, async (t) => {
    const f = await setup();
    f.time.time = 100000000000n;
    const h = startPair(f.options, f.deps, f.gate);
    cleanup(t, f, h);
    await turn();
    for (const c of f.connections)
        c.ready();
    await h.result;
    f.channels[0].hold = true;
    f.time.time = 101000000000n;
    h.cancel();
    await turn();
    f.time.time = 0n;
    // Existing cleanup timer is due on its own controlled scheduler; force its callback
    // through elapsed advancement while now() reports a regressed sample.
    f.time.now = () => 0n;
    f.time.advance(106000);
    await turn();
    assert.equal(f.fatals(), 1);
    assert.ok(f.gate.held);
    f.channels[0].receipt.resolve();
    await h.closed;
});
