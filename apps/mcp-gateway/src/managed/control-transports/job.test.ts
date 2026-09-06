import test from "node:test";
import assert from "node:assert/strict";
import { setup, turn } from "./fixture.js";
import { startPair } from "./job.js";
test("one original start composes two concrete-purpose channels", async (t) => {
    const f = await setup();
    t.after(() => f.dispose());
    const h = startPair(f.options, f.deps, f.gate);
    await turn();
    assert.equal(f.connections.length, 2);
    for (const c of f.connections)
        c.ready();
    await h.result;
    assert.equal(f.channels.length, 2);
    assert.equal(f.connections[0].options.startedAtMonotonicNs, f.connections[1].options.startedAtMonotonicNs);
    assert.equal(f.credentials[0].token, "synthetic-dedicated-governance-token");
    assert.equal(f.credentials[0].instanceProof.length, 32);
    assert.deepEqual(f.tokens, ["synthetic-dedicated-evidence-token"]);
    h.cancel();
    await h.closed;
    assert.equal(f.gate.held, undefined);
    assert.equal(f.f.counts.disposals, 0);
});
