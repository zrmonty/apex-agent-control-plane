import test from "node:test";
import assert from "node:assert/strict";
import { CompiledCallPreparer } from "./call-preparation.js";
import { harness, envelope, turns } from "./compiled-executor/testing.js";

function rawStart(h: ReturnType<typeof harness>) {
  const prepared = new CompiledCallPreparer(h.preparation).prepare(h.identity, "portfolio.read",
    { portfolioId: "p-1" }, h.original, h.deadline);
  return h.raw.start(prepared);
}
async function upstreamEnded(h: ReturnType<typeof harness>) {
  h.authorize(); await turns(); h.upstream.resolve(envelope()); h.rawClosed.resolve(); await turns();
  assert.equal(h.active, 0);
  assert.equal(h.raw.pending()[0].state, "completing");
}

for (const cancellation of ["call", "coordinator"] as const) {
  test(`${cancellation} cancellation after upstream closure preserves the actual bounded completion receipt`, async t => {
    const h = harness(); t.after(() => h.cleanup()); h.holdCompletionReply();
    const call = rawStart(h); await upstreamEnded(h); await call.result;
    if (cancellation === "call") call.cancel(); else void h.raw.close();
    let closed = false; void call.closed.then(() => { closed = true; });
    h.replyCompletion(); await turns();
    assert.equal(closed, false, "a decoded receipt is not physical RPC closure");
    h.completionClosed.resolve(); await call.closed;
    assert.deepEqual(h.raw.pending(), []);
    assert.deepEqual(await h.raw.close(), []);
    assert.equal(call.observation().cleanup!.state, "ok");
  });
}

test("compiled output/evidence success and immediate shutdown do not cancel reservation completion", async t => {
  const h = harness(); t.after(() => h.cleanup()); h.holdCompletionReply();
  const job = h.start(); await upstreamEnded(h);
  let delivered = false; void job.result.then(() => { delivered = true; }); await turns();
  assert.equal(delivered, false); assert.equal(h.events.length, 1);
  h.evidenceReply.resolve(Buffer.alloc(0)); h.evidenceClosed.resolve();
  const output = await job.result;
  assert.equal(output.structuredContent.portfolioId, "p-1");
  // Executor finally cancels raw ownership even on success. HTTP response close
  // and immediate root shutdown repeat cancellation while the receipt is pending.
  job.cancel(); const executorClosed = h.executor.close(), handoff = h.raw.close();
  let closed = false; void job.closed.then(() => { closed = true; });
  await turns(); assert.equal(closed, false);
  h.replyCompletion(); await turns(); assert.equal(closed, false);
  h.completionClosed.resolve(); await job.closed; await executorClosed;
  assert.deepEqual(await handoff, []);
  assert.equal(job.completion()!.raw!.cleanup!.state, "ok");
  assert.equal(h.effects.filter(effect => effect === "complete").length, 1);
});

test("cancellation before upstream closure stops business but retains its physical slot before completing", async t => {
  const h = harness(); t.after(() => h.cleanup()); h.holdCompletionReply();
  const call = rawStart(h); h.authorize(); await turns();
  call.cancel(); await assert.rejects(call.result, /managed call refused safely/);
  assert.ok(h.effects.includes("cancel-upstream"));
  h.upstream.reject(Error("cancelled upstream")); await turns();
  assert.equal(h.active, 1); assert.equal(h.raw.pending().length, 0);
  assert.equal(h.effects.includes("complete"), false);
  let closed = false; const handoff = h.raw.close().then(value => { closed = true; return value; });
  await turns(); assert.equal(closed, false);
  h.rawClosed.resolve(); await turns();
  assert.equal(h.active, 0); assert.equal(closed, false);
  h.replyCompletion(); h.completionClosed.resolve(); await call.closed;
  assert.deepEqual(await handoff, []);
});

test("retained completion still times out at its original ten-second transport bound and owns physical cleanup", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const h = harness(); t.after(() => h.cleanup()); h.holdCompletionReply();
  const call = rawStart(h); await upstreamEnded(h); await call.result;
  const pending = { ...h.raw.pending()[0], state: "completion_pending" };
  let closed = false; const handoff = h.raw.close().then(value => { closed = true; return value; });
  h.advance(9_999_000_000n); t.mock.timers.tick(9999); await turns();
  assert.equal(h.effects.includes("cancel-completion"), false);
  h.advance(10_000_000_000n); t.mock.timers.tick(1); await turns();
  assert.equal(h.effects.filter(effect => effect === "cancel-completion").length, 1);
  assert.equal(closed, false);
  h.replyCompletion(); await turns(); assert.equal(closed, false);
  h.completionClosed.resolve(); await call.closed;
  assert.deepEqual(await handoff, [pending]);
});

for (const failure of ["transport revocation", "malformed receipt", "late receipt", "backwards clock"] as const) {
  test(`${failure} cannot erase the reservation after business cancellation`, async t => {
    const h = harness(); t.after(() => h.cleanup()); h.holdCompletionReply();
    const call = rawStart(h); await upstreamEnded(h); await call.result;
    const pending = { ...h.raw.pending()[0], state: "completion_pending" };
    call.cancel();
    if (failure === "transport revocation") h.completionReply.reject(Error("revoked authenticated channel"));
    if (failure === "malformed receipt") h.completionReply.resolve(Buffer.alloc(0));
    if (failure === "late receipt") { h.advance(10_000_000_000n); h.replyCompletion(); }
    if (failure === "backwards clock") { h.advance(-1n); h.replyCompletion(); }
    let closed = false; void call.closed.then(() => { closed = true; });
    await turns(); assert.equal(closed, false);
    h.completionClosed.resolve(); await call.closed;
    assert.deepEqual(await h.raw.close(), [pending]);
    assert.equal(h.effects.filter(effect => effect === "complete").length, 1);
  });
}

test("unknown authorization after cancellation never fabricates a reservation receipt", async t => {
  const h = harness(); t.after(() => h.cleanup());
  const call = rawStart(h); await turns(); call.cancel();
  await assert.rejects(call.result); h.authorize(); await call.closed;
  assert.deepEqual(await h.raw.close(), [{ callId: call.observation().callId, state: "unknown_reservation" }]);
  assert.equal(h.effects.includes("upstream"), false); assert.equal(h.effects.includes("complete"), false);
});
