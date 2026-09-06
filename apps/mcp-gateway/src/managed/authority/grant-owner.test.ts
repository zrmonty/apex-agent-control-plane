import assert from "node:assert/strict";
import { test } from "node:test";
import { DeploymentGrantOwner } from "./grant-owner.js";
import type { DeploymentBinding, GrantReply, GrantRequest, GrantTransport } from "./types.js";

const binding: DeploymentBinding = Object.freeze({
  installationId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01",
  workspaceId: "work", namespaceId: "ns",
  proxyId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e02",
  revisionId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e03",
  processInstanceId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e04",
  generation: 9_007_199_254_740_993n, fencingToken: 9_007_199_254_740_995n,
  configHash: "a".repeat(64), launchContextHash: "b".repeat(64),
});
const decisionId = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e05";
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function fixture() {
  let now = 0n;
  let serial = 0;
  const exchanges: Array<{
    request: GrantRequest; result: ReturnType<typeof deferred<GrantReply>>;
    closed: ReturnType<typeof deferred<void>>; cancelled: boolean;
  }> = [];
  const timers: Array<{ callback(): void; cancelled: boolean }> = [];
  const transport: GrantTransport = { start(request) {
    const entry = { request, result: deferred<GrantReply>(), closed: deferred<void>(), cancelled: false };
    exchanges.push(entry);
    return { result: entry.result.promise, closed: entry.closed.promise, cancel() { entry.cancelled = true; } };
  } };
  const owner = new DeploymentGrantOwner({ binding, transport, monotonicNowNs: () => now,
    nonce: () => (++serial).toString(16).padStart(64, "0"),
    scheduler: { after(_ms, callback) {
      const timer = { callback, cancelled: false }; timers.push(timer);
      return () => { timer.cancelled = true; };
    } },
  });
  const reply = (index = 0, patch: Partial<GrantReply> = {}) => ({
    binding, nonce: exchanges[index].request.nonce, decisionId,
    renewalSequence: exchanges[index].request.renewalSequence,
    epoch: 9_007_199_254_740_999n, mode: "serve" as const, validForUs: 10_000_000n,
    ...patch,
  });
  return { owner, exchanges, timers, reply, time(ns: bigint) { now = ns; } };
}

test("each physical renewal has a monotonically increasing sequence and refuses an old echoed sequence", async () => {
  const f = fixture();
  const first = f.owner.renew();
  assert.equal(f.exchanges[0].request.renewalSequence, 1n);
  assert.equal(f.owner.renew(), first);
  f.exchanges[0].result.resolve(f.reply()); f.exchanges[0].closed.resolve();
  assert.equal(await first, true);
  const next = f.owner.renew();
  assert.equal(f.exchanges[1].request.renewalSequence, 2n);
  f.exchanges[1].result.resolve(f.reply(1, { renewalSequence: 1n,
    decisionId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e06" }));
  f.exchanges[1].closed.resolve();
  assert.equal(await next, false); assert.equal(f.owner.snapshot().admitting, false);
  await f.owner.close();
});

test("a grant expires at request start plus its duration, never receipt plus duration", async () => {
  const f = fixture();
  const renewal = f.owner.renew();
  assert.equal(f.exchanges.length, 1);
  f.time(9_000_000_000n);
  f.exchanges[0].result.resolve(f.reply());
  f.exchanges[0].closed.resolve();
  assert.equal(await renewal, true);
  assert.equal(f.owner.snapshot().admitting, true);
  assert.equal(f.owner.snapshot().epoch, 9_007_199_254_740_999n);
  f.time(10_000_000_000n);
  assert.equal(f.owner.snapshot().admitting, false);
  await f.owner.close();
});

test("PREPARE permits readiness but never business admission", async () => {
  const f = fixture();
  const pending = f.owner.renew();
  assert.equal(f.exchanges.length, 1);
  f.exchanges[0].result.resolve(f.reply(0, { mode: "prepare" }));
  f.exchanges[0].closed.resolve();
  assert.equal(await pending, true);
  assert.equal(f.owner.snapshot().mode, "prepare");
  assert.equal(f.owner.snapshot().admitting, false);
  await f.owner.close();
});

test("expired RPC reporting retains one physical slot until cleanup, ignoring a late reply", async () => {
  const f = fixture();
  const first = f.owner.renew();
  assert.equal(f.owner.renew(), first);
  f.time(10_000_000_000n);
  f.timers[0].callback();
  assert.equal(await first, false);
  assert.equal(f.exchanges[0].cancelled, true);
  assert.equal(f.owner.renew(), first);
  assert.equal(f.exchanges.length, 1);
  f.exchanges[0].result.resolve(f.reply());
  await Promise.resolve();
  assert.equal(f.owner.snapshot().admitting, false);
  f.exchanges[0].closed.resolve();
  await Promise.resolve();
  const next = f.owner.renew();
  assert.equal(f.exchanges.length, 2);
  assert.notEqual(f.exchanges[1].request.nonce, f.exchanges[0].request.nonce);
  const closing = f.owner.close();
  f.exchanges[1].closed.resolve();
  assert.equal(await next, false);
  await closing;
});

test("late replies at the grant's exact microsecond boundary refuse", async () => {
  const f = fixture();
  const pending = f.owner.renew();
  f.time(1_000n);
  f.exchanges[0].result.resolve(f.reply(0, { validForUs: 1n }));
  f.exchanges[0].closed.resolve();
  assert.equal(await pending, false);
  assert.equal(f.owner.snapshot().mode, "closed");
  await f.owner.close();
});

test("wrong binding, nonce, mode, epoch, UUID and unsafe durations all fail closed", async () => {
  const malformed = [
    { binding: { ...binding, processInstanceId: decisionId } },
    { binding: { ...binding, generation: binding.generation + 1n } },
    { binding: { ...binding, namespaceId: "foreign" } },
    { nonce: "c".repeat(64) }, { mode: "unknown" }, { epoch: 0n },
    { epoch: Number.MAX_SAFE_INTEGER + 2 }, { decisionId: "not-a-uuid" },
    { validForUs: 10_000_001n }, { validForUs: 0n }, { validForUs: -1n },
    { validForUs: 1000 },
  ];
  for (const patch of malformed) {
    const f = fixture();
    const pending = f.owner.renew();
    f.exchanges[0].result.resolve(f.reply(0, patch as Partial<GrantReply>));
    f.exchanges[0].closed.resolve();
    assert.equal(await pending, false);
    assert.equal(f.owner.tryBeginCall(), undefined);
    await f.owner.close();
  }
});

async function serving(f: ReturnType<typeof fixture>) {
  const pending = f.owner.renew();
  f.exchanges[0].result.resolve(f.reply());
  f.exchanges[0].closed.resolve();
  assert.equal(await pending, true);
}

test("expiry and close end start authority but do not release physical call ownership", async () => {
  const f = fixture();
  await serving(f);
  const call = f.owner.tryBeginCall();
  assert.ok(call);
  assert.equal(call.isCurrent(), true);
  f.time(10_000_000_000n);
  assert.equal(call.isCurrent(), false);
  assert.equal(f.owner.tryBeginCall(), undefined);
  assert.equal(f.owner.snapshot().activeCalls, 1);
  let closed = false;
  const closing = f.owner.close().then(() => { closed = true; });
  await Promise.resolve();
  assert.equal(closed, false);
  call.release(); call.release();
  await closing;
  assert.equal(f.owner.snapshot().activeCalls, 0);
});

test("applied acknowledgement reports expired grant closure and still-active physical calls", async () => {
  const f = fixture();
  await serving(f);
  const call = f.owner.tryBeginCall()!;
  f.time(10_000_000_000n);
  const renewal = f.owner.renew();
  assert.deepEqual(f.exchanges[1].request.applied, {
    decisionId, epoch: 9_007_199_254_740_999n, admitting: false, activeCalls: 1,
  });
  const closing = f.owner.close();
  f.exchanges[1].closed.resolve();
  call.release();
  assert.equal(await renewal, false);
  await closing;
});

test("older epochs, reused decisions and same-epoch mode changes cannot renew authority", async () => {
  for (const patch of [
    { epoch: 9_007_199_254_740_998n, decisionId: binding.revisionId },
    { decisionId },
    { mode: "prepare" as const, decisionId: binding.revisionId },
  ]) {
    const f = fixture();
    await serving(f);
    const pending = f.owner.renew();
    f.exchanges[1].result.resolve(f.reply(1, patch));
    f.exchanges[1].closed.resolve();
    assert.equal(await pending, false);
    assert.equal(f.owner.snapshot().admitting, false);
    await f.owner.close();
  }
});

test("a fresh same-epoch renewal preserves physical call authority without recounting", async () => {
  const f = fixture();
  await serving(f);
  const call = f.owner.tryBeginCall()!;
  f.time(9_000_000_000n);
  const renewal = f.owner.renew();
  f.exchanges[1].result.resolve(f.reply(1, { decisionId: binding.revisionId }));
  f.exchanges[1].closed.resolve();
  assert.equal(await renewal, true);
  f.time(10_000_000_000n);
  assert.equal(call.isCurrent(), true);
  assert.equal(f.owner.snapshot().activeCalls, 1);
  call.release();
  await f.owner.close();
});

test("a backwards monotonic clock poisons admission and cannot later recover by wall time", async () => {
  const f = fixture();
  f.time(5n); await serving(f);
  f.time(4n);
  assert.equal(f.owner.snapshot().admitting, false);
  f.time(1_000_000n);
  assert.equal(await f.owner.renew(), false);
  assert.equal(f.exchanges.length, 1);
  await f.owner.close();
});

test("the local physical cap is bounded and released exactly once", async () => {
  const f = fixture();
  await serving(f);
  const calls = Array.from({ length: 128 }, () => f.owner.tryBeginCall());
  assert.ok(calls.every(Boolean));
  assert.equal(f.owner.tryBeginCall(), undefined);
  calls[0]!.release(); calls[0]!.release();
  const replacement = f.owner.tryBeginCall();
  assert.ok(replacement);
  assert.equal(f.owner.snapshot().activeCalls, 128);
  calls.forEach(call => call!.release()); replacement.release();
  await f.owner.close();
});

test("close waits for physical RPC cleanup and a delayed reply cannot reopen it", async () => {
  const f = fixture();
  const renewal = f.owner.renew();
  let ended = false;
  const closing = f.owner.close().then(() => { ended = true; });
  assert.equal(await renewal, false);
  assert.equal(ended, false);
  assert.equal(f.exchanges[0].cancelled, true);
  f.exchanges[0].result.resolve(f.reply());
  f.exchanges[0].closed.resolve();
  await closing;
  assert.equal(f.owner.snapshot().admitting, false);
  assert.equal(await f.owner.renew(), false);
  assert.equal(f.exchanges.length, 1);
});
