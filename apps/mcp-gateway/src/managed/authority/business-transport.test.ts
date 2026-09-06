import assert from "node:assert/strict";
import { test } from "node:test";
import { fromBinary, toBinary } from "@bufbuild/protobuf";
import { ManagedCallAuthorizationDecisionSchema, ManagedCallAuthorizationRequestSchema,
  ManagedCallCompletionSchema, ManagedPolicyRequestSchema } from "@apex/contracts";
import { AuthenticatedBusinessTransport } from "./business-transport.js";
import { admissionId, allowed, binding, callId, context, harness, metadata, nonce, paths, peerReply, request } from "./business-testing.js";

for (const kind of ["policy", "authorize", "complete"] as const) {
  test(`semantic ${kind} uses generated payloads and keeps exact unresolved physical closure`, async () => {
    const h = harness();
    const client = new AuthenticatedBusinessTransport({ ...metadata, channel: h.channel, monotonicNowNs: () => 1001n });
    const exchange = kind === "policy" ? client.startPolicy(nonce) : kind === "authorize"
      ? client.startAuthorization(request(), context) : client.startCompletion(admissionId, callId);
    assert.equal(h.sent.length, 1); assert.equal(h.sent[0].path, paths[kind]);
    const bytes = h.sent[0].bytes;
    if (kind === "policy") {
      const input = fromBinary(ManagedPolicyRequestSchema, bytes);
      assert.equal(Buffer.from(input.nonce).toString("hex"), nonce);
      assert.equal(input.binding?.target?.fencingToken, 9007199254740995n);
    } else if (kind === "authorize") assert.deepEqual(fromBinary(ManagedCallAuthorizationRequestSchema, bytes), request());
    else {
      const input = fromBinary(ManagedCallCompletionSchema, bytes);
      assert.equal(input.admissionId, admissionId); assert.equal(input.callId, callId);
      assert.equal(input.binding?.configHash, binding.configHash);
    }
    h.result.resolve(peerReply(h.sent[0].path, bytes));
    const value = await exchange.result;
    if ("outcome" in value) {
      assert.equal(value.outcome, "allowed"); assert.equal(value.policyRevision, 9007199254740993n);
      if (value.outcome === "allowed") {
        assert.equal(value.startDeadlineMonotonicNs, 8000n);
        assert.equal(value.validForUs, 7n); assert.deepEqual(value.submittedRequest, request());
        assert.ok(Object.isFrozen(value)); assert.ok(Object.isFrozen(value.submittedRequest.caller));
        assert.ok(Object.isFrozen(value.submittedRequest.binding?.target));
      }
    } else if ("revision" in value) assert.equal(value.revision, 9007199254740993n);
    else assert.equal(value.released, true);
    assert.equal(exchange.closed, h.closure.promise);
    let closed = false; void exchange.closed.then(() => { closed = true; });
    await Promise.resolve(); assert.equal(closed, false);
    exchange.cancel(); assert.equal(h.cancellations, 1);
    h.closure.resolve(); await exchange.closed;
  });
}

for (const us of [1n, 7n, 999n]) for (const offset of [-1n, 0n, 1n]) {
  test(`original start + ${us}us accepts only before deadline (offset ${offset}ns)`, async () => {
    let now = 1000n;
    const h = harness();
    const client = new AuthenticatedBusinessTransport({ ...metadata, channel: h.channel, monotonicNowNs: () => now });
    const exchange = client.startAuthorization(request(), context);
    now = 1000n + us * 1000n + offset;
    h.result.resolve(toBinary(ManagedCallAuthorizationDecisionSchema, { ...allowed(), validForUs: us }));
    if (offset < 0n) {
      const value = await exchange.result;
      assert.equal(value.outcome, "allowed");
      if (value.outcome === "allowed") assert.equal(value.startDeadlineMonotonicNs, 1000n + us * 1000n);
    } else { await assert.rejects(exchange.result); assert.equal(h.cancellations, 1); }
    assert.equal(exchange.closed, h.closure.promise); h.closure.resolve();
    assert.deepEqual(h.sent.map(x => x.path), [paths.authorize]);
  });
}

test("preparation consumes original lifetime and retries retain every submitted byte", async () => {
  let now = 7000n;
  const sent: Uint8Array[] = [];
  const client = new AuthenticatedBusinessTransport({ ...metadata, monotonicNowNs: () => now,
    channel: { start(path, bytes) { sent.push(Buffer.from(bytes)); return {
      result: Promise.resolve(peerReply(path, bytes)), closed: new Promise<void>(() => {}), cancel() {},
    }; } },
  });
  const input = request();
  const first = await client.startAuthorization(input, context).result;
  now = 7999n;
  const second = await client.startAuthorization(input, context).result;
  assert.deepEqual(sent[0], sent[1]); assert.deepEqual(first, second);
  now = 8000n;
  await assert.rejects(client.startAuthorization(input, context).result);
  now = 10_000_001_000n;
  assert.throws(() => client.startAuthorization(input, context));
  assert.equal(sent.length, 3);
});

test("request and context mutation after dispatch cannot change accepted metadata", async () => {
  const h = harness();
  const client = new AuthenticatedBusinessTransport({ ...metadata, channel: h.channel, monotonicNowNs: () => 1001n });
  const input = request(), timing: { startedAtMonotonicNs: bigint; expectedEpoch: bigint } = { ...context };
  const exchange = client.startAuthorization(input, timing);
  input.caller!.principal = "changed"; input.trace!.spanId = "changed";
  input.binding!.target!.generation = 1n; input.argumentsHash = "f".repeat(64);
  timing.startedAtMonotonicNs = 7000n; timing.expectedEpoch = 25n;
  h.result.resolve(toBinary(ManagedCallAuthorizationDecisionSchema, allowed()));
  const value = await exchange.result;
  assert.equal(value.outcome, "allowed");
  if (value.outcome === "allowed") {
    assert.deepEqual(value.submittedRequest, request()); assert.equal(value.startDeadlineMonotonicNs, 8000n);
    assert.throws(() => { (value.submittedRequest.caller as { principal: string }).principal = "changed"; });
  }
  h.closure.resolve();
});

test("post-decode clock sample refuses a response that crosses the granted boundary during validation", async () => {
  let responding = false, received = false;
  const h = harness();
  const client = new AuthenticatedBusinessTransport({ ...metadata, channel: h.channel, monotonicNowNs() {
    if (!responding) return 1001n;
    if (!received) { received = true; return 7999n; }
    return 8000n;
  } });
  const exchange = client.startAuthorization(request(), context);
  responding = true; h.result.resolve(toBinary(ManagedCallAuthorizationDecisionSchema, allowed()));
  await assert.rejects(exchange.result, { message: "managed business refused safely" });
  assert.equal(h.cancellations, 1); assert.equal(exchange.closed, h.closure.promise); h.closure.resolve();
});

for (const kind of ["policy", "authorize", "complete"] as const) {
  test(`${kind} final response callback cannot outrun an overdue ten-second timer`, async t => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    let now = 1000n;
    const h = harness();
    const client = new AuthenticatedBusinessTransport({ ...metadata, channel: h.channel, monotonicNowNs: () => now });
    const exchange = kind === "policy" ? client.startPolicy(nonce) : kind === "authorize"
      ? client.startAuthorization(request(), context) : client.startCompletion(admissionId, callId);
    now = 10_000_001_000n;
    h.result.resolve(peerReply(h.sent[0].path, h.sent[0].bytes));
    await assert.rejects(exchange.result); assert.equal(h.cancellations, 1);
    assert.equal(exchange.closed, h.closure.promise); h.closure.resolve();
  });
}

test("successful authorization expiry neither sends completion nor settles RPC closure", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let now = 1001n;
  const h = harness(toBinary(ManagedCallAuthorizationDecisionSchema, allowed()));
  const client = new AuthenticatedBusinessTransport({ ...metadata, channel: h.channel, monotonicNowNs: () => now });
  const exchange = client.startAuthorization(request(), context);
  assert.equal((await exchange.result).outcome, "allowed");
  let physicallyClosed = false; void exchange.closed.then(() => { physicallyClosed = true; });
  now = 20_000_000_000n; t.mock.timers.tick(20_000); await Promise.resolve();
  assert.equal(physicallyClosed, false); assert.equal(h.cancellations, 0);
  assert.deepEqual(h.sent.map(x => x.path), [paths.authorize]); h.closure.resolve();
});

test("time spent in channel dispatch still returns owned closure on local failure", async () => {
  let now = 1001n;
  const h = harness();
  const client = new AuthenticatedBusinessTransport({ ...metadata, monotonicNowNs: () => now,
    channel: { start(path, bytes) { const exchange = h.channel.start(path, bytes); now = 10_000_001_000n; return exchange; } },
  });
  const exchange = client.startAuthorization(request(), context);
  await assert.rejects(exchange.result); assert.equal(exchange.closed, h.closure.promise);
  assert.equal(h.cancellations, 1); h.result.resolve(toBinary(ManagedCallAuthorizationDecisionSchema, allowed()));
  h.closure.resolve();
});

test("start/cancel dependency failures and an initial throwing clock remain static", async () => {
  const broken = new AuthenticatedBusinessTransport({ ...metadata, monotonicNowNs: () => 1001n,
    channel: { start() { throw new Error("START_CANARY"); } },
  });
  assert.throws(() => broken.startPolicy(nonce), { message: "managed business refused safely" });
  const h = harness();
  const clock = new AuthenticatedBusinessTransport({ ...metadata, channel: h.channel,
    monotonicNowNs() { throw new Error("CLOCK_CANARY"); },
  });
  assert.throws(() => clock.startAuthorization(request(), context), { message: "managed business refused safely" });
  assert.equal(h.sent.length, 0);
  const client = new AuthenticatedBusinessTransport({ ...metadata, monotonicNowNs: () => 1001n,
    channel: { start(path, bytes) { return { ...h.channel.start(path, bytes), cancel() { throw new Error("CANCEL_CANARY"); } }; } },
  });
  const exchange = client.startPolicy(nonce), rejected = assert.rejects(exchange.result, { message: "managed business refused safely" });
  assert.doesNotThrow(() => exchange.cancel()); await rejected;
  assert.equal(exchange.closed, h.closure.promise); h.closure.resolve();
});

for (const end of ["cancel", "closed", "rejected", "malformed"] as const) {
  test(`${end} rejects reporting without releasing physical ownership or sending completion`, async () => {
    const h = harness();
    const client = new AuthenticatedBusinessTransport({ ...metadata, channel: h.channel, monotonicNowNs: () => 1001n });
    const exchange = client.startAuthorization(request(), context);
    const rejection = assert.rejects(exchange.result, e => {
      assert.equal((e as Error).message, "managed business refused safely"); return true;
    });
    if (end === "cancel") exchange.cancel();
    if (end === "closed") h.closure.resolve();
    if (end === "rejected") h.result.reject(new Error("REMOTE_CANARY"));
    if (end === "malformed") h.result.resolve(Buffer.from([0xff]));
    await rejection;
    h.result.resolve(toBinary(ManagedCallAuthorizationDecisionSchema, allowed()));
    await Promise.resolve();
    assert.equal(exchange.closed, h.closure.promise); assert.equal(h.cancellations, 1);
    assert.deepEqual(h.sent.map(x => x.path), [paths.authorize]);
    h.closure.resolve();
  });
}

test("timer uses remaining original ten-second budget and does not fabricate cleanup", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let now = 9_999_001_000n;
  const h = harness();
  const client = new AuthenticatedBusinessTransport({ ...metadata, channel: h.channel, monotonicNowNs: () => now });
  const exchange = client.startAuthorization(request(), context);
  const rejected = assert.rejects(exchange.result);
  now = 10_000_001_000n; t.mock.timers.tick(1);
  await rejected; assert.equal(h.cancellations, 1);
  assert.equal(exchange.closed, h.closure.promise); assert.equal(h.sent.length, 1);
  h.closure.resolve();
});

for (const bad of [-1n, 999n, "throw", 1 as unknown as bigint] as const) {
  test(`bad clock ${String(bad)} refuses late responses with static errors`, async () => {
    let sample: bigint | "throw" = 1001n;
    const h = harness();
    const client = new AuthenticatedBusinessTransport({ ...metadata, channel: h.channel, monotonicNowNs() {
      if (sample === "throw") throw new Error("CLOCK_CANARY"); return sample;
    } });
    const exchange = client.startAuthorization(request(), context); sample = bad;
    h.result.resolve(toBinary(ManagedCallAuthorizationDecisionSchema, allowed()));
    await assert.rejects(exchange.result, { message: "managed business refused safely" });
    assert.equal(h.cancellations, 1); h.closure.resolve();
  });
}

test("completion is callable independently after cancellation and authorization expiry", async () => {
  let now = 1001n;
  const h = harness();
  const client = new AuthenticatedBusinessTransport({ ...metadata, channel: h.channel, monotonicNowNs: () => now });
  const authorization = client.startAuthorization(request(), context);
  const rejected = assert.rejects(authorization.result); authorization.cancel(); await rejected;
  now = 20_000_000_000n;
  const completion = client.startCompletion(admissionId, callId);
  h.result.resolve(peerReply(paths.complete, h.sent[1].bytes));
  assert.equal((await completion.result).released, true);
  assert.deepEqual(h.sent.map(x => x.path), [paths.authorize, paths.complete]); h.closure.resolve();
});
