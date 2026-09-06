import assert from "node:assert/strict";
import test from "node:test";
import { fromBinary } from "@bufbuild/protobuf";
import { EventEnvelopeSchema } from "@apex/contracts/event";
import { ManagedEvidenceClient } from "./client.js";
import { ManagedEvidenceBuilder, evidenceBytes } from "./builder.js";
import { example } from "./testing.js";
import { metadata, deferred } from "../authority/business-testing.js";

test("typed evidence receipt binds exact canonical event and preserves physical closure", async () => {
  const prepared = new ManagedEvidenceBuilder(metadata).prepare(example()); const closure = deferred<void>();
  let sent = 0;
  const client = new ManagedEvidenceClient({ start(bytes, started, deadline) {
    sent++; assert.equal(started, 1000n); assert.equal(deadline, 5_000_001_000n);
    assert.deepEqual(bytes, evidenceBytes(prepared)); assert.equal(fromBinary(EventEnvelopeSchema, bytes).eventId, prepared.eventId);
    return { result: Promise.resolve(Buffer.alloc(0)), closed: closure.promise, cancel() {} };
  } }, () => 1001n);
  const exchange = client.start(prepared, 1000n, 5_000_001_000n);
  assert.deepEqual(await exchange.result, { ...prepared, duplicate: false });
  let closed = false; void exchange.closed.then(() => { closed = true; }); await Promise.resolve(); assert.equal(closed, false);
  closure.resolve(); await exchange.closed; await client.close(); assert.equal(sent, 1);
});

test("already settled native result is decoded before its physical closure", async () => {
  const prepared = new ManagedEvidenceBuilder(metadata).prepare(example());
  const client = new ManagedEvidenceClient({ start() {
    return { result: Promise.resolve(Buffer.from([8, 1])), closed: Promise.resolve(), cancel() {} };
  } }, () => 1001n);
  const exchange = client.start(prepared, 1000n, 5000n);
  assert.deepEqual(await exchange.result, { ...prepared, duplicate: true });
  await exchange.closed; await client.close();
});

for (const payload of [[8, 0], [8, 2], [8, 1, 8, 1], [16, 1], [8, 129, 0], [8], [0], Array(8193).fill(0)]) {
  test(`typed receipt rejects noncanonical or unknown response ${payload.length}:${payload.slice(0, 5)}`, async () => {
    const closure = deferred<void>(); let cancellations = 0;
    const client = new ManagedEvidenceClient({ start() {
      return { result: Promise.resolve(Uint8Array.from(payload)), closed: closure.promise, cancel() { cancellations++; } };
    } }, () => 1001n);
    const exchange = client.start(new ManagedEvidenceBuilder(metadata).prepare(example()), 1000n, 5000n);
    await assert.rejects(exchange.result, /^Error: managed event admission refused safely$/);
    assert.equal(cancellations, 1); closure.resolve(); await exchange.closed; await client.close();
  });
}

test("bounded typed jobs retain capacity until exact physical closure", async () => {
  const closures: ReturnType<typeof deferred<void>>[] = [];
  const client = new ManagedEvidenceClient({ start() {
    const gate = deferred<void>(); closures.push(gate);
    return { result: new Promise<Uint8Array>(() => {}), closed: gate.promise, cancel() {} };
  } }, () => 1001n);
  const prepared = new ManagedEvidenceBuilder(metadata).prepare(example());
  const exchanges = Array.from({ length: 32 }, () => client.start(prepared, 1000n, 5_000_001_000n));
  const rejected = exchanges.map(exchange => assert.rejects(exchange.result, /managed event admission refused safely/));
  for (const exchange of exchanges) exchange.cancel(); await Promise.all(rejected);
  assert.throws(() => client.start(prepared, 1000n, 5000n), /managed event admission refused safely/);
  let closed = false; const closing = client.close().then(() => { closed = true; });
  await Promise.resolve(); assert.equal(closed, false);
  for (const gate of closures) gate.resolve(); await closing;
  assert.throws(() => client.start(prepared, 1000n, 5000n), /managed event admission refused safely/);
});

test("explicit retry preserves exact event identity bytes and observed time with no hidden replay", async () => {
  const sent: Uint8Array[] = [], closures: ReturnType<typeof deferred<void>>[] = [];
  const client = new ManagedEvidenceClient({ start(bytes) {
    sent.push(Uint8Array.from(bytes)); const gate = deferred<void>(); closures.push(gate);
    return { result: sent.length === 1 ? Promise.reject(new Error("private peer canary")) : Promise.resolve(Buffer.from([8, 1])),
      closed: gate.promise, cancel() {} };
  } }, () => 1001n);
  const prepared = new ManagedEvidenceBuilder(metadata).prepare(example());
  const first = client.start(prepared, 1000n, 5000n);
  await assert.rejects(first.result, /^Error: managed event admission refused safely$/);
  assert.equal(sent.length, 1); closures[0].resolve(); await first.closed;
  const retry = client.start(prepared, 1000n, 5000n);
  assert.deepEqual(await retry.result, { ...prepared, duplicate: true }); assert.deepEqual(sent[0], sent[1]);
  closures[1].resolve(); await retry.closed; await client.close();
});

for (const at of [1000n + 5_000_000_000n, 999n]) {
  test(`response-time clock ${at} cannot accept stale or regressed evidence`, async () => {
    let now = 1001n; const reply = deferred<Uint8Array>(), closure = deferred<void>();
    const client = new ManagedEvidenceClient({ start() { return { result: reply.promise, closed: closure.promise, cancel() {} }; } }, () => now);
    const exchange = client.start(new ManagedEvidenceBuilder(metadata).prepare(example()), 1000n, 60_000_001_000n);
    now = at; reply.resolve(Buffer.alloc(0));
    await assert.rejects(exchange.result, /^Error: managed event admission refused safely$/);
    closure.resolve(); await exchange.closed; await client.close();
  });
}

test("synchronous close during channel start retains the returned native owner", async () => {
  const closure = deferred<void>(); let closing!: Promise<void>, closed = false, cancelled = 0;
  const client = new ManagedEvidenceClient({ start() {
    closing = client.close().then(() => { closed = true; });
    return { result: Promise.resolve(Buffer.alloc(0)), closed: closure.promise, cancel() { cancelled++; } };
  } }, () => 1001n);
  const exchange = client.start(new ManagedEvidenceBuilder(metadata).prepare(example()), 1000n, 5000n);
  await assert.rejects(exchange.result, /managed event admission refused safely/);
  assert.equal(cancelled, 1); assert.equal(closed, false);
  closure.resolve(); await exchange.closed; await closing;
});

test("untrusted handles and expired starts never reach transport, and transport throws are redacted", async () => {
  let sent = 0;
  const client = new ManagedEvidenceClient({ start() { sent++; throw new Error("private transport canary"); } }, () => 1001n);
  const prepared = new ManagedEvidenceBuilder(metadata).prepare(example());
  assert.throws(() => client.start({ ...prepared }, 1000n, 5000n), /^Error: managed event admission refused safely$/);
  assert.throws(() => client.start(prepared, 1000n, 1001n), /^Error: managed event admission refused safely$/);
  assert.equal(sent, 0);
  for (let i = 0; i < 33; i++) assert.throws(() => client.start(prepared, 1000n, 5000n), /^Error: managed event admission refused safely$/);
  assert.equal(sent, 33); await client.close();
});

test("deadline is clamped to the original five seconds, with bytes wiped only after physical close", async () => {
  const closure = deferred<void>(); let owned!: Uint8Array;
  const client = new ManagedEvidenceClient({ start(bytes, started, deadline) {
    owned = bytes; assert.equal(started, 1000n); assert.equal(deadline, 5_000_001_000n);
    return { result: Promise.resolve(Buffer.alloc(0)), closed: closure.promise, cancel() {} };
  } }, () => 1001n);
  const prepared = new ManagedEvidenceBuilder(metadata).prepare(example());
  const exchange = client.start(prepared, 1000n, 60_000_001_000n); await exchange.result;
  assert.deepEqual(owned, evidenceBytes(prepared)); closure.resolve(); await exchange.closed;
  assert.ok(owned.every(byte => byte === 0)); assert.ok(evidenceBytes(prepared).some(byte => byte !== 0)); await client.close();
});
