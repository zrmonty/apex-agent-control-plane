import assert from "node:assert/strict";
import test from "node:test";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { RuntimeNetworkInspectionRequestSchema as Request, RuntimeNetworkInspectionResponseSchema as Response } from "@apex/contracts";
import { NetworkReadinessClient } from "./network-readiness.js";
import { binding, deferred } from "./business-testing.js";
import { readBinding } from "./grant-transport.js";
import { dependencyUnavailable, isDependencyUnavailable } from "./dependency-failure.js";
const network = "c".repeat(64), refused = /^Error: managed network readiness refused safely$/;
const method = "/apex.v1.ManagedNetworkReadiness/Check";
function answer(bytes: Uint8Array) {
  const request = fromBinary(Request, bytes);
  return create(Response, { schemaVersion: 1, binding: request.binding, nonce: request.nonce,
    networkBindingSha256: network, gatewayProcessSha256: "d".repeat(64), guardProcessSha256: "e".repeat(64),
    validForUs: 10_000_000n, confined: true });
}
test("NETWORK observation binds fresh nonce, original large fence and expected network without restamping", async () => {
  const nonces: Uint8Array[] = [], closure = deferred<void>(); let sent!: Uint8Array;
  const client = new NetworkReadinessClient(binding, network, { start(path: string, bytes: Uint8Array) {
    assert.equal(path, method); sent = bytes;
    const request = fromBinary(Request, bytes); assert.equal(request.schemaVersion, 1);
    assert.deepEqual(readBinding(request.binding), binding); assert.equal(request.nonce.length, 32);
    nonces.push(Uint8Array.from(request.nonce));
    return { result: Promise.resolve(toBinary(Response, answer(bytes))), closed: closure.promise, cancel() {} };
  } }, () => 1_000_001_000n);
  const first = client.start(1000n, 60_000_001_000n);
  assert.deepEqual(await first.result, { validUntilMonotonicNs: 10_000_001_000n });
  let drained = false; void first.closed.then(() => { drained = true; }); await Promise.resolve(); assert.equal(drained, false);
  closure.resolve(); await first.closed; assert.ok(sent.every(byte => byte === 0));
  const second = client.start(1000n, 60_000_001_000n); await second.result; await second.closed;
  assert.notDeepEqual(nonces[0], nonces[1]); await client.close();
});
for (const defect of ["schema", "nonce", "binding", "network", "gateway", "guard", "false", "zero", "long", "expired", "unknown", "duplicate", "oversize"]) {
  test(`NETWORK refuses ${defect} while retaining physical cleanup`, async () => {
    const closure = deferred<void>(); let cancelled = 0;
    const client = new NetworkReadinessClient(binding, network, { start(_path: string, bytes: Uint8Array) {
      const r = answer(bytes);
      if (defect === "schema") r.schemaVersion = 2;
      if (defect === "nonce") r.nonce = Buffer.alloc(32);
      if (defect === "binding") r.binding!.target!.fencingToken += 1n;
      if (defect === "network") r.networkBindingSha256 = "f".repeat(64);
      if (defect === "gateway") r.gatewayProcessSha256 = "D".repeat(64);
      if (defect === "guard") r.guardProcessSha256 = "";
      if (defect === "false") r.confined = false;
      if (defect === "zero") r.validForUs = 0n;
      if (defect === "long") r.validForUs = 10_000_001n;
      if (defect === "expired") r.validForUs = 1n;
      let bytesOut = toBinary(Response, r);
      if (defect === "unknown") bytesOut = Buffer.concat([bytesOut, Buffer.from([72, 1])]);
      if (defect === "duplicate") bytesOut = Buffer.concat([bytesOut, Buffer.from([8, 1])]);
      if (defect === "oversize") bytesOut = Buffer.alloc(4097);
      return { result: Promise.resolve(bytesOut), closed: closure.promise, cancel() { cancelled++; } };
    } }, () => 3000n);
    const job = client.start(1000n, 2_000_001_000n); await assert.rejects(job.result, error => {
      assert.match(String(error), refused); assert.equal(isDependencyUnavailable(error), false); return true;
    });
    assert.equal(cancelled, 1); closure.resolve(); await job.closed; await client.close();
  });
}
test("four canceled NETWORK probes retain capacity and root shutdown until actual closure", async () => {
  const closures: ReturnType<typeof deferred<void>>[] = [];
  const client = new NetworkReadinessClient(binding, network, { start() {
    const closed = deferred<void>(); closures.push(closed);
    return { result: new Promise<Uint8Array>(() => {}), closed: closed.promise, cancel() {} };
  } }, () => 1001n);
  const jobs = Array.from({ length: 4 }, () => client.start(1000n, 2_000_001_000n));
  const rejected = jobs.map(job => assert.rejects(job.result, refused)); jobs.forEach(job => job.cancel()); await Promise.all(rejected);
  assert.throws(() => client.start(1000n, 2_000_001_000n), refused);
  let drained = false; const closing = client.close().then(() => { drained = true; }); await Promise.resolve(); assert.equal(drained, false);
  closures.forEach(c => c.resolve()); await closing; assert.equal(drained, true);
});
test("NETWORK start reentry cannot lose physical ownership", async () => {
  const closure = deferred<void>(); let closing!: Promise<void>, drained = false, cancelled = 0;
  const client = new NetworkReadinessClient(binding, network, { start(_path: string, bytes: Uint8Array) {
    closing = client.close().then(() => { drained = true; });
    return { result: Promise.resolve(toBinary(Response, answer(bytes))), closed: closure.promise, cancel() { cancelled++; } };
  } }, () => 1001n);
  const job = client.start(1000n, 2_000_001_000n); await assert.rejects(job.result, refused);
  assert.equal(cancelled, 1); assert.equal(drained, false); closure.resolve(); await job.closed; await closing;
});
for (const at of [999n, 2_000_001_000n]) {
  test(`NETWORK rejects response crossing original monotonic boundary ${at}`, async () => {
    let now = 1001n; const result = deferred<Uint8Array>(), closed = deferred<void>(); let payload!: Uint8Array;
    const client = new NetworkReadinessClient(binding, network, { start(_path: string, bytes: Uint8Array) {
      payload = toBinary(Response, answer(bytes)); return { result: result.promise, closed: closed.promise, cancel() {} };
    } }, () => now);
    const job = client.start(1000n, 60_000_001_000n); now = at; result.resolve(payload);
    await assert.rejects(job.result, refused); closed.resolve(); await job.closed; await client.close();
  });
}

test("invalid NETWORK binding/hash and expired requests dispatch nothing; unacquired slots are released", async () => {
  let sent = 0;
  const channel = { start() { sent++; throw new Error("private network canary"); } };
  assert.throws(() => new NetworkReadinessClient({ ...binding, generation: 0n }, network, channel), refused);
  assert.throws(() => new NetworkReadinessClient(binding, "bad", channel), refused);
  const client = new NetworkReadinessClient(binding, network, channel, () => 1001n);
  assert.throws(() => client.start(1000n, 1001n), refused); assert.equal(sent, 0);
  for (let i = 0; i < 5; i++) assert.throws(() => client.start(1000n, 5000n), refused);
  assert.equal(sent, 5); await client.close();
});

test("actual NETWORK timer refuses a wait but does not prove physical closure", async () => {
  const closed = deferred<void>(); let cancelled = 0;
  const client = new NetworkReadinessClient(binding, network, { start() {
    return { result: new Promise<Uint8Array>(() => {}), closed: closed.promise, cancel() { cancelled++; } };
  } });
  const at = process.hrtime.bigint(), job = client.start(at, at + 30_000_000n);
  await assert.rejects(job.result, refused); assert.equal(cancelled, 1);
  let drained = false; void job.closed.then(() => { drained = true; }); await Promise.resolve(); assert.equal(drained, false);
  closed.resolve(); await job.closed; await client.close();
});

for (const ordinary of [true, false]) {
  test(`NETWORK preserves only classified ordinary failure (${ordinary}) through redaction`, async () => {
    const closure = deferred<void>();
    const client = new NetworkReadinessClient(binding, network, { start() {
      const error = ordinary ? dependencyUnavailable("private unavailable canary") : Error("private unknown canary");
      return { result: Promise.reject(error), closed: closure.promise, cancel() {} };
    } }, () => 1000n);
    const job = client.start(1000n, 2_000_001_000n);
    await assert.rejects(job.result, error => {
      assert.match(String(error), refused); assert.equal(isDependencyUnavailable(error), ordinary); return true;
    });
    let closed = false; void job.closed.then(() => { closed = true; });
    await Promise.resolve(); assert.equal(closed, false);
    closure.resolve(); await job.closed; await client.close();
  });
}
