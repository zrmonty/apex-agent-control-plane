import assert from "node:assert/strict";
import test from "node:test";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { EvidenceAdmissionProbeRequestSchema as Request, EvidenceAdmissionProbeResponseSchema as Response } from "@apex/contracts/event";
import { EvidenceReadinessClient } from "./readiness-client.js";
import { deferred } from "../authority/business-testing.js";
import { dependencyUnavailable, isDependencyUnavailable } from "../authority/dependency-failure.js";

const scope = { workspaceId: "workspace-one", namespaceId: "namespace-one", agentId: "evidence-one" };
const refused = /^Error: managed evidence readiness refused safely$/;
function answer(bytes: Uint8Array) {
  const request = fromBinary(Request, bytes);
  return create(Response, { schemaVersion: request.schemaVersion, requestNonce: request.requestNonce,
    workspaceId: request.workspaceId, namespaceId: request.namespaceId, agentId: request.agentId,
    ready: true, validForUs: 10_000_000n });
}
test("non-admitting probe echoes a fresh nonce and anchors freshness to original monotonic start", async () => {
  const nonces: Uint8Array[] = [], closure = deferred<void>(); let sent!: Uint8Array;
  const client = new EvidenceReadinessClient(scope, { startReadiness(bytes, started, deadline) {
    sent = bytes; const request = fromBinary(Request, bytes); assert.equal(request.schemaVersion, 1);
    assert.equal(request.requestNonce.length, 32); nonces.push(Uint8Array.from(request.requestNonce));
    for (const key of ["workspaceId", "namespaceId", "agentId"] as const) assert.equal(request[key], scope[key]);
    assert.equal(started, 1000n); assert.equal(deadline, 2_000_001_000n);
    return { result: Promise.resolve(toBinary(Response, answer(bytes))), closed: closure.promise, cancel() {} };
  } }, () => 1_000_001_000n);
  const first = client.start(1000n, 60_000_001_000n);
  assert.deepEqual(await first.result, { validUntilMonotonicNs: 10_000_001_000n });
  let closed = false; void first.closed.then(() => { closed = true; }); await Promise.resolve(); assert.equal(closed, false);
  assert.ok(sent.some(byte => byte !== 0)); closure.resolve(); await first.closed; assert.ok(sent.every(byte => byte === 0));
  const second = client.start(1000n, 60_000_001_000n); await second.result; await second.closed;
  assert.notDeepEqual(nonces[0], nonces[1]); await client.close();
});

for (const defect of ["schema", "nonce", "workspace", "namespace", "agent", "not-ready", "zero-life", "long-life", "expired-life", "unknown", "duplicate", "oversize"]) {
  test(`probe refuses ${defect} without admitting an event`, async () => {
    const closure = deferred<void>(); let cancellations = 0;
    const client = new EvidenceReadinessClient(scope, { startReadiness(bytes) {
      const response = answer(bytes);
      if (defect === "schema") response.schemaVersion = 2;
      if (defect === "nonce") response.requestNonce = Buffer.alloc(32);
      if (defect === "workspace") response.workspaceId = "other";
      if (defect === "namespace") response.namespaceId = "other";
      if (defect === "agent") response.agentId = "other";
      if (defect === "not-ready") response.ready = false;
      if (defect === "zero-life") response.validForUs = 0n;
      if (defect === "long-life") response.validForUs = 10_000_001n;
      if (defect === "expired-life") response.validForUs = 1n;
      let payload = toBinary(Response, response);
      if (defect === "unknown") payload = Buffer.concat([payload, Buffer.from([64, 1])]);
      if (defect === "duplicate") payload = Buffer.concat([payload, Buffer.from([8, 1])]);
      if (defect === "oversize") payload = Buffer.alloc(1025);
      return { result: Promise.resolve(payload), closed: closure.promise, cancel() { cancellations++; } };
    } }, () => 3000n);
    const job = client.start(1000n, 2_000_001_000n); await assert.rejects(job.result, error => {
      assert.match(String(error), refused);
      assert.equal(isDependencyUnavailable(error), defect === "not-ready"); return true;
    });
    assert.equal(cancellations, 1); closure.resolve(); await job.closed; await client.close();
  });
}

test("four logically cancelled probes retain physical capacity and shutdown ownership", async () => {
  const closures: ReturnType<typeof deferred<void>>[] = [];
  const client = new EvidenceReadinessClient(scope, { startReadiness() {
    const closed = deferred<void>(); closures.push(closed);
    return { result: new Promise<Uint8Array>(() => {}), closed: closed.promise, cancel() {} };
  } }, () => 1001n);
  const jobs = Array.from({ length: 4 }, () => client.start(1000n, 2_000_001_000n));
  const failures = jobs.map(job => assert.rejects(job.result, refused)); jobs.forEach(job => job.cancel()); await Promise.all(failures);
  assert.throws(() => client.start(1000n, 2_000_001_000n), refused);
  let drained = false; const closing = client.close().then(() => { drained = true; }); await Promise.resolve(); assert.equal(drained, false);
  closures.forEach(item => item.resolve()); await closing; assert.equal(drained, true);
});

for (const at of [999n, 2_000_001_000n]) {
  test(`probe cannot accept a response at invalid monotonic time ${at}`, async () => {
    let now = 1001n; const response = deferred<Uint8Array>(), closure = deferred<void>(); let payload!: Uint8Array;
    const client = new EvidenceReadinessClient(scope, { startReadiness(bytes) {
      payload = toBinary(Response, answer(bytes)); return { result: response.promise, closed: closure.promise, cancel() {} };
    } }, () => now);
    const job = client.start(1000n, 60_000_001_000n); now = at; response.resolve(payload);
    await assert.rejects(job.result, refused); closure.resolve(); await job.closed; await client.close();
  });
}

test("reentrant owner close during transport start retains the newly returned physical operation", async () => {
  const closure = deferred<void>(); let closing!: Promise<void>, drained = false, cancellations = 0;
  const client = new EvidenceReadinessClient(scope, { startReadiness(bytes) {
    closing = client.close().then(() => { drained = true; });
    return { result: Promise.resolve(toBinary(Response, answer(bytes))), closed: closure.promise, cancel() { cancellations++; } };
  } }, () => 1001n);
  const job = client.start(1000n, 2_000_001_000n); await assert.rejects(job.result, refused);
  assert.equal(cancellations, 1); assert.equal(drained, false); closure.resolve(); await job.closed; await closing;
});

test("invalid scope and expired requests start no I/O; transport failures remain static and release only unacquired slots", async () => {
  let sent = 0;
  const channel = { startReadiness() { sent++; throw new Error("private transport canary"); } };
  assert.throws(() => new EvidenceReadinessClient({ ...scope, agentId: "invalid agent" }, channel), refused);
  const client = new EvidenceReadinessClient(scope, channel, () => 1001n);
  assert.throws(() => client.start(1000n, 1001n), refused); assert.equal(sent, 0);
  for (let i = 0; i < 5; i++) assert.throws(() => client.start(1000n, 5000n), refused);
  assert.equal(sent, 5); await client.close();
});

test("a real deadline rejects the wait but cannot settle physical probe closure", async () => {
  const closure = deferred<void>(); let cancelled = 0;
  const client = new EvidenceReadinessClient(scope, { startReadiness() {
    return { result: new Promise<Uint8Array>(() => {}), closed: closure.promise, cancel() { cancelled++; } };
  } });
  const started = process.hrtime.bigint(), job = client.start(started, started + 30_000_000n);
  await assert.rejects(job.result, refused); assert.equal(cancelled, 1);
  let drained = false; void job.closed.then(() => { drained = true; }); await Promise.resolve(); assert.equal(drained, false);
  closure.resolve(); await job.closed; await client.close();
});

for (const ordinary of [true, false]) {
  test(`EVIDENCE preserves only classified ordinary failure (${ordinary}) through redaction`, async () => {
    const closure = deferred<void>();
    const client = new EvidenceReadinessClient(scope, { startReadiness() {
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
