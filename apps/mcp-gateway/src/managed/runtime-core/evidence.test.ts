import test from "node:test";
import assert from "node:assert/strict";
import { servingFixture, tick } from "./testing.js";

test("PREPARE core probes actual bound evidence identity without event, reservation or upstream work", async t => {
  const f = await servingFixture(t, { prepareOnly: true });
  const started = f.time.now(), job = f.core.startEvidenceReadiness(started, started + 2_000_000_000n);
  assert.deepEqual(await job.result, { validUntilMonotonicNs: started + 10_000_000_000n }); await job.closed;
  assert.equal(f.probes.length, 1);
  const request = f.probes[0], binding = f.stage.documents.binding;
  assert.equal(request.workspaceId, binding.workspaceId); assert.equal(request.namespaceId, binding.namespaceId);
  assert.equal(request.agentId, f.stage.documents.authority.profile.managed.evidence_agent_id);
  assert.equal(f.events.length, 0); assert.equal(f.authorizations.length, 0); assert.equal(f.requests.length, 0);
  assert.equal(f.core.grants.snapshot().activeCalls, 0); assert.equal(f.core.isAdmitting(), false);
});

test("core shutdown retains an evidence probe's physical cleanup and refuses new probes", async t => {
  const f = await servingFixture(t, { prepareOnly: true }); f.holdProbeClosure(); f.holdProbeReply();
  const job = f.core.startEvidenceReadiness(f.time.now(), f.time.now() + 2_000_000_000n);
  const rejected = assert.rejects(job.result, /managed evidence readiness refused safely/);
  f.handle.cancel(); await rejected;
  let drained = false; void f.handle.closed.then(() => { drained = true; }); await tick(); assert.equal(drained, false);
  assert.throws(() => f.core.startEvidenceReadiness(f.time.now(), f.time.now() + 2_000_000_000n));
  assert.equal(f.probes.length, 1); f.releaseProbes(); await job.closed; await f.handle.closed;
  assert.equal(f.stats().fatals, 0);
});

test("evidence result cannot become readiness after core credential revocation", async t => {
  const f = await servingFixture(t, { prepareOnly: true }); f.holdProbeClosure(); f.holdProbeReply();
  const job = f.core.startEvidenceReadiness(f.time.now(), f.time.now() + 2_000_000_000n);
  const rejected = assert.rejects(job.result, /managed evidence readiness refused safely/);
  f.revokeControl(); await tick(); f.replyProbes(); await rejected;
  f.releaseProbes(); await job.closed; await f.handle.closed;
  assert.equal(f.events.length, 0); assert.equal(f.core.isAdmitting(), false);
});
