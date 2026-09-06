import test from "node:test";
import assert from "node:assert/strict";
import { harness, envelope, turns, deferred, canary } from "./testing.js";
import { CompiledManagedExecutor } from "../compiled-executor.js";
import { fixture, configuration } from "../call-preparation/fixture.js";
import type { CallStart, CallResult, OwnedCall } from "../call-owner.js";
import { CallObservationRecord } from "../call-observation.js";
import { McpProxyAuthBindingSchema } from "@apex/contracts";
import { create } from "@bufbuild/protobuf";

test("cancel retains raw and evidence ownership until both exact closures", async t => {
  const h = harness(); t.after(() => h.cleanup()); const job = h.start();
  h.authorize(); await turns(); h.upstream.resolve(envelope()); await turns();
  job.cancel(); await assert.rejects(job.result); let closed = false; void job.closed.then(() => { closed = true; });
  h.rawClosed.resolve(); h.completionClosed.resolve(); await turns(); assert.equal(closed, false);
  h.evidenceReply.resolve(Buffer.alloc(0)); await turns(); assert.equal(closed, false);
  h.evidenceClosed.resolve(); await job.closed; assert.equal(job.observation().state, "cancelled");
});

test("close during a synchronous preparation clock prevents raw dispatch and revokes future starts", async t => {
  const h = harness(); t.after(() => h.cleanup()); let closing: Promise<void> | undefined;
  h.hook(() => { h.hook(); closing = h.executor.close(); }); const job = h.start();
  await assert.rejects(job.result); await job.closed; await closing;
  assert.equal(h.effects.length, 0); assert.throws(() => h.start());
});

test("close cancels jobs but never closes the independently owned shared roots", async t => {
  const h = harness(); t.after(() => h.cleanup()); const job = h.start(); h.authorize(); await turns();
  let closed = false; const closing = h.executor.close().then(() => { closed = true; });
  assert.equal(h.executor.close(), h.executor.close()); await assert.rejects(job.result); await turns(); assert.equal(closed, false);
  h.upstream.resolve(envelope()); h.rawClosed.resolve(); h.completionClosed.resolve(); await closing;
  assert.equal(h.events.length, 0); assert.equal(job.completion()?.admission.status, "failed");
  assert.throws(() => h.start());
});

test("late known authorization after cancel is retained without new evidence I/O", async t => {
  const h = harness(); t.after(() => h.cleanup()); const job = h.start(); await turns(); job.cancel();
  await assert.rejects(job.result); h.authorize(); h.completionClosed.resolve(); await job.closed;
  // Actual business transport cancels unknown authorization, so it does not
  // promote a later unvalidated wire reply to a known decision.
  assert.equal(h.events.length, 0); assert.equal(job.completion(), undefined);
});

for (const point of ["raw", "evidence"]) test(`original deadline at ${point} settlement cannot be reset`, async t => {
  const h = harness(); t.after(() => h.cleanup()); const job = h.start(); h.authorize(); await turns();
  if (point === "raw") h.advance(120000000000n);
  h.upstream.resolve(envelope()); await turns();
  if (point === "evidence") { h.advance(120000000000n); h.evidenceReply.resolve(Buffer.alloc(0)); }
  await assert.rejects(job.result); assert.notEqual(job.observation().state, "succeeded");
  h.rawClosed.resolve(); h.completionClosed.resolve(); h.evidenceClosed.resolve(); await job.closed;
});

for (const kind of ["backwards", "wall", "throw"]) test(`clock ${kind} cannot abandon a held raw owner`, async t => {
  const h = harness(); t.after(() => { h.hook(); return h.cleanup(); }); const job = h.start();
  h.authorize(); await turns();
  if (kind === "throw") h.hook(() => { throw Error(canary); });
  else h.clock({ ...h.original, ...(kind === "wall" ? { unixUs: h.original.unixUs + 10n } : { monotonicNs: h.original.monotonicNs - 1n }) });
  h.upstream.resolve(envelope()); await assert.rejects(job.result); await turns();
  assert.ok(h.effects.includes("cancel-upstream")); let closed = false; void job.closed.then(() => { closed = true; });
  assert.equal(closed, false); h.rawClosed.resolve(); h.completionClosed.resolve(); await job.closed;
  assert.equal(job.observation().closedAtMonotonicNs, undefined);
});

test("executor compilation rejects per-subject authBindings without contacting roots", () => {
  const f = fixture(); let calls = 0;
  const config = configuration(config => { config.spec!.authBindings = [create(McpProxyAuthBindingSchema, {
    bindingId: "subject", inboundSubject: "spiffe://apex/agent/research", outboundCredentialRef: config.secretRefs[0], scopes: ["mcp:tools"] })]; });
  assert.throws(() => new CompiledManagedExecutor({ preparation: { ...f.options, config },
    calls: { start() { calls++; throw Error(canary); } }, evidence: { start() { calls++; throw Error(canary); } } }), /compiled managed execution refused safely/);
  assert.equal(calls, 0);
});

function heldHarness() {
  const f = fixture(), jobs: { result: ReturnType<typeof deferred<CallResult>>; closed: ReturnType<typeof deferred<void>>; request: CallStart }[] = [];
  const executor = new CompiledManagedExecutor({ preparation: f.options, calls: { start(request): OwnedCall {
    const result = deferred<CallResult>(), closed = deferred<void>(); const observation = new CallObservationRecord(request.request, request.startedAtMonotonicNs);
    jobs.push({ result, closed, request }); return { result: result.promise, closed: closed.promise, cancel() {}, observation: () => observation.snapshot() };
  } }, evidence: { start() { throw Error("must not send for unknown decisions"); } } });
  return { ...f, jobs, executor, start: () => executor.start(f.identity, "portfolio.read", { portfolioId: "p-1" }, f.original, f.deadline) };
}

test("128 cancelled jobs retain capacity across late settlement and raw physical holds", async () => {
  const h = heldHarness(), jobs = Array.from({ length: 128 }, () => h.start()); await turns();
  assert.equal(new Set(jobs.map(job => job.observation().callId)).size, 128);
  assert.equal(new Set(jobs.map(job => job.observation().traceId)).size, 128);
  assert.equal(new Set(jobs.map(job => job.observation().spanId)).size, 128);
  assert.equal(h.jobs.length, 128); for (const job of jobs) job.cancel(); await Promise.all(jobs.map(job => assert.rejects(job.result)));
  assert.throws(() => h.start(), /compiled managed execution refused safely/);
  for (const job of h.jobs) job.result.reject(Error(canary)); await turns(); assert.throws(() => h.start());
  h.jobs[0].closed.resolve(); await jobs[0].closed;
  const extra = h.start(); await turns(); assert.equal(h.jobs.length, 129); extra.cancel(); await assert.rejects(extra.result);
  const closing = h.executor.close(); for (const job of h.jobs) { job.result.reject(Error(canary)); job.closed.resolve(); }
  await closing;
});

test("reentrant close during raw start cancels the owner returned after the stop", async () => {
  const f = fixture(), held = deferred<void>(); let cancels = 0, closed = false;
  let closing: Promise<void> | undefined;
  const executor = new CompiledManagedExecutor({ preparation: f.options, calls: { start(input) {
    const observation = new CallObservationRecord(input.request, input.startedAtMonotonicNs);
    closing = executor.close().then(() => { closed = true; });
    return { result: Promise.reject(Error(canary)), closed: held.promise, cancel() { cancels++; }, observation: () => observation.snapshot() };
  } }, evidence: { start() { throw Error("no decision"); } } });
  const job = executor.start(f.identity, "portfolio.read", { portfolioId: "p-1" }, f.original, f.deadline);
  await assert.rejects(job.result); await turns(); assert.equal(cancels, 1); assert.equal(closed, false);
  held.resolve(); await job.closed; await closing;
});

for (const kind of ["accessor", "proxy", "unknown", "malformed"]) test(`input ${kind} refuses before clock or authority hooks`, async t => {
  const h = harness(); t.after(() => h.cleanup()); let reads = 0;
  h.hook(() => { reads++; });
  let value: unknown = { portfolioId: "p-1" };
  if (kind === "accessor") value = { get portfolioId() { reads++; return "p-1"; } };
  if (kind === "proxy") value = new Proxy({}, { ownKeys() { reads++; return []; } });
  if (kind === "unknown") value = { portfolioId: "p-1", extra: canary };
  if (kind === "malformed") value = { portfolioId: "p-1\n" };
  const job = h.executor.start(h.identity, "portfolio.read", value, h.original, h.deadline);
  await assert.rejects(job.result); await job.closed; assert.equal(reads, 0); assert.equal(h.effects.length, 0);
});

test("rejected physical close never resolves executor closed or permits capacity reuse", async () => {
  const h = heldHarness(), job = h.start(); await turns(); const closing = h.executor.close();
  h.jobs[0].closed.reject(Error(canary)); h.jobs[0].result.reject(Error(canary)); await assert.rejects(job.result);
  let closed = false; void job.closed.then(() => { closed = true; }); void closing.then(() => { closed = true; });
  await turns(); assert.equal(closed, false); assert.throws(() => h.start());
});

test("failure before evidence start still requests cancellation of the retained raw owner", async () => {
  const f = fixture(), closed = deferred<void>(); let cancellations = 0, failClock = false;
  const executor = new CompiledManagedExecutor({ preparation: { ...f.options, clock: { now() {
    if (failClock) throw Error(canary); return { ...f.original };
  } } }, calls: { start(input) {
    const observation = new CallObservationRecord(input.request, input.startedAtMonotonicNs);
    const decision = { outcome: "denied" as const, policyId: f.options.config.spec!.governanceBinding!.policyId,
      policyRevision: 1n, reasonCode: "policy.denied", fieldRestrictions: [] };
    observation.known(decision); failClock = true;
    return { result: Promise.resolve({ decision }), closed: closed.promise,
      cancel() { cancellations++; }, observation: () => observation.snapshot() };
  } }, evidence: { start() { throw Error("no evidence with failed clock"); } } });
  const job = executor.start(f.identity, "portfolio.read", { portfolioId: "p-1" }, f.original, f.deadline);
  await assert.rejects(job.result); await turns(); assert.equal(cancellations, 1);
  closed.resolve(); await job.closed;
});
