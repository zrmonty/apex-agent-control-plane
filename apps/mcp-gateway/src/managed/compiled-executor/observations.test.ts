import test from "node:test";
import assert from "node:assert/strict";
import { harness, envelope, turns, canary, deferred } from "./testing.js";
import { CompiledManagedExecutor } from "../compiled-executor.js";
import { ManagedEvidenceClient } from "../evidence/client.js";

for (const us of [1n, 7n, 999n]) test(`canonical admitted trace preserves measured ${us}us above 2^53 with linked completion`, async t => {
  const h = harness(); t.after(() => h.cleanup()); const job = h.start(); await turns();
  h.advance(1000n); h.authorize(); await turns(); h.advance((us + 1n) * 1000n); h.upstream.resolve(envelope()); await turns();
  const data = h.events[0].data!;
  assert.equal(data.started_at_unix_us, "9007199254740993");
  assert.equal(data.observed_at_unix_us, (9007199254740994n + us).toString());
  const stages = data.stages as { name: string; duration_us: string; duration_ns: string }[];
  assert.equal(stages.find(s => s.name === "authorization")?.duration_us, "1");
  assert.equal(stages.find(s => s.name === "upstream")?.duration_us, us.toString());
  assert.equal(stages.find(s => s.name === "upstream")?.duration_ns, (us * 1000n).toString());
  assert.equal(stages.some(s => ["evidence.admission", "response.finish", "response.abort", "call.cleanup", "dns", "tls"].includes(s.name)), false);
  assert.equal(h.evidenceTiming[0].start, h.original.monotonicNs + (us + 1n) * 1000n);
  assert.equal(h.evidenceTiming[0].deadline, h.evidenceTiming[0].start + 5000000000n);
  h.advance((us + 8n) * 1000n); h.evidenceReply.resolve(Buffer.alloc(0)); const output = await job.result;
  const admitted = job.completion()!;
  assert.notEqual(admitted.admission.eventId, admitted.admission.linkedEventId);
  assert.equal(admitted.receipt!.eventHash, h.events[0].integrity!.eventHash);
  assert.equal(admitted.evidence!.resultAtMonotonicNs! - admitted.evidence!.startedAtMonotonicNs!, 7000n);
  assert.equal(admitted.evidence!.closedAtMonotonicNs, undefined);
  const sizes = data.sizes as Record<string, number>;
  assert.equal(sizes.input_bytes, 21); assert.equal(sizes.source_bytes, Buffer.byteLength(JSON.stringify(envelope().structuredContent)));
  assert.equal(sizes.filtered_bytes, Buffer.byteLength(JSON.stringify(output.structuredContent)));
  assert.equal(sizes.output_bytes, Buffer.byteLength(JSON.stringify(output)));
  assert.ok(Object.isFrozen(output.structuredContent.positions)); assert.ok(Object.isFrozen(admitted.admission.decision));
  const before = job.observation(); h.hook(() => { throw Error("observation must not call clock"); });
  assert.deepEqual(job.observation(), before); assert.equal(job.completion()!.admission, admitted.admission); h.hook();
  h.rawClosed.resolve(); h.completionClosed.resolve(); h.evidenceClosed.resolve(); await job.closed;
  assert.equal(admitted.evidence!.closedAtMonotonicNs, undefined); // Earlier snapshot is immutable.
  assert.equal(JSON.stringify(job.completion(), (_, v) => typeof v === "bigint" ? String(v) : v).includes(canary), false);
});

test("output is passively copied before a clock callback can mutate the upstream envelope", async t => {
  const h = harness(); t.after(() => h.cleanup()); const job = h.start(); h.authorize(); await turns();
  const mutable = envelope(); h.hook(() => { mutable.structuredContent.client.display_name = canary; });
  h.upstream.resolve(mutable); await turns(); h.hook(); h.evidenceReply.resolve(Buffer.alloc(0));
  const output = await job.result; assert.equal(output.structuredContent.client.displayName, "Public name");
  h.rawClosed.resolve(); h.completionClosed.resolve(); h.evidenceClosed.resolve(); await job.closed;
});

test("mismatched receipt identity from an injected dependency is refused without leaking output", async t => {
  const h = harness(); t.after(() => h.cleanup()); const close = deferred<void>();
  const executor = new CompiledManagedExecutor({ preparation: h.preparation, calls: h.raw, evidence: { start() {
    return { result: Promise.resolve({ eventId: "wrong", eventHash: "wrong", duplicate: false }), closed: close.promise, cancel() {} };
  } } });
  const job = executor.start(h.identity, "portfolio.read", { portfolioId: "p-1" }, h.original, h.deadline);
  h.authorize(); await turns(); h.upstream.resolve(envelope()); await assert.rejects(job.result);
  let closed = false; void job.closed.then(() => { closed = true; }); await turns(); assert.equal(closed, false);
  close.resolve(); h.rawClosed.resolve(); h.completionClosed.resolve(); await job.closed;
});

test("synchronous close in evidence start retains the returned exchange", async t => {
  const h = harness(); t.after(() => h.cleanup()); const held = deferred<void>(); let closed = false, cancels = 0;
  let closing: Promise<void> | undefined;
  const client = new ManagedEvidenceClient({ start() {
    closing = executor.close().then(() => { closed = true; });
    return { result: Promise.resolve(Buffer.alloc(0)), closed: held.promise, cancel() { cancels++; } };
  } }, () => h.original.monotonicNs);
  const executor = new CompiledManagedExecutor({ preparation: h.preparation, calls: h.raw, evidence: client });
  const job = executor.start(h.identity, "portfolio.read", { portfolioId: "p-1" }, h.original, h.deadline);
  h.authorize(); await turns(); h.upstream.resolve(envelope()); await assert.rejects(job.result);
  h.rawClosed.resolve(); h.completionClosed.resolve(); await turns(); assert.equal(closed, false); assert.equal(cancels, 1);
  held.resolve(); await job.closed; await closing; await client.close();
});

test("evidence attempt is clamped to remaining overall time rather than receiving five fresh seconds", async t => {
  const h = harness(); t.after(() => h.cleanup());
  const job = h.executor.start(h.identity, "portfolio.read", { portfolioId: "p-1" }, h.original, h.original.monotonicNs + 100000n);
  h.authorize(); await turns(); h.advance(90000n); h.upstream.resolve(envelope()); await turns();
  assert.equal(h.evidenceTiming[0].start, h.original.monotonicNs + 90000n);
  assert.equal(h.evidenceTiming[0].deadline, h.original.monotonicNs + 100000n);
  h.advance(100000n); h.evidenceReply.resolve(Buffer.alloc(0)); await assert.rejects(job.result);
  h.rawClosed.resolve(); h.completionClosed.resolve(); h.evidenceClosed.resolve(); await job.closed;
});

test("raw stage reconstruction preserves a stable anchor straddling a microsecond quantum", async t => {
  const h = harness(); t.after(() => h.cleanup()); const job = h.start(); await turns();
  // Original sample is 999 ns into the anchor's current microsecond. These are
  // consistent integer samples, not wall-clock drift or a changed origin.
  h.clock({ ...h.original, monotonicNs: h.original.monotonicNs + 1001n, unixUs: h.original.unixUs + 2n });
  h.authorize(); await turns();
  h.clock({ ...h.original, monotonicNs: h.original.monotonicNs + 2001n, unixUs: h.original.unixUs + 3n });
  h.upstream.resolve(envelope()); await turns(); assert.equal(h.events.length, 1);
  const stage = (h.events[0].data!.stages as any[]).find(s => s.name === "upstream");
  assert.equal(stage.offset_ns, "1001"); assert.equal(stage.duration_ns, "1000"); assert.equal(stage.duration_us, "1");
  h.evidenceReply.resolve(Buffer.alloc(0)); await job.result;
  h.rawClosed.resolve(); h.completionClosed.resolve(); h.evidenceClosed.resolve(); await job.closed;
});
