import test from "node:test";
import assert from "node:assert/strict";
import { harness, envelope, canary, turns } from "./compiled-executor/testing.js";
import { GovernanceOutcome } from "@apex/contracts";

test("safe filtered MCP output is withheld until canonical evidence receipt, independently of physical closure", async t => {
  const h = harness(); t.after(() => h.cleanup());
  const job = h.start() as { result: Promise<any>; closed: Promise<void>; observation(): any; completion(): any };
  let delivered = false, closed = false;
  void job.result.then(() => { delivered = true; }, () => {}); void job.closed.then(() => { closed = true; });
  h.authorize(); await turns(); h.advance(7000n); h.upstream.resolve(envelope()); await turns();
  assert.equal(h.events.length, 1); assert.equal(delivered, false); assert.equal(closed, false);
  const data = h.events[0].data!;
  assert.equal(data.status, "succeeded"); assert.equal((data.policy as any).revision, "9007199254740993");
  assert.equal(JSON.stringify(data).includes(canary), false);
  h.evidenceReply.resolve(Buffer.alloc(0)); const result = await job.result;
  assert.equal(result.structuredContent.portfolioId, "p-1"); assert.equal(result.structuredContent.client.account_number, undefined);
  assert.equal(JSON.stringify(result).includes(canary), false); assert.equal(result._meta, undefined);
  assert.equal(result.content[0].text, JSON.stringify(result.structuredContent));
  assert.equal(closed, false); assert.equal(job.observation().closedAtMonotonicNs, undefined);
  assert.equal(job.completion().admission.eventId, h.events[0].eventId);
  h.rawClosed.resolve(); h.completionClosed.resolve(); await turns(); assert.equal(closed, false);
  h.evidenceClosed.resolve(); await job.closed; assert.equal(closed, true);
});

for (const outcome of [GovernanceOutcome.DENIED, GovernanceOutcome.REQUIRES_APPROVAL]) {
  test(`known decision ${outcome} emits honest denied evidence without upstream execution`, async t => {
    const h = harness(); t.after(() => h.cleanup()); const job = h.start() as any;
    const failure = assert.rejects(job.result, /compiled managed execution refused safely/);
    h.authorize(outcome, []); await turns();
    assert.equal(h.effects.includes("upstream"), false); assert.equal(h.events.length, 1);
    assert.equal(h.events[0].data!.status, "denied");
    assert.equal((h.events[0].data!.policy as any).outcome, outcome === GovernanceOutcome.DENIED ? "denied" : "requires_approval");
    h.evidenceReply.resolve(Buffer.alloc(0)); h.evidenceClosed.resolve(); await failure; await job.closed;
  });
}

for (const kind of ["missing", "text-fallback", "is-error", "resource", "proxy", "accessor", "oversize", "restriction", "upstream-error"]) {
  test(`unsafe output ${kind} never escapes and known authorization yields failed evidence`, async t => {
    const h = harness(); t.after(() => h.cleanup()); const job = h.start() as any;
    const failure = assert.rejects(job.result, /^Error: compiled managed execution refused safely$/); let hooks = 0;
    h.authorize(GovernanceOutcome.ALLOWED, kind === "restriction" ? ["total_value"] : []); await turns();
    let output: any = envelope();
    if (kind === "missing") output = { content: [] };
    if (kind === "text-fallback") output = { content: [{ type: "text", text: JSON.stringify(envelope().structuredContent) }] };
    if (kind === "is-error") output.isError = true;
    if (kind === "resource") output.structuredContent.portfolio_id = "another-portfolio";
    if (kind === "proxy") output = new Proxy(output, { ownKeys() { hooks++; throw Error(canary); } });
    if (kind === "accessor") Object.defineProperty(output, "structuredContent", { enumerable: true, get() { hooks++; throw Error(canary); } });
    if (kind === "oversize") output.structuredContent.extra = "x".repeat(262144);
    if (kind === "upstream-error") h.upstream.reject(Error(canary)); else h.upstream.resolve(output);
    await turns(); assert.equal(h.events.length, 1); assert.equal(h.events[0].data!.status, "failed");
    assert.equal((h.events[0].data!.sizes as any).output_bytes, 0); assert.equal(hooks, 0);
    assert.equal(JSON.stringify(h.events[0]).includes(canary), false);
    h.evidenceReply.resolve(Buffer.alloc(0)); h.rawClosed.resolve(); h.completionClosed.resolve(); h.evidenceClosed.resolve();
    await failure; await job.closed;
  });
}

test("authorization transport failure invents neither decision nor evidence", async t => {
  const h = harness(); t.after(() => h.cleanup()); const job = h.start() as any;
  h.auth.reject(Error(canary)); h.authClosed.resolve();
  await assert.rejects(job.result, /^Error: compiled managed execution refused safely$/); await job.closed;
  assert.equal(h.events.length, 0); assert.equal(job.completion(), undefined);
});

test("invalid canonical receipt blocks otherwise successful output and holds physical ownership", async t => {
  const h = harness(); t.after(() => h.cleanup()); const job = h.start() as any;
  h.authorize(); await turns(); h.upstream.resolve(envelope()); await turns();
  h.evidenceReply.resolve(Buffer.from([8, 2])); await assert.rejects(job.result, /^Error: compiled managed execution refused safely$/);
  let closed = false; void job.closed.then(() => { closed = true; }); await turns(); assert.equal(closed, false);
  h.rawClosed.resolve(); h.completionClosed.resolve(); h.evidenceClosed.resolve(); await job.closed;
});

test("failed filtering retains the measured structured source size but no successful output bytes", async t => {
  const h = harness(); t.after(() => h.cleanup()); const job = h.start();
  h.authorize(GovernanceOutcome.ALLOWED, ["total_value"]); await turns();
  const source = envelope(); h.upstream.resolve(source); await turns();
  assert.equal((h.events[0].data!.sizes as any).source_bytes, Buffer.byteLength(JSON.stringify(source.structuredContent)));
  assert.equal((h.events[0].data!.sizes as any).filtered_bytes, 0);
  h.evidenceReply.resolve(Buffer.alloc(0)); await assert.rejects(job.result);
  h.rawClosed.resolve(); h.completionClosed.resolve(); h.evidenceClosed.resolve(); await job.closed;
});
