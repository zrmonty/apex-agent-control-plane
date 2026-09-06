import assert from "node:assert/strict";
import { test } from "node:test";
import { CompiledCallPreparer } from "./call-preparation.js";
import { fixture } from "./call-preparation/fixture.js";

test("published portfolio call prepares exact protected bigint binding and fresh frozen identities", () => {
  const f = fixture(), preparer = new CompiledCallPreparer(f.options), input = { portfolioId: "retirement-1" };
  const prepared = preparer.prepare(f.identity, "portfolio.read", input, f.original, f.deadline);
  assert.deepEqual(prepared.input, input); assert.notEqual(prepared.input, input);
  assert(Object.isFrozen(prepared.input)); assert(Object.isFrozen(prepared.request.caller));
  assert.equal(prepared.request.caller!.principal, f.identity.subject);
  assert.equal(prepared.request.caller!.agentId, "managed-evidence");
  assert.equal(prepared.request.classification, "confidential");
  assert.equal(prepared.request.generation, 9007199254740993n);
  assert.equal(prepared.request.binding!.target!.fencingToken, 9007199254740995n);
  assert.equal(prepared.startedAtMonotonicNs, f.original.monotonicNs);
  assert.deepEqual(prepared.originalSnapshot, f.original);
  assert.equal(prepared.trace.startedAtUnixUs, 9007199254740993n);
  assert.match(prepared.request.callId, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.match(prepared.trace.traceId, /^[0-9a-f]{32}$/); assert.match(prepared.trace.spanId, /^[0-9a-f]{16}$/);
  assert.equal(prepared.request.argumentsHash, "e41fc02384b2a7bc84fde1a3d97442a08cd473d1c6183a82af95f1d4b5985892");
  assert.equal(prepared.request.resource, "portfolio:sha256:2fd0b34008988a165487c03481438debfe65fe5681b1b48a5dc65c699bf05784");
});
test("trusted clock callback cannot change the already copied verified subject", () => {
  const f = fixture();
  const before = f.identity.subject;
  const preparer = new CompiledCallPreparer({ ...f.options, clock: { now() {
    f.identity.subject = "different-actor"; return { ...f.original };
  } } });
  const result = preparer.prepare(f.identity, "portfolio.read", { portfolioId: "retirement-1" }, f.original, f.deadline);
  assert.equal(result.request.caller!.principal, before);
});
test("portfolio identifier with terminal newline is not a canonical identifier", () => {
  const f = fixture(), preparer = new CompiledCallPreparer(f.options);
  assert.throws(() => preparer.prepare(f.identity, "portfolio.read", { portfolioId: "retirement-1\n" }, f.original, f.deadline));
});
