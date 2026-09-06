import assert from "node:assert/strict";
import { test } from "node:test";
import { toBinary, fromBinary } from "@bufbuild/protobuf";
import { ManagedCallAuthorizationRequestSchema } from "@apex/contracts";
import { CompiledCallPreparer, type CallPreparationOptions } from "./call-preparation.js";
import { fixture } from "./call-preparation/fixture.js";
import { canonicalizeJson, sha256CanonicalJson } from "../live/canonical.js";
import type { InboundIdentity } from "./auth.js";
import type { ClockSnapshot } from "../telemetry/clock.js";
const refused = /^Error: managed call preparation refused safely$/;

test("canonical accepted input has fixed bytes/hash independent of object representation", () => {
  const f = fixture(), p = new CompiledCallPreparer(f.options);
  const first = p.prepare(f.identity, "portfolio.read", { portfolioId: "retirement-1" }, f.original, f.deadline);
  const second = p.prepare(f.identity, "portfolio.read", Object.assign(Object.create(null), { portfolioId: "retirement-1" }), f.original, f.deadline);
  assert.deepEqual(first.input, second.input);
  assert.equal(canonicalizeJson(first.input), '{"portfolioId":"retirement-1"}');
  assert.equal(first.request.argumentsHash, "e41fc02384b2a7bc84fde1a3d97442a08cd473d1c6183a82af95f1d4b5985892");
  assert.equal(sha256CanonicalJson(second.input), first.request.argumentsHash);
});
test("full generated request survives wire roundtrip and is deeply immutable", () => {
  const f = fixture(), p = new CompiledCallPreparer(f.options);
  const prepared = p.prepare(f.identity, "portfolio.read", { portfolioId: "p" }, f.original, f.deadline);
  const encoded = toBinary(ManagedCallAuthorizationRequestSchema, prepared.request);
  assert.deepEqual(fromBinary(ManagedCallAuthorizationRequestSchema, encoded), prepared.request);
  function frozen(value: unknown): void {
    if (value && typeof value === "object") { assert(Object.isFrozen(value)); for (const child of Object.values(value)) frozen(child); }
  }
  frozen(prepared);
  assert.equal(prepared.request.approvalId, "");
  assert.equal(prepared.request.trace!.traceId, prepared.trace.traceId);
  assert.equal(prepared.request.trace!.spanId, prepared.trace.spanId);
  assert.equal(prepared.request.callId, prepared.trace.callId);
  assert.throws(() => { prepared.request.caller!.principal = "changed"; }, TypeError);
  assert.throws(() => { prepared.request.binding!.target!.generation = 1n; }, TypeError);
});
test("fresh calls never reuse startup/user trace IDs, each other, or span ID as trace ID", () => {
  const f = fixture(), p = new CompiledCallPreparer(f.options), seen = new Set<string>();
  for (let i = 0; i < 20; i++) {
    const result = p.prepare(f.identity, "portfolio.read", { portfolioId: "p" }, f.original, f.deadline);
    for (const value of [result.request.callId, result.trace.traceId, result.trace.spanId]) {
      assert(!seen.has(value)); seen.add(value); assert(!/^0+$/.test(value));
    }
  }
});
test("input and original data are copied before clock callbacks; constructor profile is detached", () => {
  const f = fixture(), input = { portfolioId: "p" }, original = { ...f.original };
  const options = { ...f.options, binding: { ...f.options.binding }, clock: { now() {
    input.portfolioId = "other"; original.unixUs = 1n; options.evidenceAgentId = "other";
    options.binding.fencingToken = 1n; return { ...f.original };
  } } };
  const p = new CompiledCallPreparer(options), result = p.prepare(f.identity, "portfolio.read", input, original, f.deadline);
  assert.equal(result.input.portfolioId, "p"); assert.equal(result.originalSnapshot.unixUs, f.original.unixUs);
  assert.equal(result.request.caller!.agentId, "managed-evidence");
  assert.equal(result.request.binding!.target!.fencingToken, 9007199254740995n);
});
test("active configuration/binding/clock/options refuse without evaluating traps", () => {
  const f = fixture(); let entered = 0;
  const active = <T extends object>(value: T) => new Proxy(value, {
    get() { entered++; throw Error(); }, getPrototypeOf() { entered++; throw Error(); },
    ownKeys() { entered++; throw Error(); }, getOwnPropertyDescriptor() { entered++; throw Error(); },
  });
  const accessor = (value: object, field: string) => Object.defineProperty({ ...value }, field,
    { enumerable: true, get() { entered++; throw Error(); } });
  for (const options of [active(f.options), { ...f.options, config: active(f.options.config) },
    { ...f.options, binding: active(f.options.binding) }, { ...f.options, clock: active(f.options.clock) },
    accessor(f.options, "evidenceAgentId"), { ...f.options, binding: accessor(f.options.binding, "workspaceId") },
    { ...f.options, clock: accessor(f.options.clock, "now") }]) {
    assert.throws(() => new CompiledCallPreparer(options as CallPreparationOptions), refused);
  }
  assert.equal(entered, 0);
});
test("passive data validation rejects active nested input, identity and original snapshots before clock reads", () => {
  const f = fixture(); let entered = 0, clockReads = 0;
  const p = new CompiledCallPreparer({ ...f.options, clock: { now() { clockReads++; return f.original; } } });
  const active = <T extends object>(value: T) => new Proxy(value, { get() { entered++; throw Error(); },
    getPrototypeOf() { entered++; throw Error(); }, ownKeys() { entered++; throw Error(); } });
  const getter = { get portfolioId() { entered++; return "p"; } };
  const hidden = Object.defineProperty({ portfolioId: "p" }, "extra", { get() { entered++; throw Error(); } });
  for (const input of [active({ portfolioId: "p" }), getter, hidden, { portfolioId: active({}) },
    Object.create({ portfolioId: "p" }), { portfolioId: "p", [Symbol()]: true }]) {
    assert.throws(() => p.prepare(f.identity, "portfolio.read", input, f.original, f.deadline), refused);
  }
  const scope = ["mcp:tools"]; Object.defineProperty(scope, "0", { get() { entered++; return "mcp:tools"; } });
  for (const identity of [active(f.identity), { ...f.identity, scopes: active([]) }, { ...f.identity, scopes: scope },
    { ...f.identity, get subject() { entered++; return "p"; } }]) {
    assert.throws(() => p.prepare(identity as InboundIdentity, "portfolio.read", { portfolioId: "p" }, f.original, f.deadline), refused);
  }
  for (const original of [active(f.original), { ...f.original, get monotonicNs() { entered++; return 0n; } }]) {
    assert.throws(() => p.prepare(f.identity, "portfolio.read", { portfolioId: "p" }, original as ClockSnapshot, f.deadline), refused);
  }
  assert.equal(entered, 0); assert.equal(clockReads, 0);
});
test("active or throwing local clock results remain static errors without exposing details", () => {
  for (const throws of [true, false]) {
    const f = fixture(); let getter = 0;
    const p = new CompiledCallPreparer({ ...f.options, clock: { now() {
      if (throws) throw new Error("SENSITIVE clock diagnostic");
      return { ...f.original, get source() { getter++; return "SENSITIVE"; } };
    } } });
    assert.throws(() => p.prepare(f.identity, "portfolio.read", { portfolioId: "p" }, f.original, f.deadline), refused);
    assert.equal(getter, 0);
  }
});
test("constructor has no caller-supplied random/id or endpoint override", () => {
  const f = fixture();
  for (const extra of [{ randomBytes() { return Buffer.alloc(32); } }, { callId: "override" }, { endpoint: "https://other.test" }]) {
    assert.throws(() => new CompiledCallPreparer({ ...f.options, ...extra }), refused);
  }
});
