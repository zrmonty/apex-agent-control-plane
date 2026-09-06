import assert from "node:assert/strict";
import test from "node:test";
import { fromBinary } from "@bufbuild/protobuf";
import { EventEnvelopeSchema, EventType, ActorType } from "@apex/contracts/event";
import { ManagedEvidenceBuilder, evidenceBytes, timestampUs } from "./builder.js";
import type { CallEvidence } from "./types.js";
import { metadata, admissionId } from "../authority/business-testing.js";
import { authorizationRequest } from "../authority/business-codec.js";
import { example } from "./testing.js";

test("canonical generated managed event preserves exact microseconds and paired event identity", () => {
  const source = example(); const prepared = new ManagedEvidenceBuilder(metadata).prepare(source);
  const envelope = fromBinary(EventEnvelopeSchema, evidenceBytes(prepared));
  assert.equal(envelope.type, EventType.TOOL); assert.equal(envelope.actor?.type, ActorType.AGENT);
  assert.equal(envelope.actor?.id, metadata.evidenceAgentId); assert.equal(envelope.integrity?.eventHash, prepared.eventHash);
  assert.equal(envelope.data?.observed_at_unix_us, "9007199254741000");
  assert.equal(envelope.data?.duration_us, "7"); assert.equal(envelope.data?.duration_ns, "7000");
  assert.equal(envelope.data?.linked_event_id, source.linkedEventId); assert.equal(envelope.data?.generation, metadata.binding.generation.toString());
  assert.equal(envelope.timestamp, "2255-06-05T23:47:34.741000Z");
});

test("OTel trace stays in the canonical envelope trace_id without a second opaque payload copy", () => {
  const prepared = new ManagedEvidenceBuilder(metadata).prepare(example());
  const envelope = fromBinary(EventEnvelopeSchema, evidenceBytes(prepared));
  assert.equal(envelope.traceId, "1".repeat(32));
  assert.equal(Object.hasOwn(envelope.data!, "otel_trace_id"), false);
});

for (const us of [1n, 7n, 999n]) test(`generated evidence preserves ${us}us above 2^53 and immutable retry bytes`, () => {
  const source = example(us), builder = new ManagedEvidenceBuilder(metadata), prepared = builder.prepare(source);
  const first = evidenceBytes(prepared), expected = Buffer.from(first); first.fill(0);
  source.request.caller!.principal = "changed-actor";
  assert.deepEqual(Buffer.from(evidenceBytes(prepared)), expected); assert.ok(Object.isFrozen(prepared));
  const decoded = fromBinary(EventEnvelopeSchema, expected);
  assert.equal(decoded.data?.duration_us, us.toString()); assert.equal(decoded.data?.duration_ns, (us * 1000n).toString());
  assert.equal(decoded.data?.observed_at_unix_us, (9_007_199_254_740_993n + us).toString());
});

test("missing measurement omits duration instead of inventing zero", () => {
  const source = example(); const stage = { ...source.stages[0], status: "missing" as const, durationNs: undefined };
  const prepared = new ManagedEvidenceBuilder(metadata).prepare({ ...source, stages: [stage] });
  const decoded = fromBinary(EventEnvelopeSchema, evidenceBytes(prepared));
  const stages = decoded.data!.stages as Array<Record<string, unknown>>;
  assert.equal(stages[0].status, "missing"); assert.equal(Object.hasOwn(stages[0], "duration_us"), false);
});

for (const invalid of ["event-newline", "span-newline", "missing-zero", "future-stage", "cross-clock", "own-admission", "duplicate-stage", "wrong-scope", "false-success"])
  test(`evidence refuses ${invalid} before producing sendable bytes`, () => {
    const source = example(); let value: CallEvidence = source;
    if (invalid === "event-newline") value = { ...source, eventId: source.eventId + "\n" };
    if (invalid === "span-newline") value = { ...source, stages: [{ ...source.stages[0], spanId: source.stages[0].spanId + "\n" }] };
    if (invalid === "missing-zero") value = { ...source, stages: [{ ...source.stages[0], status: "missing", durationNs: 0n }] };
    if (invalid === "future-stage") value = { ...source, stages: [{ ...source.stages[0], durationNs: 7001n }] };
    if (invalid === "cross-clock") value = { ...source, observed: { ...source.observed, source: "foreign-clock" } };
    if (invalid === "own-admission") value = { ...source, stages: [{ ...source.stages[0], name: "evidence.admission" }] };
    if (invalid === "duplicate-stage") value = { ...source, stages: [...source.stages, source.stages[0]] };
    if (invalid === "wrong-scope") source.request.scope!.namespaceId = "other";
    if (invalid === "false-success") value = { ...source, status: "succeeded" };
    assert.throws(() => new ManagedEvidenceBuilder(metadata).prepare(value), /managed call evidence refused safely/);
  });

test("ordinary object imitation cannot supply arbitrary event bytes", () => {
  assert.throws(() => evidenceBytes({ eventId: example().eventId, eventHash: "a".repeat(64) }), /managed call evidence refused safely/);
});

test("microsecond timestamp formatting respects the frozen four-digit UTC contract", () => {
  assert.equal(timestampUs(1n), "1970-01-01T00:00:00.000001Z");
  assert.equal(timestampUs(253_402_300_799_999_999n), "9999-12-31T23:59:59.999999Z");
  for (const value of [-1n, 253_402_300_800_000_000n]) assert.throws(() => timestampUs(value), /managed call evidence refused safely/);
});

test("completion admits only matching decision provenance and measured post-admission stages", () => {
  const source = example(), builder = new ManagedEvidenceBuilder(metadata);
  const submittedRequest = authorizationRequest(source.request, metadata).submittedRequest;
  const decision = { ...source.decision, outcome: "allowed" as const, admissionId, epoch: 1n,
    expiresAtUnixUs: 1n, validForUs: 7n, startDeadlineMonotonicNs: 8000n, submittedRequest };
  const completed: CallEvidence = { ...source, phase: "completion", decision, status: "succeeded",
    sourceBytes: 120, filteredBytes: 60, outputBytes: 90, removedFields: ["client.tax_id"],
    stages: [{ ...source.stages[0], name: "evidence.admission" }] };
  const event = fromBinary(EventEnvelopeSchema, evidenceBytes(builder.prepare(completed)));
  assert.equal(event.data?.admission_id, admissionId); assert.equal(event.data?.phase, "completion");
  assert.deepEqual(event.data?.removed_fields, ["client.tax_id"]);
  assert.throws(() => builder.prepare({ ...completed, decision: { ...decision,
    submittedRequest: { ...submittedRequest, callId: source.linkedEventId } } }), /managed call evidence refused safely/);
});

for (const invalid of ["overflow-revision", "zero-revision", "input-size", "negative-size", "fraction-size", "expanded-filter",
  "stages-cap", "unknown-stage", "unknown-parent", "self-parent", "unknown-property", "raw-output", "bad-policy", "bad-restriction"])
  test(`builder rejects ${invalid} with static diagnostics`, () => {
    const source = example(); const value: any = { ...source };
    if (invalid === "overflow-revision") value.decision = { ...source.decision, policyRevision: 1n << 64n };
    if (invalid === "zero-revision") value.decision = { ...source.decision, policyRevision: 0n };
    if (invalid === "input-size") value.inputBytes = 262145;
    if (invalid === "negative-size") value.outputBytes = -1;
    if (invalid === "fraction-size") value.outputBytes = 0.1;
    if (invalid === "expanded-filter") value.filteredBytes = 1;
    if (invalid === "stages-cap") value.stages = Array(33).fill(source.stages[0]);
    if (invalid === "unknown-stage") value.stages = [{ ...source.stages[0], name: "made-up-stage" }];
    if (invalid === "unknown-parent") value.stages = [{ ...source.stages[0], parentSpanId: "f".repeat(16) }];
    if (invalid === "self-parent") value.stages = [{ ...source.stages[0], parentSpanId: source.stages[0].spanId }];
    if (invalid === "unknown-property") value.secret = "private test canary";
    if (invalid === "raw-output") value.output = { raw: "private test canary" };
    if (invalid === "bad-policy") value.decision = { ...source.decision, policyId: "other-policy" };
    if (invalid === "bad-restriction") value.removedFields = ["client.tax_id", "client.tax_id"];
    assert.throws(() => new ManagedEvidenceBuilder(metadata).prepare(value), /^Error: managed call evidence refused safely$/);
  });

test("active inputs are refused without invoking getters or proxy traps", () => {
  let hooks = 0; const builder = new ManagedEvidenceBuilder(metadata);
  const active = { ...example(), get outputBytes(): number { hooks++; throw new Error("private canary"); } };
  const proxy = new Proxy(example(), { ownKeys() { hooks++; throw new Error("private canary"); } });
  for (const value of [active, proxy]) assert.throws(() => builder.prepare(value), /^Error: managed call evidence refused safely$/);
  assert.equal(hooks, 0);
});

for (const field of ["event", "linked", "self-linked", "admission"]) test(`UUID ${field} never coerces array input to a string`, () => {
  const source = example(); const value: any = { ...source };
  if (field === "event") value.eventId = [source.eventId];
  if (field === "linked") value.linkedEventId = [source.linkedEventId];
  if (field === "self-linked") value.linkedEventId = [source.eventId];
  if (field === "admission") {
    value.status = "succeeded";
    value.decision = { ...source.decision, outcome: "allowed", admissionId: [admissionId], epoch: 1n,
      expiresAtUnixUs: 1n, validForUs: 7n, startDeadlineMonotonicNs: 8000n,
      submittedRequest: authorizationRequest(source.request, metadata).submittedRequest };
  }
  assert.throws(() => new ManagedEvidenceBuilder(metadata).prepare(value), /^Error: managed call evidence refused safely$/);
});
