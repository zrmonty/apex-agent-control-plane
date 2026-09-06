import assert from "node:assert/strict";
import { test } from "node:test";
import { create, toBinary } from "@bufbuild/protobuf";
import { GovernanceOutcome, ManagedCallAuthorizationDecisionSchema, ManagedCallCompletionReceiptSchema,
  ManagedPolicySnapshotSchema, ProxyApprovalSchema, type ManagedCallAuthorizationRequest } from "@apex/contracts";
import { AuthenticatedBusinessTransport } from "./business-transport.js";
import type { BusinessTransportOptions } from "./business-types.js";
import { admissionId, allowed, binding, callId, context, harness, metadata, nonce, policy, receipt, request } from "./business-testing.js";

const refusal = { message: "managed business refused safely" };
const max = 18_446_744_073_709_551_615n;
function client(h = harness(), extra: Partial<BusinessTransportOptions> = {}) {
  return new AuthenticatedBusinessTransport({ ...metadata, channel: h.channel, monotonicNowNs: () => 1001n, ...extra });
}
for (const outcome of [GovernanceOutcome.DENIED, GovernanceOutcome.REQUIRES_APPROVAL]) {
  test(`nonpermitted outcome ${outcome} preserves policy metadata without admission`, async () => {
    const message = create(ManagedCallAuthorizationDecisionSchema, {
      decision: { ...allowed().decision!, outcome }, policyRevision: max,
    });
    const h = harness(toBinary(ManagedCallAuthorizationDecisionSchema, message));
    const value = await client(h).startAuthorization(request(), context).result;
    assert.deepEqual(value, { outcome: outcome === GovernanceOutcome.DENIED ? "denied" : "requires_approval",
      policyId: metadata.policyId, reasonCode: "policy.allowed", policyRevision: max, fieldRestrictions: ["ssn"] });
    assert.ok(Object.isFrozen(value)); assert.ok(Object.isFrozen(value.fieldRestrictions));
    assert.equal("admissionId" in value, false); h.closure.resolve();
  });
}
test("policy and allowed revisions retain u64::MAX exactly", async () => {
  const a = harness(toBinary(ManagedCallAuthorizationDecisionSchema, { ...allowed(), policyRevision: max }));
  assert.equal((await client(a).startAuthorization(request(), context).result).policyRevision, max);
  const p = harness(toBinary(ManagedPolicySnapshotSchema, { ...policy(), revision: max }));
  assert.equal((await client(p).startPolicy(nonce).result).revision, max);
  a.closure.resolve(); p.closure.resolve();
});

const authorizationMutations: Array<[string, (value: ReturnType<typeof allowed>) => void]> = [
  ["missing decision", x => { x.decision = undefined; }],
  ["default outcome", x => { x.decision!.outcome = 0; }],
  ["unknown outcome", x => { x.decision!.outcome = 99 as GovernanceOutcome; }],
  ["wrong policy", x => { x.decision!.policyId = "wrong"; }],
  ["empty policy", x => { x.decision!.policyId = ""; }],
  ["zero revision", x => { x.policyRevision = 0n; }],
  ["missing admission", x => { x.admissionId = ""; }],
  ["UUIDv4 admission", x => { x.admissionId = admissionId.replace("-7d", "-4d"); }],
  ["uppercase admission", x => { x.admissionId = admissionId.toUpperCase(); }],
  ["zero epoch", x => { x.epoch = 0n; }],
  ["different epoch", x => { x.epoch++; }],
  ["zero Unix expiry", x => { x.expiresAtUnixUs = 0n; }],
  ["zero interval", x => { x.validForUs = 0n; }],
  ["oversize interval", x => { x.validForUs = 10_000_001n; }],
  ["approval payload", x => { x.approval = create(ProxyApprovalSchema); }],
  ["denial with admission", x => { x.decision!.outcome = GovernanceOutcome.DENIED; }],
  ["approval required with admission", x => { x.decision!.outcome = GovernanceOutcome.REQUIRES_APPROVAL; }],
  ["empty reason", x => { x.decision!.reasonCode = ""; }],
  ["oversize reason", x => { x.decision!.reasonCode = "r".repeat(257); }],
  ["oversize restriction", x => { x.decision!.fieldRestrictions = ["r".repeat(257)]; }],
  ["too many restrictions", x => { x.decision!.fieldRestrictions = Array(129).fill("a"); }],
  ["invalid restriction", x => { x.decision!.fieldRestrictions = ["a..b"]; }],
];
for (const [name, mutate] of authorizationMutations) test(`authorization refuses ${name}`, async () => {
  const message = allowed(); mutate(message);
  const bytes = toBinary(ManagedCallAuthorizationDecisionSchema, create(ManagedCallAuthorizationDecisionSchema, message));
  const h = harness(bytes), exchange = client(h).startAuthorization(request(), context);
  await assert.rejects(exchange.result, refusal);
  assert.equal(h.cancellations, 1); assert.equal(exchange.closed, h.closure.promise); h.closure.resolve();
});

for (const field of ["admissionId", "epoch", "expiresAtUnixUs", "validForUs"] as const) {
  test(`denial refuses isolated contradictory ${field}`, async () => {
    const value = create(ManagedCallAuthorizationDecisionSchema, {
      decision: { ...allowed().decision!, outcome: GovernanceOutcome.DENIED }, policyRevision: 1n,
      [field]: field === "admissionId" ? admissionId : 1n,
    });
    const h = harness(toBinary(ManagedCallAuthorizationDecisionSchema, value));
    await assert.rejects(client(h).startAuthorization(request(), context).result, refusal); h.closure.resolve();
  });
}

for (const field of Object.keys(binding) as Array<keyof typeof binding>) {
  test(`policy, completion and outgoing authorization reject changed binding ${field}`, async () => {
    const modified = { ...binding, [field]: typeof binding[field] === "bigint" ? 9n :
      field.endsWith("Hash") ? "f".repeat(64) : field.endsWith("Id") && field !== "workspaceId" && field !== "namespaceId"
        ? "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e09" : "different" };
    // Use the existing binding mapping, never a second local wire definition.
    const { wireBinding } = await import("./grant-transport.js");
    const p = harness(toBinary(ManagedPolicySnapshotSchema, { ...policy(), binding: create(ManagedPolicySnapshotSchema,
      { binding: wireBinding(modified) }).binding }));
    await assert.rejects(client(p).startPolicy(nonce).result, refusal); p.closure.resolve();
    const r = receipt(); r.binding = create(ManagedCallCompletionReceiptSchema, { binding: wireBinding(modified) }).binding;
    const c = harness(toBinary(ManagedCallCompletionReceiptSchema, r));
    await assert.rejects(client(c).startCompletion(admissionId, callId).result, refusal); c.closure.resolve();
    const h = harness(), input = request(); input.binding = r.binding;
    assert.throws(() => client(h).startAuthorization(input, context), refusal); assert.equal(h.sent.length, 0);
  });
}
for (const [name, patch] of [
  ["missing binding", { binding: undefined }], ["missing target", { binding: { ...policy().binding!, target: undefined } }],
  ["short nonce", { nonce: Buffer.alloc(31) }], ["wrong nonce", { nonce: Buffer.alloc(32) }],
  ["long nonce", { nonce: Buffer.alloc(33) }], ["zero revision", { revision: 0n }],
  ["wrong policy", { policyId: "wrong" }], ["invalid restrictions", { fieldRestrictions: ["a..b"] }],
  ["too many restrictions", { fieldRestrictions: Array(129).fill("x") }],
] as const) test(`policy refuses ${name}`, async () => {
  const message = create(ManagedPolicySnapshotSchema, { ...policy(), ...patch,
    fieldRestrictions: "fieldRestrictions" in patch ? [...patch.fieldRestrictions] : policy().fieldRestrictions });
  const h = harness(toBinary(ManagedPolicySnapshotSchema, message));
  await assert.rejects(client(h).startPolicy(nonce).result, refusal); h.closure.resolve();
});
for (const [name, patch] of [
  ["missing binding", { binding: undefined }], ["wrong admission", { admissionId: callId }],
  ["wrong call", { callId: admissionId }], ["unreleased", { released: false }],
] as const) test(`completion refuses ${name}`, async () => {
  const h = harness(toBinary(ManagedCallCompletionReceiptSchema, { ...receipt(), ...patch }));
  await assert.rejects(client(h).startCompletion(admissionId, callId).result, refusal); h.closure.resolve();
});

const inputMutations: Array<[string, (x: ManagedCallAuthorizationRequest) => void]> = [
  ["scope", x => { x.scope!.workspaceId = "other"; }],
  ["namespace", x => { x.scope!.namespaceId = "other"; }],
  ["proxy", x => { x.proxyId = admissionId; }], ["revision", x => { x.revisionId = admissionId; }],
  ["generation", x => { x.generation++; }], ["number generation", x => { x.generation = 1 as unknown as bigint; }],
  ["call ID", x => { x.callId = "not-a-uuid"; }], ["call uppercase", x => { x.callId = callId.toUpperCase(); }],
  ["argument hash", x => { x.argumentsHash = "F".repeat(64); }],
  ["long argument hash", x => { x.argumentsHash = "e".repeat(65); }],
  ["undeclared tool", x => { x.toolAlias = "portfolio.write"; }],
  ["wrong action", x => { x.action = "write"; }], ["approval", x => { x.approvalId = admissionId; }],
  ["wrong evidence actor", x => { x.caller!.agentId = "user-selected"; }],
  ["wrong classification", x => { x.classification = "public"; }],
  ["numeric classification", x => { x.classification = 1 as unknown as string; }],
  ["missing caller", x => { x.caller = undefined; }], ["missing scope", x => { x.scope = undefined; }],
  ["empty principal", x => { x.caller!.principal = ""; }],
  ["long principal", x => { x.caller!.principal = "p".repeat(257); }],
  ["non-ASCII principal", x => { x.caller!.principal = "é"; }],
  ["invalid principal", x => { x.caller!.principal = "spiffe://apex//agent"; }],
  ["missing trace", x => { x.trace = undefined; }], ["empty trace", x => { x.trace!.traceId = ""; }],
  ["empty span", x => { x.trace!.spanId = ""; }], ["long span", x => { x.trace!.spanId = "s".repeat(257); }],
  ["long resource", x => { x.resource = "r".repeat(257); }], ["traversal resource", x => { x.resource = "a..b"; }],
  ["unbounded unknown fields", x => { x.$unknown = new Array(1_000_000); }],
  ["accessor", x => { Object.defineProperty(x, "resource", { get() { throw new Error("INPUT_CANARY"); } }); }],
];
for (const [name, mutate] of inputMutations) test(`outgoing ${name} dispatches zero RPCs`, () => {
  const h = harness(), input = request(); mutate(input);
  assert.throws(() => client(h).startAuthorization(input, context), refusal); assert.equal(h.sent.length, 0);
});

test("malformed runtime JS and constructor metadata fail statically before dispatch", () => {
  const h = harness(), c = client(h);
  for (const value of [null, undefined, [], 1, "REMOTE_CANARY", { toString() { throw new Error("INPUT_CANARY"); } }]) {
    assert.throws(() => c.startAuthorization(value as unknown as ManagedCallAuthorizationRequest, context), refusal);
    assert.throws(() => c.startPolicy(value as string), refusal);
    assert.throws(() => c.startCompletion(value as string, callId), refusal);
  }
  for (const patch of [{ policyId: "" }, { evidenceAgentId: "" }, { dataClassification: "READ" },
    { binding: null }, { monotonicNowNs: null }]) {
    assert.throws(() => client(h, patch as Partial<BusinessTransportOptions>), refusal);
  }
  for (const timing of [{ ...context, expectedEpoch: 0n }, { ...context, expectedEpoch: max + 1n },
    { ...context, startedAtMonotonicNs: -1n }, { ...context, startedAtMonotonicNs: 1002n }, null])
    assert.throws(() => c.startAuthorization(request(), timing as typeof context), refusal);
  assert.equal(h.sent.length, 0);
});

for (const bytes of [Buffer.from([0xff]), Buffer.alloc(16_385), Buffer.from("REMOTE_CANARY")]) {
  test(`malformed or oversized ${bytes.length}-byte reply refuses all methods`, async () => {
    for (const kind of ["policy", "authorize", "complete"]) {
      const h = harness(bytes), c = client(h);
      const exchange = kind === "policy" ? c.startPolicy(nonce) : kind === "authorize"
        ? c.startAuthorization(request(), context) : c.startCompletion(admissionId, callId);
      await assert.rejects(exchange.result, refusal); assert.equal(h.cancellations, 1); h.closure.resolve();
    }
  });
}

test("restriction count and aggregate byte bounds accept their exact limits", async () => {
  for (const length of [8192, 8193]) {
    const fields = Array<string>(128).fill("a".repeat(64));
    if (length === 8193) fields[127] += "b";
    const p = policy(); p.fieldRestrictions = fields;
    const a = allowed(); a.decision!.fieldRestrictions = fields;
    for (const kind of ["policy", "authorize"]) {
      const h = harness(kind === "policy" ? toBinary(ManagedPolicySnapshotSchema, p) : toBinary(ManagedCallAuthorizationDecisionSchema, a));
      const exchange = kind === "policy" ? client(h).startPolicy(nonce) : client(h).startAuthorization(request(), context);
      if (length === 8192) assert.equal((await exchange.result).fieldRestrictions.length, 128);
      else await assert.rejects(exchange.result, refusal);
      h.closure.resolve();
    }
  }
});

test("maximum identifier scalars and empty restrictions remain representable", async () => {
  const h = harness(), input = request();
  input.caller!.principal = "p".repeat(256); input.trace!.traceId = "t".repeat(256);
  input.trace!.spanId = "s".repeat(256); input.resource = "r".repeat(256);
  const exchange = client(h).startAuthorization(input, context), value = allowed();
  value.decision!.fieldRestrictions = [];
  h.result.resolve(toBinary(ManagedCallAuthorizationDecisionSchema, value));
  const decision = await exchange.result;
  assert.deepEqual(decision.fieldRestrictions, []);
  if (decision.outcome === "allowed") assert.equal(decision.submittedRequest.resource, input.resource);
  assert.ok(h.sent[0].bytes.length <= 16_384); h.closure.resolve();
});

test("unknown caller arrays and accessors are rejected before their contents are read", () => {
  const h = harness(), input = request(); let traversed = 0;
  const unknown = new Array(1_000_000);
  Object.defineProperty(unknown, "0", { get() { traversed++; throw new Error("ARRAY_CANARY"); } });
  input.caller!.$unknown = unknown;
  assert.throws(() => client(h).startAuthorization(input, context), refusal);
  const next = request();
  Object.defineProperty(next.caller, "principal", { get() { traversed++; throw new Error("GETTER_CANARY"); } });
  assert.throws(() => client(h).startAuthorization(next, context), refusal);
  assert.equal(traversed, 0); assert.equal(h.sent.length, 0);
});
