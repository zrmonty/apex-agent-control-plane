// Deterministic external HTTP/RPC boundaries; the root, grant/business codecs,
// MCP sessions, wire parser, call owner, executor and evidence client are real.
import assert from "node:assert/strict";
import type { TestContext } from "node:test";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { ManagedDeploymentRenewalSchema, ManagedDeploymentGrantSchema, ManagedGrantMode, GovernanceOutcome,
  ManagedCallAuthorizationRequestSchema, ManagedCallAuthorizationDecisionSchema,
  ManagedCallCompletionSchema, ManagedCallCompletionReceiptSchema,
  RuntimeNetworkInspectionRequestSchema, RuntimeNetworkInspectionResponseSchema,
  ManagedPolicyRequestSchema, ManagedPolicySnapshotSchema } from "@apex/contracts";
import { EventEnvelopeSchema, EvidenceAdmissionProbeRequestSchema, EvidenceAdmissionProbeResponseSchema } from "@apex/contracts/event";
import { materialFixture, now } from "../bootstrap/runtime-materials/fixture.js";
import { jwks } from "../bootstrap/inbound-verifier/fixture.js";
import { createManagedRuntimeMaterials, disposeRuntimeMaterials } from "../bootstrap/runtime-materials.js";
import { disposeStageOwner } from "../bootstrap/stage-owner.js";
import { FakeTime, deferred } from "../stage-reader/fixture.js";
import { OwnedHttpClient, type OwnedHttpRequest, type OwnedHttpResponse } from "../guard/http-owner.js";
import { envelope } from "../compiled-executor/testing.js";
import { startCore } from "./job.js";
import { startApplication, type ManagedApplication } from "../application/owner.js";
import type { RuntimeCoreHandle } from "./types.js";
import { dependencyUnavailable } from "../authority/dependency-failure.js";

export const tick = async () => { for (let i = 0; i < 100; i++) await Promise.resolve(); };
export const admissionId = "018f3d4a-8b9c-7000-8000-000000000999";
export async function servingFixture(t: TestContext, options: { prepareOnly?: boolean; skipReadiness?: boolean;
  application?: boolean; networkUnavailable?: boolean; startupDelayMs?: number } = {}) {
  const f = await materialFixture(f => {
    Object.assign(f.env, { APEX_MCP_MANAGED_BOOTSTRAP: "sealed-stage-v2", APEX_MCP_NETWORK_PROFILE: "isolated-bridge-v1",
      APEX_MCP_GUARD_ADDRESS: "10.96.0.3", APEX_MCP_NETWORK_BINDING_SHA256: "b".repeat(64) });
    f.stage.files["inbound-jwks"] = jwks();
  });
  let materials: ReturnType<typeof createManagedRuntimeMaterials>;
  const time = new FakeTime();
  const httpOwners = new Map<OwnedHttpClient, { id: number; jobs: Set<{ cancel(): void; closed: Promise<void> }>; closed: boolean }>();
  const requests: { owner: number; method: string }[] = [];
  const heldReplies: (() => void)[] = [], heldClosures: (() => void)[] = [];
  let holdCalls = false, holdCatalog = false, holdPhysical = false, holdOwnerClose = false;
  const ownerClosures: (() => void)[] = [];
  const tool = { name: "portfolio.read", inputSchema: { type: "object", properties: { portfolioId: { type: "string" } },
    required: ["portfolioId"], additionalProperties: false }, outputSchema: { type: "object" } };
  t.mock.method(OwnedHttpClient.prototype, "start", function (this: OwnedHttpClient, input: OwnedHttpRequest) {
    let owner = httpOwners.get(this);
    if (!owner) { owner = { id: httpOwners.size + 1, jobs: new Set(), closed: false }; httpOwners.set(this, owner); }
    assert.equal(owner.closed, false); input.beforeWrite();
    const rpc = input.body ? JSON.parse(Buffer.from(input.body).toString()) as { id: string; method: string } : undefined;
    const method = rpc?.method ?? input.method;
    if (method !== "initialize") assert.equal(input.sessionId, `session-${owner.id}`);
    requests.push({ owner: owner.id, method });
    const result = deferred<OwnedHttpResponse>(), closed = deferred<void>();
    void result.promise.catch(() => {});
    let answered = false, released = false;
    const physicalHeld = holdPhysical && method === "tools/call";
    const release = () => { if (!released) { released = true; owner!.jobs.delete(job); closed.resolve(); } };
    if (physicalHeld) heldClosures.push(release);
    const cancel = () => { if (!answered) result.reject(Error("cancelled HTTP fixture")); if (!physicalHeld) release(); };
    const job = { cancel, closed: closed.promise }; owner.jobs.add(job);
    const reply = () => {
      answered = true;
      const value = method === "initialize" ? { protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: "fixture", version: "1" } }
        : method === "tools/list" ? { tools: [tool] } : envelope();
      const empty = method === "notifications/initialized" || method === "DELETE";
      result.resolve({ status: empty ? 204 : 200, sessionId: `session-${owner!.id}`, contentType: "application/json",
        body: { async *[Symbol.asyncIterator]() {
          if (!empty) yield Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: rpc!.id, result: value }));
        } } });
    };
    if (holdCalls && method === "tools/call" || holdCatalog && method === "tools/list") heldReplies.push(reply); else reply();
    return { result: result.promise, closed: closed.promise, cancel };
  });
  t.mock.method(OwnedHttpClient.prototype, "close", function (this: OwnedHttpClient) {
    const owner = httpOwners.get(this); if (!owner) return Promise.resolve();
    owner.closed = true;
    const jobs = [...owner.jobs]; jobs.forEach(job => job.cancel());
    const held = deferred<void>();
    if (holdOwnerClose && owner.id !== 1) ownerClosures.push(() => held.resolve()); else held.resolve();
    return Promise.all([...jobs.map(job => job.closed), held.promise]).then(() => undefined);
  });
  const controlClosed = deferred<void>(), revoked = deferred<void>();
  let renewals = 0, controlCancelled = false, fatals = 0, authHeld = false, failCompletion = false;
  let authorization: (() => void) | undefined;
  const authorizations: ReturnType<typeof fromBinary<typeof ManagedCallAuthorizationRequestSchema>>[] = [];
  const completions: ReturnType<typeof fromBinary<typeof ManagedCallCompletionSchema>>[] = [];
  const events: ReturnType<typeof fromBinary<typeof EventEnvelopeSchema>>[] = [];
  const grantRequests: ReturnType<typeof fromBinary<typeof ManagedDeploymentRenewalSchema>>[] = [];
  const policies: ReturnType<typeof fromBinary<typeof ManagedPolicyRequestSchema>>[] = [];
  const probes: ReturnType<typeof fromBinary<typeof EvidenceAdmissionProbeRequestSchema>>[] = [];
  const networkProbes: ReturnType<typeof fromBinary<typeof RuntimeNetworkInspectionRequestSchema>>[] = [];
  const networkClosures: (() => void)[] = [], networkReplies: (() => void)[] = [];
  let holdNetworkReply = false, holdNetworkClosure = false, networkHash = f.stageOwner.network!.bindingSha256;
  let networkUnavailable = options.networkUnavailable ?? false;
  const probeClosures: (() => void)[] = [], probeReplies: (() => void)[] = [];
  let holdProbeReply = false, holdProbeClosure = false, probeReady = true;
  const policyClosures: (() => void)[] = [], policyReplies: (() => void)[] = [];
  let holdPolicyReply = false, holdPolicyClosure = false, policyId = "ria-read-v1", policyUnavailable = false;
  const responses = {
    NETWORK: (bytes: Uint8Array) => bytes, EVIDENCE: (bytes: Uint8Array) => bytes, GOVERNANCE: (bytes: Uint8Array) => bytes,
  };
  const authority = { start(method: string, bytes: Uint8Array) {
    assert.equal(controlCancelled, false, "completion must retain the authenticated control channel");
    if (method.endsWith("GetManagedPolicy")) {
      const request = fromBinary(ManagedPolicyRequestSchema, bytes); policies.push(request);
      const result = deferred<Uint8Array>(), closed = deferred<void>();
      const reply = () => policyUnavailable ? result.reject(dependencyUnavailable("policy unavailable fixture")) :
        result.resolve(responses.GOVERNANCE(toBinary(ManagedPolicySnapshotSchema, create(ManagedPolicySnapshotSchema, {
        binding: request.binding, nonce: request.nonce, policyId, revision: 9007199254740993n,
      }))));
      if (holdPolicyReply) policyReplies.push(reply); else reply();
      if (holdPolicyClosure) policyClosures.push(() => closed.resolve()); else closed.resolve();
      return { result: result.promise, closed: closed.promise, cancel() { result.reject(Error("cancelled policy fixture")); } };
    }
    if (method === "/apex.v1.ManagedNetworkReadiness/Check") {
      const request = fromBinary(RuntimeNetworkInspectionRequestSchema, bytes); networkProbes.push(request);
      const result = deferred<Uint8Array>(), closed = deferred<void>();
      const reply = () => networkUnavailable ? result.reject(dependencyUnavailable("network inspection busy fixture")) :
        result.resolve(responses.NETWORK(toBinary(RuntimeNetworkInspectionResponseSchema, create(RuntimeNetworkInspectionResponseSchema, {
        schemaVersion: request.schemaVersion, binding: request.binding, nonce: request.nonce,
        networkBindingSha256: networkHash, gatewayProcessSha256: "d".repeat(64), guardProcessSha256: "e".repeat(64),
        confined: true, validForUs: 10_000_000n,
      }))));
      if (holdNetworkReply) networkReplies.push(reply); else reply();
      if (holdNetworkClosure) networkClosures.push(() => closed.resolve()); else closed.resolve();
      return { result: result.promise, closed: closed.promise, cancel() { result.reject(Error("cancelled network fixture")); } };
    }
    if (method.endsWith("RenewDeployment")) {
      const request = fromBinary(ManagedDeploymentRenewalSchema, bytes); grantRequests.push(request); renewals++;
      return { result: Promise.resolve(toBinary(ManagedDeploymentGrantSchema, create(ManagedDeploymentGrantSchema, {
        binding: request.binding, nonce: request.nonce, renewalSequence: request.renewalSequence,
        decisionId: `018f3d4a-8b9c-7000-8000-${String(renewals).padStart(12, "0")}`, epoch: 1n,
        mode: options.prepareOnly ? ManagedGrantMode.PREPARE : ManagedGrantMode.SERVE, validForUs: 10_000_000n }))), closed: Promise.resolve(), cancel() {} };
    }
    if (method.endsWith("AuthorizeManagedCall")) {
      const request = fromBinary(ManagedCallAuthorizationRequestSchema, bytes); authorizations.push(request);
      const result = deferred<Uint8Array>(), closed = deferred<void>();
      const reply = () => { result.resolve(toBinary(ManagedCallAuthorizationDecisionSchema, create(ManagedCallAuthorizationDecisionSchema, {
        decision: { outcome: GovernanceOutcome.ALLOWED, policyId: "ria-read-v1", reasonCode: "policy.allowed", fieldRestrictions: [] },
        admissionId, epoch: 1n, policyRevision: 9007199254740993n, validForUs: 10_000_000n, expiresAtUnixUs: now + 10_000_000n })));
        closed.resolve(); };
      if (authHeld) authorization = reply; else reply();
      return { result: result.promise, closed: closed.promise, cancel() { result.reject(Error("cancelled authority fixture")); closed.resolve(); } };
    }
    assert.ok(method.endsWith("CompleteManagedCall"));
    const request = fromBinary(ManagedCallCompletionSchema, bytes); completions.push(request);
    return { result: failCompletion ? Promise.reject(Error("transient completion failure")) :
      Promise.resolve(toBinary(ManagedCallCompletionReceiptSchema, create(ManagedCallCompletionReceiptSchema, {
        binding: request.binding, admissionId: request.admissionId, callId: request.callId, released: true }))),
      closed: Promise.resolve(), cancel() {} };
  } };
  const clock = { now: () => ({ monotonicNs: time.now(), unixUs: now + time.now() / 1000n,
    resolutionNs: 1000n, source: "test high resolution clock", uncertaintyUs: 1n }) };
  const dependencies: Parameters<typeof startCore>[1] = {
    timers: time, unixMs: () => Number(now / 1000n) + Number(time.now() / 1_000_000n),
    control: () => ({ result: Promise.resolve({ authority, evidence: { start(bytes: Uint8Array) {
      events.push(fromBinary(EventEnvelopeSchema, bytes)); return { result: Promise.resolve(Buffer.alloc(0)), closed: Promise.resolve(), cancel() {} };
    }, startReadiness(bytes: Uint8Array) {
      assert.equal(controlCancelled, false);
      const request = fromBinary(EvidenceAdmissionProbeRequestSchema, bytes); probes.push(request);
      const result = deferred<Uint8Array>(), closed = deferred<void>();
      const reply = () => result.resolve(responses.EVIDENCE(toBinary(EvidenceAdmissionProbeResponseSchema, create(EvidenceAdmissionProbeResponseSchema, {
        schemaVersion: request.schemaVersion, requestNonce: request.requestNonce, workspaceId: request.workspaceId,
        namespaceId: request.namespaceId, agentId: request.agentId, ready: probeReady, validForUs: 10_000_000n,
      }))));
      if (holdProbeReply) probeReplies.push(reply); else reply();
      if (holdProbeClosure) probeClosures.push(() => closed.resolve()); else closed.resolve();
      return { result: result.promise, closed: closed.promise, cancel() { result.reject(Error("cancelled probe fixture")); } };
    } } }), closed: controlClosed.promise, revoked: revoked.promise,
    cancel() { controlCancelled = true; revoked.resolve(); controlClosed.resolve(); } }),
  };
  let handle!: RuntimeCoreHandle, application: ManagedApplication | undefined;
  let admitting = () => false, coreStarts = 0;
  if (options.application) {
    application = startApplication({ env: f.env, onFatal() { fatals++; } }, {
      clock, timers: time, bootstrap: () => { time.time += BigInt(options.startupDelayMs ?? 0) * 1000000n; return f.bootstrap; },
      core(input) { coreStarts++; materials = input.materials; return handle = startCore(input, dependencies); },
      health: async () => ({ lost: new Promise<void>(() => {}), close: async () => {} }),
      ingress(input) {
        admitting = input.isAdmitting;
        const closed = deferred<void>();
        return { result: Promise.resolve({ host: "10.96.0.2", port: 8080 }), closed: closed.promise,
          cancel: () => closed.resolve() };
      },
    });
    await tick(); assert.ok(handle, "application must compose its actual core");
  } else {
    materials = createManagedRuntimeMaterials(f.stageOwner, now);
    coreStarts++; handle = startCore({ stage: f.stageOwner, materials, clock, onFatal() { fatals++; } }, dependencies);
  }
  t.after(async () => {
    holdOwnerClose = false; application?.cancel(); handle.cancel(); heldClosures.forEach(release => release()); ownerClosures.forEach(release => release());
    probeClosures.forEach(release => release());
    networkClosures.forEach(release => release());
    policyClosures.forEach(release => release());
    await handle.closed; await application?.closed;
    disposeRuntimeMaterials(materials); disposeStageOwner(f.stageOwner); await f.bootstrap.closed;
  });
  const core = await handle.result;
  const timing = () => ({ startedAtMonotonicNs: time.now(), deadlineMonotonicNs: time.now() + 10_000_000_000n });
  if (!options.prepareOnly && !options.skipReadiness) assert.equal((await core.readiness.checkStartup()).ready, true);
  return { core, handle, application, admitting: () => admitting(), time, timing, requests, authorizations, completions, events, probes, networkProbes, policies, grantRequests, materials: materials!, stage: f.stageOwner,
    start() { const at = clock.now(); return core.executor.start({ subject: "operator:alice", proxyId: f.stageOwner.documents.config.proxyId,
      scopes: ["mcp:tools"] }, "portfolio.read", { portfolioId: "p-1" }, at, at.monotonicNs + 10_000_000_000n); },
    holdCalls() { holdCalls = true; }, holdCatalog() { holdCatalog = true; }, holdPhysical() { holdPhysical = true; },
    holdOwnerClose() { holdOwnerClose = true; }, releaseOwners() { holdOwnerClose = false; ownerClosures.splice(0).forEach(release => release()); },
    reply() { assert.ok(heldReplies.length); heldReplies.splice(0).forEach(reply => reply()); },
    releasePhysical() { heldClosures.splice(0).forEach(release => release()); },
    holdAuthorization() { authHeld = true; }, authorize() { assert.ok(authorization); authorization(); },
    failCompletion(value: boolean) { failCompletion = value; },
    holdProbeReply() { holdProbeReply = true; }, holdProbeClosure() { holdProbeClosure = true; },
    replyProbes() { probeReplies.splice(0).forEach(reply => reply()); }, releaseProbes() { probeClosures.splice(0).forEach(release => release()); },
    refuseProbe(value = true) { probeReady = !value; },
    holdPolicyReply() { holdPolicyReply = true; }, holdPolicyClosure() { holdPolicyClosure = true; },
    replyPolicies() { policyReplies.splice(0).forEach(reply => reply()); },
    releasePolicies() { policyClosures.splice(0).forEach(release => release()); },
    wrongPolicy() { policyId = "wrong-policy"; },
    policyUnavailable(value: boolean) { policyUnavailable = value; },
    holdNetworkReply() { holdNetworkReply = true; }, holdNetworkClosure() { holdNetworkClosure = true; },
    replyNetwork() { networkReplies.splice(0).forEach(reply => reply()); },
    releaseNetwork() { networkClosures.splice(0).forEach(release => release()); },
    wrongNetwork() { networkHash = "c".repeat(64); },
    networkUnavailable(value: boolean) { networkUnavailable = value; },
    response(kind: keyof typeof responses, rewrite: (bytes: Uint8Array) => Uint8Array) { responses[kind] = rewrite; },
    revokeControl() { controlCancelled = true; revoked.resolve(); controlClosed.resolve(); },
    stats: () => ({ fatals, controlCancelled, coreStarts, owners: httpOwners.size, openOwners: [...httpOwners.values()].filter(o => !o.closed).length }) };
}
