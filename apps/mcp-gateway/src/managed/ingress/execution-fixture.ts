import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { GovernanceOutcome, ManagedCallAuthorizationDecisionSchema, ManagedCallCompletionSchema,
  ManagedCallCompletionReceiptSchema } from "@apex/contracts";
import { EventEnvelopeSchema } from "@apex/contracts/event";
import type { StageOwner } from "../bootstrap/stage-owner.js";
import { now } from "../bootstrap/runtime-materials/fixture.js";
import { deferred } from "../authority/business-testing.js";
import { AuthenticatedBusinessTransport } from "../authority/business-transport.js";
import { OwnedCallCoordinator } from "../call-owner.js";
import { ManagedEvidenceClient } from "../evidence/client.js";
import { CompiledManagedExecutor } from "../compiled-executor.js";

export function executionFixture(stage: StageOwner) {
  const original = { monotonicNs: 9007199254740993n, unixUs: now, resolutionNs: 1n,
    uncertaintyUs: 7n, source: "synthetic stable anchor" };
  let at = { ...original };
  const clock = { now: () => ({ ...at }) }, mono = () => at.monotonicNs;
  const { config, binding } = stage.documents;
  const preparation = { config, binding, evidenceAgentId: "managed-evidence", dataClassification: "confidential", clock };
  const profile = { binding, policyId: config.spec!.governanceBinding!.policyId,
    evidenceAgentId: preparation.evidenceAgentId, dataClassification: preparation.dataClassification };
  const auth = deferred<Uint8Array>(), authClosed = deferred<void>();
  const upstream = deferred<unknown>(), rawClosed = deferred<void>();
  const evidenceReply = deferred<Uint8Array>(), evidenceClosed = deferred<void>(), completionClosed = deferred<void>();
  for (const p of [auth.promise, upstream.promise, evidenceReply.promise]) void p.catch(() => {});
  const effects: string[] = [], events: ReturnType<typeof fromBinary<typeof EventEnvelopeSchema>>[] = [];
  const business = new AuthenticatedBusinessTransport({ ...profile, monotonicNowNs: mono, channel: {
    start(path, bytes) {
      if (path.endsWith("AuthorizeManagedCall")) {
        effects.push("authorize");
        return { result: auth.promise, closed: authClosed.promise, cancel() { effects.push("cancel-auth"); } };
      }
      effects.push("complete"); const request = fromBinary(ManagedCallCompletionSchema, bytes);
      return { result: Promise.resolve(toBinary(ManagedCallCompletionReceiptSchema, create(ManagedCallCompletionReceiptSchema,
        { binding: request.binding, admissionId: request.admissionId, callId: request.callId, released: true }))),
        closed: completionClosed.promise, cancel() {} };
    },
  } });
  const raw = new OwnedCallCoordinator({ ...profile, business, monotonicNowNs: mono,
    grants: { snapshot: () => ({ mode: "serve", admitting: true, epoch: 23n, activeCalls: 0 }),
      tryBeginCall() { return { isCurrent: () => true, release() { effects.push("released"); } }; } },
    routes: new Map([["portfolio.read", { toolName: "portfolio.read", session: { call(_id, _name, _input, context) {
      context.beforeWrite(); effects.push("upstream");
      return { result: upstream.promise, closed: rawClosed.promise, cancel() { effects.push("cancel-upstream"); }, metadata: () => ({}) };
    } } }]]) });
  const evidence = new ManagedEvidenceClient({ start(bytes) {
    events.push(fromBinary(EventEnvelopeSchema, bytes));
    return { result: evidenceReply.promise, closed: evidenceClosed.promise, cancel() { effects.push("cancel-evidence"); } };
  } }, mono);
  const executor = new CompiledManagedExecutor({ preparation, calls: raw, evidence });
  return { original, clock, executor, effects, events, rawClosed, evidenceReply, evidenceClosed, completionClosed, upstream,
    advance(ns: bigint) { at = { ...original, monotonicNs: original.monotonicNs + ns, unixUs: original.unixUs + ns / 1000n }; },
    authorize() { auth.resolve(toBinary(ManagedCallAuthorizationDecisionSchema, create(ManagedCallAuthorizationDecisionSchema, {
      decision: { outcome: GovernanceOutcome.ALLOWED, policyId: profile.policyId, reasonCode: "policy.decision",
        fieldRestrictions: ["client.account_number", "client.tax_id", "positions.cost_basis"] },
      policyRevision: 9007199254740993n, admissionId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e06",
      epoch: 23n, validForUs: 10000000n, expiresAtUnixUs: 1n }))); authClosed.resolve(); },
    async cleanup() {
      auth.reject(Error("synthetic failure")); upstream.reject(Error("synthetic failure")); evidenceReply.reject(Error("synthetic failure"));
      authClosed.resolve(); rawClosed.resolve(); evidenceClosed.resolve(); completionClosed.resolve();
      await executor.close(); await raw.close(); await evidence.close();
    },
  };
}
