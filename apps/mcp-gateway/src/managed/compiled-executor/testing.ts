// Synthetic scheduling at external boundaries. Real compilation, authorization
// codecs, raw ownership, canonical evidence builder and receipt client are used.
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { GovernanceOutcome, ManagedCallAuthorizationDecisionSchema, ManagedCallAuthorizationRequestSchema,
  ManagedCallCompletionSchema, ManagedCallCompletionReceiptSchema } from "@apex/contracts";
import { EventEnvelopeSchema } from "@apex/contracts/event";
import { fixture } from "../call-preparation/fixture.js";
import { deferred } from "../authority/business-testing.js";
import { AuthenticatedBusinessTransport } from "../authority/business-transport.js";
import { OwnedCallCoordinator } from "../call-owner.js";
import { ManagedEvidenceClient } from "../evidence/client.js";
import { CompiledManagedExecutor } from "../compiled-executor.js";
import type { OwnedMcpSession } from "../upstream-wire/session.js";
import type { Clock } from "../../telemetry/clock.js";
export { deferred };
export const turns = async () => { for (let i = 0; i < 40; i++) await Promise.resolve(); };
export const canary = "PRIVATE-canary-never-export";
export const portfolio = () => ({ portfolio_id: "p-1", as_of: "2026-09-06", base_currency: "USD", total_value: 123,
  client: { display_name: "Public name", account_number: canary, tax_id: canary },
  positions: [{ symbol: "AAA", quantity: 2, market_value: 123, cost_basis: 88 }], private_extra: canary });
export const envelope = () => ({ content: [{ type: "text", text: canary }], structuredContent: portfolio(), _meta: { canary } });
export function harness(native?: { clock: Clock; session: Pick<OwnedMcpSession, "call"> }) {
  const base = fixture(), original = native?.clock.now() ?? base.original;
  const f = { ...base, original, deadline: original.monotonicNs + 120000000000n };
  let at = { ...f.original }, clockHook: (() => void) | undefined;
  const mono = () => native?.clock.now().monotonicNs ?? at.monotonicNs;
  const clock = { now() { clockHook?.(); return native?.clock.now() ?? { ...at }; } };
  const preparation = { ...f.options, clock };
  const profile = { binding: preparation.binding, policyId: preparation.config.spec!.governanceBinding!.policyId,
    evidenceAgentId: preparation.evidenceAgentId, dataClassification: preparation.dataClassification };
  const auth = deferred<Uint8Array>(), authClosed = deferred<void>(), upstream = deferred<unknown>(), rawClosed = deferred<void>();
  const evidenceReply = deferred<Uint8Array>(), evidenceClosed = deferred<void>(), completionClosed = deferred<void>();
  for (const pending of [auth.promise, upstream.promise, evidenceReply.promise]) void pending.catch(() => {});
  const effects: string[] = [], events: ReturnType<typeof fromBinary<typeof EventEnvelopeSchema>>[] = [];
  const evidenceTiming: { start: bigint; deadline: bigint }[] = [];
  let active = 0, current = true;
  const business = new AuthenticatedBusinessTransport({ ...profile, monotonicNowNs: mono, channel: {
    start(path, bytes) {
      if (path.endsWith("AuthorizeManagedCall")) {
        fromBinary(ManagedCallAuthorizationRequestSchema, bytes); effects.push("authorize");
        return { result: auth.promise, closed: authClosed.promise, cancel() { effects.push("cancel-auth"); } };
      }
      effects.push("complete"); const request = fromBinary(ManagedCallCompletionSchema, bytes);
      return { result: Promise.resolve(toBinary(ManagedCallCompletionReceiptSchema, create(ManagedCallCompletionReceiptSchema,
        { binding: request.binding, admissionId: request.admissionId, callId: request.callId, released: true }))),
        closed: completionClosed.promise, cancel() {} };
    } } });
  const raw = new OwnedCallCoordinator({ ...profile, business, monotonicNowNs: mono,
    grants: { snapshot: () => ({ mode: "serve", admitting: current, epoch: 23n, activeCalls: active }),
      tryBeginCall() { active++; let released = false; return { isCurrent: () => current, release() { if (!released) { released = true; active--; } } }; } },
    routes: new Map([["portfolio.read", { toolName: "portfolio.read", session: native?.session ?? { call(_id, _name, _input, context) {
      context.beforeWrite(); effects.push("upstream");
      return { result: upstream.promise, closed: rawClosed.promise, cancel() { effects.push("cancel-upstream"); }, metadata: () => ({}) };
    } } }]]) });
  const evidence = new ManagedEvidenceClient({ start(bytes, start, deadline) {
    effects.push("evidence"); events.push(fromBinary(EventEnvelopeSchema, bytes)); evidenceTiming.push({ start, deadline });
    return { result: evidenceReply.promise, closed: evidenceClosed.promise, cancel() { effects.push("cancel-evidence"); } };
  } }, mono);
  const executor = new CompiledManagedExecutor({ preparation, calls: raw, evidence });
  return { ...f, preparation, profile, executor, raw, evidence, effects, events, evidenceTiming,
    auth, authClosed, upstream, rawClosed, evidenceReply, evidenceClosed, completionClosed,
    start: () => executor.start(f.identity, "portfolio.read", { portfolioId: "p-1" }, f.original, f.deadline),
    authorize(outcome = GovernanceOutcome.ALLOWED, restrictions = ["client.account_number", "client.tax_id", "positions.cost_basis"]) {
      const allowed = outcome === GovernanceOutcome.ALLOWED;
      auth.resolve(toBinary(ManagedCallAuthorizationDecisionSchema, create(ManagedCallAuthorizationDecisionSchema, {
        decision: { outcome, policyId: profile.policyId, reasonCode: "policy.decision", fieldRestrictions: restrictions },
        policyRevision: 9007199254740993n, ...(allowed ? { admissionId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e06",
          epoch: 23n, validForUs: 10000000n, expiresAtUnixUs: 1n } : {}) }))); authClosed.resolve();
    },
    advance(ns: bigint) { at = { ...f.original, monotonicNs: f.original.monotonicNs + ns, unixUs: f.original.unixUs + ns / 1000n }; },
    clock(value: typeof at) { at = value; }, hook(value?: () => void) { clockHook = value; }, revoke() { current = false; },
    async cleanup() { auth.reject(new Error(canary)); upstream.reject(new Error(canary)); evidenceReply.reject(new Error(canary));
      authClosed.resolve(); rawClosed.resolve(); evidenceClosed.resolve(); completionClosed.resolve();
      await raw.close(); await evidence.close(); },
    get active() { return active; } };
}
