import { randomBytes } from "node:crypto";
import { create } from "@bufbuild/protobuf";
import { ManagedCallAuthorizationRequestSchema } from "@apex/contracts";
import type { ClockSnapshot } from "../telemetry/clock.js";
import type { InboundIdentity } from "./auth.js";
import type { CallPreparationOptions, PreparedManagedCall } from "./call-preparation-types.js";
import { CallerPrincipalSchema, PortfolioReadInputSchema } from "../schemas.js";
import { portfolioResourceReference } from "../context.js";
import { createUuidV7 } from "../live/uuid.js";
import { canonicalizeJson, sha256CanonicalJson } from "../live/canonical.js";
import { authorizationRequest } from "./authority/business-codec.js";
import { wireBinding } from "./authority/grant-transport.js";
import { assertDataTree } from "./runtime-config/boundary.js";
import { compile } from "./call-preparation/compile.js";
import { record, refused } from "./call-preparation/boundary.js";
import { consistent, deadline, snapshot } from "./call-preparation/timing.js";
export type { CallPreparationOptions, PreparedManagedCall, PreparedCallTrace } from "./call-preparation-types.js";

/** Pure trusted-composition seam. Neither identity nor config hashes authenticate themselves. */
export class CompiledCallPreparer {
  readonly #compiled: ReturnType<typeof compile>;
  #last?: Readonly<ClockSnapshot>;
  constructor(options: CallPreparationOptions) {
    try { this.#compiled = compile(options); } catch { throw refused(); }
  }
  prepare(identity: InboundIdentity, alias: string, input: unknown,
    original: ClockSnapshot, deadlineNs: bigint): PreparedManagedCall {
    try {
      // Validate/copy every inbound data object before invoking the trusted clock.
      record(identity, ["subject", "proxyId", "scopes"]); assertDataTree(identity, false);
      if (identity.proxyId !== this.#compiled.binding.proxyId || typeof identity.subject !== "string" ||
        /[^\x21-\x7e]/.test(identity.subject) || !CallerPrincipalSchema.safeParse(identity.subject).success ||
        !Array.isArray(identity.scopes) || identity.scopes.length > 64 ||
        identity.scopes.some(scope => typeof scope !== "string" || scope.length > 256)) throw refused();
      const subject = identity.subject;
      if (typeof alias !== "string" || !this.#compiled.indexes.byAlias.has(alias)) throw refused();
      // Exact published schema is narrower than the reusable Zod input (no asOf).
      record(input, ["portfolioId"]); assertDataTree(input, false);
      const parsed = PortfolioReadInputSchema.parse(input);
      const copied: Readonly<Record<string, string>> = Object.freeze(JSON.parse(canonicalizeJson(parsed)));
      const start = snapshot(original); deadline(start, deadlineNs);
      this.check(start, deadlineNs);
      const callId = createUuidV7(), traceId = randomId(16), spanId = randomId(8);
      const request = authorizationRequest(create(ManagedCallAuthorizationRequestSchema, {
        binding: wireBinding(this.#compiled.binding), caller: { principal: subject, agentId: this.#compiled.evidenceAgentId },
        scope: { workspaceId: this.#compiled.binding.workspaceId, namespaceId: this.#compiled.binding.namespaceId },
        proxyId: this.#compiled.binding.proxyId, revisionId: this.#compiled.binding.revisionId,
        generation: this.#compiled.binding.generation, callId, toolAlias: alias, action: "read",
        resource: portfolioResourceReference(parsed.portfolioId), classification: this.#compiled.dataClassification,
        argumentsHash: sha256CanonicalJson(copied), trace: { traceId, spanId }, approvalId: "",
      }), this.#compiled).submittedRequest;
      this.check(start, deadlineNs);
      return Object.freeze({ request, input: copied, startedAtMonotonicNs: start.monotonicNs,
        deadlineMonotonicNs: deadlineNs, originalSnapshot: start,
        trace: Object.freeze({ callId, traceId, spanId, startedAtUnixUs: start.unixUs, clockSource: start.source,
          clockResolutionNs: start.resolutionNs, clockUncertaintyUs: start.uncertaintyUs }) });
    } catch { throw refused(); }
  }
  private check(start: Readonly<ClockSnapshot>, deadlineNs: bigint): void {
    const now = snapshot(this.#compiled.now());
    if (this.#last) consistent(this.#last, now);
    consistent(start, now); this.#last = now;
    if (now.monotonicNs >= deadlineNs) throw refused();
  }
}
function randomId(bytes: number): string {
  const value = randomBytes(bytes);
  if (!value.some(byte => byte !== 0)) throw refused();
  return value.toString("hex");
}
