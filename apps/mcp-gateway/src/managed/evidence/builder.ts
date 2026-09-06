import type { CallEvidence, EvidenceProfile, PreparedEvidence } from "./types.js";
import { create, toBinary, type JsonObject } from "@bufbuild/protobuf";
import { EventEnvelopeSchema, EventType, ActorType } from "@apex/contracts/event";
import { sha256CanonicalJson, type JsonValue } from "../../live/canonical.js";
import { assertDataTree } from "../runtime-config/boundary.js";
import { authorizationRequest, businessBinding, businessClassification, businessIdentifier } from "../authority/business-codec.js";
import { snapshot, consistent } from "../call-preparation/timing.js";
import { record } from "../call-preparation/boundary.js";
import { isDeepStrictEqual } from "node:util";
const refused = () => new Error("managed call evidence refused safely");
const bytesByHandle = new WeakMap<PreparedEvidence, Uint8Array>();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const STAGES = new Set(["ingress", "authentication", "input.validation", "authorization", "policy", "egress",
  "dns", "tls", "upstream", "output.validation", "output.filtering", "evidence.admission", "response.finish", "response.abort", "call.cleanup"]);
const AFTER_ADMISSION = new Set(["evidence.admission", "response.finish", "response.abort", "call.cleanup"]);
export class ManagedEvidenceBuilder {
  private readonly profile: EvidenceProfile;
  constructor(profile: EvidenceProfile) {
    try {
      assertDataTree(profile, true);
      this.profile = Object.freeze({ binding: businessBinding(profile.binding), policyId: businessIdentifier(profile.policyId),
        evidenceAgentId: businessIdentifier(profile.evidenceAgentId), dataClassification: businessClassification(profile.dataClassification) });
    } catch { throw refused(); }
  }
  prepare(input: CallEvidence): PreparedEvidence {
    try {
      assertDataTree(input, true);
      record(input, ["phase", "eventId", "linkedEventId", "request", "decision", "status", "started", "observed", "stages",
        "inputBytes", "sourceBytes", "filteredBytes", "outputBytes", "removedFields"]);
      const request = authorizationRequest(input.request, this.profile).submittedRequest;
      const { eventId, linkedEventId, phase, status, decision } = input;
      if (!uuid(eventId) || !uuid(linkedEventId) || eventId === linkedEventId ||
        !["admission", "completion"].includes(phase) || !["succeeded", "denied", "failed"].includes(status) ||
        !/^[0-9a-f]{32}$/.test(request.trace!.traceId) || /^0+$/.test(request.trace!.traceId) || !spanId(request.trace!.spanId) ||
        !["allowed", "denied", "requires_approval"].includes(decision.outcome) || decision.policyId !== this.profile.policyId ||
        typeof decision.policyRevision !== "bigint" || decision.policyRevision <= 0n || decision.policyRevision > (1n << 64n) - 1n ||
        (status === "succeeded" && decision.outcome !== "allowed") || (status === "denied" && decision.outcome === "allowed")) throw refused();
      if (decision.outcome === "allowed" && (!isDeepStrictEqual(decision.submittedRequest, request) || !uuid(decision.admissionId))) throw refused();
      const restrictions = fields(decision.fieldRestrictions), removed = fields(input.removedFields);
      const reason = businessIdentifier(decision.reasonCode);
      for (const count of [input.inputBytes, input.sourceBytes, input.filteredBytes, input.outputBytes])
        if (!Number.isSafeInteger(count) || count < 0 || count > 1_048_576) throw refused();
      if (input.inputBytes > 262_144 || input.filteredBytes > input.sourceBytes) throw refused();
      const started = snapshot(input.started), observed = snapshot(input.observed); consistent(started, observed);
      const duration = observed.monotonicNs - started.monotonicNs;
      const seen = new Set([request.trace!.spanId]), names = new Set<string>();
      if (!Array.isArray(input.stages) || input.stages.length > 32) throw refused();
      const stages = input.stages.map(stage => {
        record(stage, ["name", "spanId", "parentSpanId", "started", "durationNs", "status"]);
        if (!STAGES.has(stage.name) || names.has(stage.name) || (phase === "admission" && AFTER_ADMISSION.has(stage.name)) ||
          !spanId(stage.spanId) || seen.has(stage.spanId) || !seen.has(stage.parentSpanId) ||
          !["ok", "error", "missing"].includes(stage.status)) throw refused();
        names.add(stage.name); seen.add(stage.spanId);
        const at = snapshot(stage.started); consistent(started, at); consistent(at, observed);
        if (stage.status === "missing" ? stage.durationNs !== undefined : typeof stage.durationNs !== "bigint" || stage.durationNs < 0n ||
          at.monotonicNs + stage.durationNs > observed.monotonicNs) throw refused();
        return { name: stage.name, span_id: stage.spanId, parent_span_id: stage.parentSpanId, status: stage.status,
          started_at_unix_us: at.unixUs.toString(), offset_ns: (at.monotonicNs - started.monotonicNs).toString(),
          ...(stage.durationNs === undefined ? {} : { duration_ns: stage.durationNs.toString(), duration_us: (stage.durationNs / 1000n).toString() }) };
      });
      const binding = this.profile.binding;
      const data: JsonObject = {
        kind: "mcp_proxy_call", schema_version: 1, phase, linked_event_id: linkedEventId,
        installation_id: binding.installationId, workspace_id: binding.workspaceId, namespace_id: binding.namespaceId,
        proxy_id: binding.proxyId, revision_id: binding.revisionId, generation: binding.generation.toString(),
        fencing_token: binding.fencingToken.toString(), process_instance_id: binding.processInstanceId,
        config_hash: binding.configHash, launch_context_hash: binding.launchContextHash, call_id: request.callId,
        ...(decision.outcome === "allowed" ? { admission_id: decision.admissionId } : {}),
        caller: { principal: request.caller!.principal, agent_id: this.profile.evidenceAgentId },
        tool: request.toolAlias, action: request.action, resource: request.resource, arguments_hash: request.argumentsHash,
        classification: request.classification, status,
        policy: { outcome: decision.outcome, policy_id: decision.policyId, revision: decision.policyRevision.toString(),
          reason_code: reason, field_restrictions: restrictions },
        sizes: { input_bytes: input.inputBytes, source_bytes: input.sourceBytes, filtered_bytes: input.filteredBytes, output_bytes: input.outputBytes },
        removed_fields: removed, span_id: request.trace!.spanId,
        clock_domain: binding.processInstanceId, clock_source: started.source, clock_resolution_ns: started.resolutionNs.toString(),
        ...(started.uncertaintyUs === undefined ? {} : { clock_uncertainty_us: started.uncertaintyUs.toString() }),
        started_at_unix_us: started.unixUs.toString(), observed_at_unix_us: observed.unixUs.toString(),
        duration_ns: duration.toString(), duration_us: (duration / 1000n).toString(), stages,
      };
      const timestamp = timestampUs(observed.unixUs);
      const scope = { workspace_id: binding.workspaceId, namespace_id: binding.namespaceId, agent_group_ids: [] };
      const version = { agent_code: "apex-mcp-gateway", prompt: "managed-call-v1", model: "n-a" };
      const eventHash = sha256CanonicalJson({ event_id: eventId, timestamp, type: "tool", agent_id: this.profile.evidenceAgentId,
        run_id: request.callId, parent_run_id: null, trace_id: request.trace!.traceId, scope,
        actor: { type: "agent", id: this.profile.evidenceAgentId }, version, data: data as JsonValue,
        integrity: { prev_hash: null }, schema_version: 1 });
      const payload = toBinary(EventEnvelopeSchema, create(EventEnvelopeSchema, { eventId, timestamp, type: EventType.TOOL,
        agentId: this.profile.evidenceAgentId, runId: request.callId, traceId: request.trace!.traceId,
        scope: { workspaceId: binding.workspaceId, namespaceId: binding.namespaceId },
        actor: { type: ActorType.AGENT, id: this.profile.evidenceAgentId },
        version: { agentCode: version.agent_code, prompt: version.prompt, model: version.model }, data,
        integrity: { eventHash }, schemaVersion: 1 }));
      if (payload.length > 65_536) throw refused();
      const prepared = Object.freeze({ eventId, eventHash }); bytesByHandle.set(prepared, payload); return prepared;
    } catch { throw refused(); }
  }
}
export function evidenceBytes(value: PreparedEvidence): Uint8Array {
  const bytes = bytesByHandle.get(value); if (!bytes) throw refused(); return Uint8Array.from(bytes);
}
function fields(value: readonly string[]): string[] {
  if (!Array.isArray(value) || value.length > 128 || new Set(value).size !== value.length) throw refused();
  return value.map(field => businessIdentifier(field));
}
function spanId(value: string): boolean { return typeof value === "string" && /^[0-9a-f]{16}$/.test(value) && !/^0+$/.test(value); }
function uuid(value: unknown): value is string { return typeof value === "string" && value.length === 36 && UUID.test(value); }
export function timestampUs(value: bigint): string {
  if (typeof value !== "bigint" || value < 0n || value >= 253_402_300_800_000_000n) throw refused();
  const date = new Date(Number(value / 1_000_000n) * 1000).toISOString().slice(0, 19);
  return `${date}.${(value % 1_000_000n).toString().padStart(6, "0")}Z`;
}
