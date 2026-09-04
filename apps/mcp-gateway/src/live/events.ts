import type { ApexEvents, EventReceipt, ToolExecutionEvent } from "../contracts.js";
import { GatewayError } from "../contracts.js";
import type { LiveGrpcConfig } from "./config.js";
import { sha256CanonicalJson, type JsonValue } from "./canonical.js";
import { createGrpcClient, protoPath, unaryCall } from "./grpc.js";
import { loadClientMaterial } from "./secrets.js";
import { createUuidV7, timestampFromUuidV7 } from "./uuid.js";

type JsonObject = { readonly [key: string]: JsonValue };

export type StructWire = { readonly fields: Record<string, ValueWire> };
export type ValueWire = {
  readonly nullValue?: number;
  readonly numberValue?: number;
  readonly stringValue?: string;
  readonly boolValue?: boolean;
  readonly structValue?: StructWire;
  readonly listValue?: { readonly values: readonly ValueWire[] };
};

export type ToolEventEnvelope = {
  readonly event_id: string;
  readonly timestamp: string;
  readonly type: "TOOL";
  readonly agent_id: string;
  readonly run_id: string;
  readonly parent_run_id: null;
  readonly trace_id: string;
  readonly scope: {
    readonly workspace_id: string;
    readonly namespace_id: string;
    readonly agent_group_ids: readonly string[];
  };
  readonly actor: { readonly type: "AGENT"; readonly id: string };
  readonly version: {
    readonly agent_code: string;
    readonly prompt: string;
    readonly model: string;
  };
  readonly data: JsonObject;
  readonly integrity: { readonly prev_hash: null; readonly event_hash: string };
  readonly schema_version: 1;
};

export { canonicalizeJson } from "./canonical.js";

export function jsonToStruct(value: JsonValue): StructWire {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("Struct root must be an object");
  }
  return { fields: Object.fromEntries(Object.entries(value).map(([key, item]) => [key, jsonToValue(item)])) };
}

export function structToJson(value: StructWire): JsonObject {
  return Object.fromEntries(Object.entries(value.fields).map(([key, item]) => [key, valueToJson(item)]));
}

export function createToolEventEnvelope(
  event: ToolExecutionEvent,
  eventId = createUuidV7(),
  timestamp = timestampFromUuidV7(eventId),
): ToolEventEnvelope {
  const unsigned = {
    event_id: eventId,
    timestamp,
    type: "tool" as const,
    agent_id: event.caller.agentId,
    run_id: `mcp-${event.trace.traceId}`,
    parent_run_id: null,
    trace_id: event.trace.traceId,
    scope: {
      workspace_id: event.scope.workspaceId,
      namespace_id: event.scope.namespaceId,
      agent_group_ids: [],
    },
    actor: { type: "agent" as const, id: event.caller.agentId },
    version: { agent_code: "apex-mcp-gateway", prompt: "mcp-gateway-v1", model: "n-a" },
    data: eventData(event),
    integrity: { prev_hash: null },
    schema_version: 1 as const,
  };
  return {
    ...unsigned,
    type: "TOOL",
    actor: { type: "AGENT", id: event.caller.agentId },
    integrity: { prev_hash: null, event_hash: sha256CanonicalJson(unsigned) },
  };
}

export function createLiveEventsClient(
  config: LiveGrpcConfig,
  trustedSecretBase: string,
  timeoutMs = 5_000,
): ApexEvents {
  let clientPromise: Promise<{ readonly client: ReturnType<typeof createGrpcClient>; readonly token: string }> | undefined;
  const getClient = async () => {
    clientPromise ??= loadClientMaterial(config, trustedSecretBase).then((material) => ({
      client: createGrpcClient(protoPath("event.proto"), "EventIngest", config.endpoint, material),
      token: material.token,
    }));
    return clientPromise;
  };
  return {
    async emit(event): Promise<EventReceipt> {
      const { client, token } = await getClient();
      const envelope = createToolEventEnvelope(event);
      await unaryCall(
        client,
        "ingest",
        toEventWireEnvelope(envelope),
        token,
        timeoutMs,
        "EVENT_ADMISSION_FAILED",
      );
      return { eventId: envelope.event_id };
    },
  };
}

function eventData(event: ToolExecutionEvent): JsonObject {
  return {
    caller: { principal: event.caller.principal, agent_id: event.caller.agentId },
    scope: { workspace_id: event.scope.workspaceId, namespace_id: event.scope.namespaceId },
    tool: event.tool,
    action: event.action,
    resource: event.resource,
    backend: event.backend,
    status: event.status,
    latency_ms: event.latencyMs,
    retry_count: event.retryCount,
    sizes: {
      input_bytes: event.sizes.inputBytes,
      source_bytes: event.sizes.sourceBytes,
      filtered_bytes: event.sizes.filteredBytes,
      output_bytes: event.sizes.outputBytes,
    },
    filtering: { removed_fields: [...event.filtering.removedFields] },
    policy: {
      outcome: event.policy.outcome,
      policy_id: event.policy.policyId,
      reason_code: event.policy.reasonCode,
      field_restrictions: [...event.policy.fieldRestrictions],
    },
    trace: { trace_id: event.trace.traceId, span_id: event.trace.spanId },
  };
}

function toEventWireEnvelope(envelope: ToolEventEnvelope): Record<string, unknown> {
  return {
    event_id: envelope.event_id,
    timestamp: envelope.timestamp,
    type: 3,
    agent_id: envelope.agent_id,
    run_id: envelope.run_id,
    trace_id: envelope.trace_id,
    scope: envelope.scope,
    actor: { type: 2, id: envelope.actor.id },
    version: envelope.version,
    data: jsonToStruct(envelope.data),
    integrity: { event_hash: envelope.integrity.event_hash },
    schema_version: envelope.schema_version,
  };
}

function jsonToValue(value: JsonValue): ValueWire {
  if (value === null) return { nullValue: 0 };
  if (typeof value === "boolean") return { boolValue: value };
  if (typeof value === "string") return { stringValue: value };
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) {
      throw new TypeError("Struct numbers must be finite safe integers");
    }
    return { numberValue: value };
  }
  if (Array.isArray(value)) {
    return { listValue: { values: value.map(jsonToValue) } };
  }
  return { structValue: jsonToStruct(value) };
}

function valueToJson(value: ValueWire): JsonValue {
  if (value.nullValue !== undefined) return null;
  if (value.boolValue !== undefined) return value.boolValue;
  if (value.stringValue !== undefined) return value.stringValue;
  if (value.numberValue !== undefined) {
    if (!Number.isFinite(value.numberValue)) throw new TypeError("invalid Struct number");
    return value.numberValue;
  }
  if (value.structValue !== undefined) return structToJson(value.structValue);
  if (value.listValue !== undefined) return value.listValue.values.map(valueToJson);
  throw new GatewayError("EVENT_ADMISSION_FAILED", "request rejected safely");
}
