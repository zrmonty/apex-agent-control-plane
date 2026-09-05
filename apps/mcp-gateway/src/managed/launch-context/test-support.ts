import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { RuntimeLaunchContextSchema } from "@apex/contracts";
import { fromJson, toJson, type JsonObject, type JsonValue } from "@bufbuild/protobuf";
import { GatewayError } from "../../contracts.js";
import { parseRuntimeConfiguration } from "../runtime-config.js";
import { artifactText, object } from "../runtime-config/test-support.js";

export const config = parseRuntimeConfiguration(artifactText);
export const fence = "9007199254740993";

/** Synthetic metadata only. The configuration is the actual supplied Rust
 * export; no trusted Task 7 launch producer, profile or material is fabricated. */
export function source(): JsonObject {
  return resign({
    schemaVersion: 1,
    target: {
      workspaceId: config.workspaceId, namespaceId: config.namespaceId,
      proxyId: config.proxyId, revisionId: config.revisionId,
      generation: config.generation.toString(), fencingToken: fence,
    },
    configHash: config.configHash, runtimeManifestHash: config.runtimeManifestHash, imageRef: config.imageRef,
    processInstanceId: "0191b7f1-7f2c-7c13-9a61-2f29f2be1003",
    health: { port: 8081, credentialRef: "secret://deployment/health" },
    materials: [
      { role: "RUNTIME_MATERIAL_ROLE_HEALTH_TOKEN", reference: "secret://deployment/health", version: "v1" },
      { role: "RUNTIME_MATERIAL_ROLE_GOVERNANCE_CA", reference: "secret://deployment/authority-ca", version: "v1" },
    ],
    authorityProfileRef: "deployment-live", authorityProfileVersion: "v1",
  });
}

/** Independent reference: generated ProtoJSON, sorted plain objects, then the
 * platform JSON serializer. Generated keys are ASCII and not integer-like. */
function sorted(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(sorted);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])]));
  }
  return value;
}
export function referenceHash(input: JsonObject): string {
  const json = object(toJson(RuntimeLaunchContextSchema, fromJson(RuntimeLaunchContextSchema, input)));
  delete json.launchContextHash;
  return createHash("sha256").update(JSON.stringify(sorted(json))).digest("hex");
}
export function resign(input: JsonObject): JsonObject {
  input.launchContextHash = referenceHash(input);
  return input;
}
export function generated(input: JsonObject = source()) {
  return fromJson(RuntimeLaunchContextSchema, input);
}
export function rejectsSafely(action: () => unknown): void {
  assert.throws(action, (error: unknown) => {
    assert.ok(error instanceof GatewayError);
    assert.equal(error.code, "INVALID_INPUT");
    assert.equal(error.message, "INVALID_INPUT: managed launch context rejected safely");
    assert.equal((error as Error & { cause?: unknown }).cause, undefined);
    assert.ok(!String(error.stack).includes("LAUNCH_CANARY"));
    assert.ok(!JSON.stringify(error).includes("LAUNCH_CANARY"));
    return true;
  });
}
